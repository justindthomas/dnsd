"""Iterative recursion — root walk for names without a forwarder match.

Enabled by `dns.recursion.enabled: true` in router.yaml. The recursor
starts at the IANA root hints, follows NS referrals toward the target
zone, handles glue, and follows CNAME chains. Upstream UDP queries
run on the tokio blocking pool (forwarder.rs query_one_udp uses
spawn_blocking) so VCL's blocking `vppcom_session_listen` can't wedge
the single-threaded main runtime.

These tests use names OUTSIDE the configured `iana.org` forwarder so
the forwarder path is bypassed and iterative resolution is the only
answer source.
"""


def test_recursive_a_resolves(recursive_query, dnsd_query):
    """A-record resolution for a stable non-forwarded name."""
    dnsd_query("cache", "--op", "flush")
    before = dnsd_query("stats")
    walked_before = before.get("recursion_walked", 0)

    r = recursive_query("example.com")
    assert not r.get("timeout"), "recursive A timed out"
    assert r.get("rcode") == "NOERROR", f"expected NOERROR, got: {r}"
    assert r.get("an", 0) >= 1, f"no answers: {r}"

    after = dnsd_query("stats")
    walked_after = after.get("recursion_walked", 0)
    assert walked_after > walked_before, (
        f"recursion_walked didn't advance: {walked_before} -> {walked_after}"
    )


def test_recursive_aaaa_resolves(recursive_query):
    """AAAA over iterative recursion: example.com serves AAAA records."""
    r = recursive_query("example.com", rtype=28)
    assert not r.get("timeout"), "recursive AAAA timed out"
    assert r.get("rcode") == "NOERROR", f"expected NOERROR, got: {r}"
    assert r.get("an", 0) >= 1, f"no AAAA answers: {r}"


def test_recursive_cname_chain(recursive_query):
    """www.google.com is a CNAME to a load-balanced zone. The recursor
    must follow the chain and return both the CNAME and the terminal
    A records so the client sees the full answer."""
    r = recursive_query("www.google.com")
    assert not r.get("timeout"), "CNAME-chain resolution timed out"
    assert r.get("rcode") == "NOERROR", f"unexpected: {r}"
    # At minimum: the CNAME plus one A. Google usually returns several As.
    assert r.get("an", 0) >= 2, (
        f"too few RRs — CNAME walk may have stopped short: {r}"
    )


def test_recursive_nxdomain(recursive_query):
    """A non-existent TLD resolves to NXDOMAIN via the root SOA."""
    r = recursive_query("definitely-not-a-real-tld-7c9b3a.invalid-test-xyz")
    assert not r.get("timeout"), "recursive NXDOMAIN timed out"
    assert r.get("rcode") == "NXDOMAIN", f"expected NXDOMAIN, got: {r}"


def test_recursive_answer_is_cached(recursive_query, dnsd_query, wait_for_cache_entries):
    """A second recursive query for the same name is served from cache
    — recursion should only be walked once per (name, rtype) while the
    TTL holds."""
    dnsd_query("cache", "--op", "flush")
    # nist.gov has reliable v4 glue all the way down the delegation
    # chain (unlike e.g. iana.com / example.org which hit glueless
    # NSes whose sub-walks our recursor doesn't currently complete).
    name = "nist.gov"

    before = dnsd_query("stats")
    walked_before = before.get("recursion_walked", 0)
    hits_before = before.get("cache_hits", 0)

    r1 = recursive_query(name)
    assert r1.get("rcode") == "NOERROR"
    wait_for_cache_entries(min_entries=1)  # moka insert is async

    mid = dnsd_query("stats")
    walked_mid = mid.get("recursion_walked", 0)
    assert walked_mid > walked_before, "first query didn't walk"

    r2 = recursive_query(name)
    assert r2.get("rcode") == "NOERROR"

    after = dnsd_query("stats")
    walked_after = after.get("recursion_walked", 0)
    hits_after = after.get("cache_hits", 0)

    assert walked_after == walked_mid, (
        f"second query re-walked: {walked_mid} -> {walked_after} (should have hit cache)"
    )
    assert hits_after > hits_before, (
        f"cache_hits didn't advance: {hits_before} -> {hits_after}"
    )


def test_recursive_tcp_works_too(query_tcp):
    """Recursive resolution returns over TCP with proper length framing."""
    r = query_tcp("example.com", timeout=10.0)
    assert not r.get("timeout"), "recursive TCP timed out"
    assert r.get("rcode") == "NOERROR", f"unexpected: {r}"
    assert r.get("an", 0) >= 1


def test_root_hints_primed_and_persisted(ssh):
    """dnsd runs a `./NS` priming query at startup, caches the
    authoritative response + glue, and persists the IP set to
    `/var/lib/dnsd/root-hints`. Cold-boot on the next start then
    reads that file instead of the compiled-in hardcoded list.

    Verifies: (1) the persisted file exists and is non-empty;
    (2) it lists 26 IPs (13 roots × v4/v6); (3) the startup log
    recorded a successful prime."""
    rc, out, _ = ssh("cat /var/lib/dnsd/root-hints 2>/dev/null")
    assert rc == 0, "persisted root-hints file missing"
    ips = [
        line.strip()
        for line in out.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert len(ips) == 26, f"expected 26 root IPs (v4+v6), got {len(ips)}: {ips}"

    # At least one v4 and one v6 IP should be present.
    assert any("." in ip for ip in ips), "no v4 roots"
    assert any(":" in ip for ip in ips), "no v6 roots"

    # Log trail: priming emitted a `root hints primed` line.
    rc, out, _ = ssh(
        "journalctl -u dnsd.service --no-pager | grep 'root hints primed' | tail -1"
    )
    assert "roots=26" in out, f"no successful prime in journal: {out!r}"


def test_root_server_a_records_cached_by_prime(ssh, dnsd_query):
    """Priming caches each root server's A/AAAA record as a side
    effect of parsing the `./NS` response's glue. Earlier tests in
    the suite flush the cache mid-run, so restart dnsd to force a
    fresh prime and THEN verify the cache is populated from glue
    rather than from test queries."""
    import time
    rc, _, _ = ssh("systemctl restart dnsd.service")
    assert rc == 0, "dnsd restart failed"
    # Priming is asynchronous; give it a beat to complete.
    time.sleep(2.0)

    dump = dnsd_query("cache", "--op", "dump")
    entries = dump.get("entries", [])
    root_entries = [
        e for e in entries
        if e.get("name", "").rstrip(".").endswith("root-servers.net")
    ]
    # IANA's root response returns 13 NS records with full A+AAAA
    # glue — expect a healthy chunk of them in the cache after prime.
    assert len(root_entries) >= 10, (
        f"expected cached root-servers.net records from prime, got "
        f"{len(root_entries)} entries: {[e.get('name') for e in root_entries]}"
    )

    # Also verify the authoritative `./NS` response itself was
    # cached (not just the glue A/AAAAs).
    ns_entries = [
        e for e in entries
        if e.get("name") == "." and e.get("rtype") == "NS"
    ]
    assert ns_entries, "priming didn't cache the ./NS response itself"


def test_recursive_glueless_sibling_delegation(recursive_query, dnsd_query):
    """Regression guard for the `gtld-servers.net` class of glueless
    sub-walks.

    Names like `example.org`, `iana.com`, `ietf.org`, `www.debian.org`
    are delegated to out-of-bailiwick nameservers whose authoritative
    zone (typically `*.gtld-servers.net` or similar) serves delegation
    responses WITHOUT glue. Before glue caching landed, sub-resolving
    those nameservers looped until the query budget ran out and every
    name came back SERVFAIL. With glue caching, the addresses the root
    gave us for `.net` TLD servers are reused on the sub-walk and
    resolution succeeds.

    The specific names below are the ones that reliably SERVFAIL'd
    on a pre-fix build; they should all resolve now."""
    dnsd_query("cache", "--op", "flush")
    for name in ("example.org", "iana.com", "ietf.org", "www.debian.org"):
        r = recursive_query(name)
        assert not r.get("timeout"), f"{name}: recursive query timed out"
        assert r.get("rcode") == "NOERROR", (
            f"{name}: expected NOERROR, got {r!r}"
        )
        assert r.get("an", 0) >= 1, f"{name}: no answers: {r}"


def test_forwarded_name_does_not_bump_recursion_counter(query_udp, dnsd_query):
    """Names inside the `iana.org` forwarder take the forwarder path,
    not the recursor — recursion_walked shouldn't move on those."""
    dnsd_query("cache", "--op", "flush")
    before = dnsd_query("stats")
    walked_before = before.get("recursion_walked", 0)

    query_udp("www.iana.org")  # matches forwarder for iana.org

    after = dnsd_query("stats")
    walked_after = after.get("recursion_walked", 0)
    assert walked_after == walked_before, (
        f"forwarded query walked the recursor: {walked_before} -> {walked_after}"
    )
