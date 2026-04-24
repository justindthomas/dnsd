"""DNSSEC validation — chain walk from root KSK down to the answer.

With `dns.recursion.dnssec_validate: true` and a `trust_anchor` path
configured, dnsd:
  * sends DO=1 on upstream queries to get RRSIGs back
  * bootstraps the root zone's ZSK by fetching `./DNSKEY` and
    verifying it with the loaded trust anchor (root KSK)
  * at each delegation, verifies the parent's DS RRSIG with the
    parent's validated keys, then fetches the child's DNSKEY set
    and confirms at least one DNSKEY matches one of the DS records
  * validates the answer's RRSIG with the terminal zone's keys
  * sets AD=1 on verified responses, SERVFAILs + EDE 6 on Bogus,
    leaves AD=0 on Insecure (unsigned zones, missing denial-of-DS,
    etc.)

Positive tests hit real signed public zones. The bogus-signature
test relies on `dnssec-failed.org` — a long-running test domain
specifically published with deliberately-broken signatures.
"""

import socket
import struct


def _dns_query_with_do(target: str, name: str, rtype: int = 1, timeout: float = 15.0):
    """Like conftest's query_udp but sets EDNS DO=1 so dnsd's
    validator sees a client that cares about DNSSEC."""
    parts = name.rstrip(".").split(".")
    qname = b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"
    # Header: 1 query, 0 answers, 0 authority, 1 additional (OPT)
    header = struct.pack(">HHHHHH", 0x7777, 0x0100, 1, 0, 0, 1)
    question = qname + struct.pack(">HH", rtype, 1)
    # OPT pseudo-record: name=., type=41, class=4096 (payload),
    # ttl=0x00008000 (DO bit set), rdlen=0
    opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0x00008000, 0)
    msg = header + question + opt

    fam = socket.AF_INET6 if ":" in target else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(msg, (target, 53))
    try:
        data, _ = s.recvfrom(4096)
    except socket.timeout:
        return {"timeout": True}
    finally:
        s.close()

    if len(data) < 12:
        return {"error": "short response"}
    txid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    rcodes = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"]
    rc = flags & 0x0F
    return {
        "rcode": rcodes[rc] if rc < len(rcodes) else f"RCODE{rc}",
        "ad": bool((flags >> 5) & 1),
        "qd": qd,
        "an": an,
        "bytes": len(data),
    }


# Retry these once — the real internet occasionally flakes on first
# queries while iterative recursion fills the cache.
def _retry(fn, attempts=3):
    last = None
    for _ in range(attempts):
        r = fn()
        if not r.get("timeout") and "error" not in r:
            return r
        last = r
        import time
        time.sleep(0.3)
    return last or {"error": "no response"}


def test_signed_zone_returns_ad_bit(dnsd_query):
    """Positive DNSSEC: icann.org is signed with a chain-of-trust
    back to the IANA root KSK. dnsd must set AD=1 on the response."""
    dnsd_query("cache", "--op", "flush")
    r = _retry(lambda: _dns_query_with_do("10.99.0.2", "icann.org"))
    assert not r.get("timeout"), f"query timed out: {r}"
    assert r.get("rcode") == "NOERROR", f"expected NOERROR, got: {r}"
    assert r["ad"] is True, f"expected AD=1 on signed name, got: {r}"
    assert r.get("an", 0) >= 1


def test_signed_zone_tls_size_multiple(dnsd_query):
    """Another signed public zone — NLnet Labs (Unbound authors),
    DNSSEC-signed. Exercises a different TLD + key combo."""
    dnsd_query("cache", "--op", "flush")
    r = _retry(lambda: _dns_query_with_do("10.99.0.2", "nlnetlabs.nl"))
    assert not r.get("timeout"), f"query timed out: {r}"
    assert r.get("rcode") == "NOERROR", f"unexpected: {r}"
    assert r["ad"] is True, f"expected AD=1 on signed name, got: {r}"


def test_bogus_signature_servfails(dnsd_query):
    """dnssec-failed.org is deliberately published with a broken
    signature chain. The validator must detect the tampered RRSIG
    and SERVFAIL rather than returning the forged answer."""
    dnsd_query("cache", "--op", "flush")
    r = _retry(lambda: _dns_query_with_do("10.99.0.2", "dnssec-failed.org"))
    assert not r.get("timeout"), f"query timed out: {r}"
    assert r.get("rcode") == "SERVFAIL", (
        f"expected SERVFAIL on bogus DNSSEC, got: {r}"
    )
    assert r.get("an", 0) == 0


def test_bogus_host_under_bogus_zone_also_servfails(dnsd_query):
    """Hosts under a bogus zone inherit the failure — any record
    inside dnssec-failed.org should be refused, not just the apex."""
    dnsd_query("cache", "--op", "flush")
    r = _retry(lambda: _dns_query_with_do(
        "10.99.0.2", "www.dnssec-failed.org"
    ))
    assert not r.get("timeout"), f"query timed out: {r}"
    assert r.get("rcode") == "SERVFAIL", (
        f"expected SERVFAIL inside bogus zone, got: {r}"
    )


def test_dnssec_validated_counter_increments(dnsd_query):
    """Every Secure validation bumps metrics.dnssec_validated —
    gives the control socket + log plane a way to see that the
    validator actually ran."""
    dnsd_query("cache", "--op", "flush")
    before = dnsd_query("stats")
    validated_before = before.get("dnssec_validated", 0)

    r = _retry(lambda: _dns_query_with_do("10.99.0.2", "icann.org"))
    assert r.get("rcode") == "NOERROR" and r["ad"]

    after = dnsd_query("stats")
    validated_after = after.get("dnssec_validated", 0)
    assert validated_after > validated_before, (
        f"dnssec_validated didn't advance: {validated_before} -> {validated_after}"
    )


def test_dnssec_failed_counter_increments(dnsd_query):
    """Bogus responses bump metrics.dnssec_failed."""
    dnsd_query("cache", "--op", "flush")
    before = dnsd_query("stats")
    failed_before = before.get("dnssec_failed", 0)

    r = _retry(lambda: _dns_query_with_do("10.99.0.2", "dnssec-failed.org"))
    assert r.get("rcode") == "SERVFAIL"

    after = dnsd_query("stats")
    failed_after = after.get("dnssec_failed", 0)
    assert failed_after > failed_before, (
        f"dnssec_failed didn't advance: {failed_before} -> {failed_after}"
    )


# --- NSEC / NSEC3 denial-of-existence proofs ---------------------


def test_nxdomain_under_signed_zone_sets_ad(dnsd_query):
    """A non-existent name under a signed zone must return NXDOMAIN
    with AD=1. Requires the authority section to carry NSEC or NSEC3
    records that prove the name is absent, and the validator to
    walk those proofs end-to-end.

    `icann.org` is NSEC3-signed; any clearly-nonexistent subdomain
    exercises the closest-encloser + next-closer + wildcard proof."""
    dnsd_query("cache", "--op", "flush")
    bogus = "nonexistent-a98c72e6-test.icann.org"
    r = _retry(lambda: _dns_query_with_do("10.99.0.2", bogus))
    assert not r.get("timeout"), f"query timed out: {r}"
    assert r.get("rcode") == "NXDOMAIN", f"expected NXDOMAIN, got: {r}"
    assert r["ad"] is True, f"NXDOMAIN denial didn't validate (AD=0): {r}"


def test_nxdomain_under_nsec_signed_zone_sets_ad(dnsd_query):
    """Same as above but targeting an NSEC-signed zone (as opposed
    to NSEC3). nlnetlabs.nl uses NSEC; the walk exercises the
    NSEC-specific two-NSEC coverage proof (name range + wildcard
    range) rather than the NSEC3 closest-encloser chain."""
    dnsd_query("cache", "--op", "flush")
    bogus = "bogus-test-5f4c2d7e.nlnetlabs.nl"
    r = _retry(lambda: _dns_query_with_do("10.99.0.2", bogus))
    assert not r.get("timeout"), f"query timed out: {r}"
    assert r.get("rcode") == "NXDOMAIN", f"expected NXDOMAIN, got: {r}"
    assert r["ad"] is True, f"NXDOMAIN denial didn't validate (AD=0): {r}"


def test_nodata_under_signed_zone_sets_ad(dnsd_query):
    """NOERROR-with-no-answers (NODATA) also requires a validated
    denial proof — the zone returns an NSEC/NSEC3 at the queried
    name whose type bitmap omits the queried type.

    icann.org has an A record; querying for a type that doesn't
    exist at the apex (e.g. HINFO, rtype 13) hits the NODATA path."""
    dnsd_query("cache", "--op", "flush")
    r = _retry(lambda: _dns_query_with_do(
        "10.99.0.2", "icann.org", rtype=13  # HINFO
    ))
    assert not r.get("timeout"), f"query timed out: {r}"
    assert r.get("rcode") == "NOERROR", f"expected NOERROR NODATA, got: {r}"
    assert r.get("an", 0) == 0, f"expected empty answer, got {r}"
    assert r["ad"] is True, f"NODATA denial didn't validate (AD=0): {r}"
