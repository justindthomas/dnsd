"""IPv6 listener + upstream coverage.

Exercises:
  - Queries arriving on the v6 listener (`wan-v6`, [2001:db8:99::2]:53)
  - AAAA responses from the forwarder (1.1.1.1 speaks v6 RRs over v4 transport)
  - Iterative recursion choosing v6 root servers (run-tests.sh NATs the
    v6 test prefix onto the host's global default so v6 upstream is live)
  - TCP DNS over v6

The tests work against the v6 listener by passing `target=VM_IP6` into
the existing `query_udp` / `query_tcp` fixtures — they infer the socket
family from the address literal.
"""

from conftest import VM_IP6


def test_v6_listener_udp(query_udp):
    """Forwarded UDP query arrives on the v6 listener and returns."""
    r = query_udp("www.iana.org", target=VM_IP6)
    assert not r.get("timeout"), "v6 UDP query timed out"
    assert r.get("rcode") == "NOERROR", f"unexpected: {r}"
    assert r.get("an", 0) >= 1


def test_v6_listener_tcp(query_tcp):
    """Forwarded TCP query arrives on the v6 listener and returns —
    exercises VclListener accept on the v6 address + VclStream reads."""
    r = query_tcp("www.iana.org", target=VM_IP6)
    assert not r.get("timeout"), "v6 TCP query timed out"
    assert r.get("rcode") == "NOERROR", f"unexpected: {r}"
    assert r.get("an", 0) >= 1


def test_v6_listener_aaaa_query(query_udp):
    """AAAA query over v6 transport — forwarder returns v6 RRs."""
    r = query_udp("www.iana.org", rtype=28, target=VM_IP6)
    assert not r.get("timeout"), "v6 AAAA query timed out"
    assert r.get("rcode") == "NOERROR", f"unexpected: {r}"
    assert r.get("an", 0) >= 1, f"no AAAA answers: {r}"


def test_v6_listener_recursive(recursive_query):
    """A query on the v6 listener for a non-forwarded name falls
    through to iterative recursion. Uses `example.com` so the
    delegation has v4 glue — `ipv6_upstream: true` in the test config
    means v6 roots are also tried, but we don't require v6 upstream
    to succeed (host's v6 default may vary)."""
    r = recursive_query("example.com", target=VM_IP6)
    assert not r.get("timeout"), "v6 recursive query timed out"
    assert r.get("rcode") == "NOERROR", f"unexpected: {r}"
    assert r.get("an", 0) >= 1


def test_v4_and_v6_share_cache(query_udp, dnsd_query, wait_for_cache_entries):
    """Cache is keyed on (name, rtype, class) — not on transport.
    A query answered for the v4 listener should be served from cache
    for the v6 listener, and vice versa."""
    dnsd_query("cache", "--op", "flush")

    # Warm via v4.
    r4 = query_udp("www.iana.org")
    assert r4.get("rcode") == "NOERROR"
    wait_for_cache_entries(min_entries=1)

    before = dnsd_query("stats")
    hits_before = before.get("cache_hits", 0)

    # Same question on the v6 listener — should hit cache, not forward.
    r6 = query_udp("www.iana.org", target=VM_IP6)
    assert r6.get("rcode") == "NOERROR"

    after = dnsd_query("stats")
    hits_after = after.get("cache_hits", 0)
    assert hits_after > hits_before, (
        f"v6 query didn't hit cache warmed by v4: "
        f"{hits_before} -> {hits_after}"
    )


def test_v6_listener_acl_allow(query_udp):
    """router.yaml allows `2001:db8:99::/64` on the v6 listener. The
    build host side of the bridge is `2001:db8:99::1`, so this query
    comes from an allowed source and succeeds."""
    r = query_udp("www.iana.org", target=VM_IP6)
    assert not r.get("timeout")
    assert r.get("rcode") == "NOERROR"
