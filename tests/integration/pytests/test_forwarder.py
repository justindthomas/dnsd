"""Forwarder behaviour — AAAA, cross-rtype, stats counters.

The VM is configured with a single forwarder `iana.org → 1.1.1.1`.
These tests use real upstream resolution (run-tests.sh sets up NAT
so the VM has internet access).
"""


def test_aaaa_query_returns_answer(query_udp):
    """IANA's website has AAAA records; forwarder should return them."""
    r = query_udp("www.iana.org", rtype=28)
    assert not r.get("timeout"), "AAAA timed out"
    assert r.get("rcode") == "NOERROR", f"expected NOERROR, got: {r}"
    assert r.get("an", 0) >= 1, f"no AAAA answers: {r}"


def test_a_and_aaaa_are_separate_cache_entries(query_udp, dnsd_query):
    """A and AAAA for the same name are keyed independently in the
    cache — the rtype is part of the cache key."""
    dnsd_query("cache", "--op", "flush")
    query_udp("www.iana.org")               # A
    query_udp("www.iana.org", rtype=28)     # AAAA

    dump = dnsd_query("cache", "--op", "dump")
    entries = [
        e for e in dump.get("entries", [])
        if e.get("name", "").rstrip(".") == "www.iana.org"
    ]
    rtypes = sorted(e.get("rtype") for e in entries)
    assert rtypes == ["A", "AAAA"], f"expected A+AAAA entries, got: {entries}"


def test_forwarder_counter_increments(query_udp, dnsd_query):
    """Each forwarded query bumps the forwarder_matched counter —
    verifies longest-suffix match is firing for the configured
    `iana.org` forwarder."""
    dnsd_query("cache", "--op", "flush")
    before = dnsd_query("stats")
    matched_before = before.get("forwarder_matched", 0)

    # Two distinct names, both under iana.org.
    query_udp("www.iana.org")
    query_udp("example.iana.org")  # likely NXDOMAIN; still matches the forwarder

    after = dnsd_query("stats")
    matched_after = after.get("forwarder_matched", 0)
    assert matched_after >= matched_before + 2, (
        f"forwarder_matched didn't advance: {matched_before} -> {matched_after}"
    )


def test_unmatched_name_does_not_bump_forwarder_counter(query_udp, dnsd_query):
    """Names outside any forwarder domain fall through to iterative
    recursion — the forwarder counter should NOT move for these."""
    dnsd_query("cache", "--op", "flush")
    before = dnsd_query("stats")
    matched_before = before.get("forwarder_matched", 0)

    query_udp("example.com", timeout=10.0)

    after = dnsd_query("stats")
    matched_after = after.get("forwarder_matched", 0)
    assert matched_after == matched_before, (
        f"forwarder_matched moved on unmatched: {matched_before} -> {matched_after}"
    )
