"""Cache behaviour — flush, dump, negative caching.

The daemon uses moka as the LRU backing store with RFC 2181 positive
TTL and RFC 2308 negative cache. These tests exercise the observable
effects through the control socket.
"""


def test_flush_empties_the_cache(query_udp, dnsd_query, wait_for_cache_entries):
    """`dnsd-query cache --op flush` clears every entry."""
    dnsd_query("cache", "--op", "flush")  # start from a clean slate
    query_udp("www.iana.org")
    query_udp("www.iana.org", rtype=28)  # AAAA so there's >1 entry

    before = wait_for_cache_entries(min_entries=1)
    assert before.get("entries", 0) >= 1, f"cache didn't warm: {before}"

    resp = dnsd_query("cache", "--op", "flush")
    assert resp.get("type") == "ok", resp

    after = dnsd_query("cache", "--op", "stats")
    assert after.get("entries") == 0, f"flush didn't empty cache: {after}"


def test_dump_lists_warmed_entries(query_udp, dnsd_query, wait_for_cache_entries):
    """`dnsd-query cache --op dump` returns structured entries for
    every cached answer: name (FQDN), rtype (text), TTL remaining,
    size in bytes."""
    dnsd_query("cache", "--op", "flush")
    query_udp("www.iana.org")
    wait_for_cache_entries(min_entries=1)

    dump = dnsd_query("cache", "--op", "dump")
    entries = dump.get("entries", [])
    assert entries, f"dump is empty: {dump}"

    entry = next(
        (e for e in entries if e.get("name", "").rstrip(".") == "www.iana.org"),
        None,
    )
    assert entry is not None, f"no www.iana.org entry: {entries}"
    assert entry.get("rtype") == "A"
    assert entry.get("class") == "IN"
    assert entry.get("ttl_remaining_secs", 0) >= 1
    assert entry.get("size_bytes", 0) >= 12  # at least a header


def test_nxdomain_is_cached(query_udp, dnsd_query, wait_for_cache_entries):
    """NXDOMAIN answers go into the negative cache (RFC 2308)."""
    dnsd_query("cache", "--op", "flush")
    bogus = "nonexistent-xyz-abc-9ff2a1.iana.org"

    r1 = query_udp(bogus)
    assert not r1.get("timeout"), "NXDOMAIN query timed out"
    assert r1.get("rcode") == "NXDOMAIN", f"expected NXDOMAIN, got: {r1}"
    wait_for_cache_entries(min_entries=1)

    # The entry may have a synthesised SOA but the name key is what
    # matters for negative caching — it should show up in the dump.
    dump = dnsd_query("cache", "--op", "dump")
    cached = [
        e for e in dump.get("entries", [])
        if e.get("name", "").rstrip(".").endswith(bogus)
    ]
    assert cached, f"NXDOMAIN not cached: dump={dump}"


def test_second_nxdomain_query_is_cache_hit(query_udp, dnsd_query):
    """The cache hit counter moves for repeated NXDOMAIN lookups —
    confirms the negative cache actually short-circuits the forwarder."""
    dnsd_query("cache", "--op", "flush")
    bogus = "nonexistent-xyz-abc-7cb419.iana.org"

    before = dnsd_query("stats")
    hits_before = before.get("cache_hits", 0)

    r1 = query_udp(bogus)
    assert r1.get("rcode") == "NXDOMAIN"
    r2 = query_udp(bogus)
    assert r2.get("rcode") == "NXDOMAIN"

    after = dnsd_query("stats")
    hits_after = after.get("cache_hits", 0)
    assert hits_after > hits_before, (
        f"NXDOMAIN not hitting cache: {hits_before} -> {hits_after}"
    )
