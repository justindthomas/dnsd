"""Control-socket commands — the json-line protocol at /run/dnsd.sock
(and its `dnsd-query` CLI wrapper)."""


def test_stats_shape(dnsd_query):
    """Every documented counter appears in the stats blob."""
    s = dnsd_query("stats")
    assert "_error" not in s, s
    for k in (
        "queries_udp",
        "queries_tcp",
        "queries_dot",
        "queries_doh",
        "cache_hits",
        "cache_misses",
        "forwarder_matched",
        "recursion_walked",
        "rrl_dropped",
        "acl_denied",
        "dns64_synthesised",
        "dnssec_validated",
        "dnssec_failed",
    ):
        assert k in s, f"missing {k!r} in stats: {s}"


def test_forwarders_shape(dnsd_query):
    """`dnsd-query forwarders` returns the materialised table."""
    f = dnsd_query("forwarders")
    assert f.get("type") == "forwarders"
    assert isinstance(f.get("forwarders"), list)
    assert f["forwarders"], "no forwarders configured"
    entry = f["forwarders"][0]
    assert "domain" in entry and "servers" in entry
    assert isinstance(entry["servers"], list) and entry["servers"]


def test_reload_roundtrips_and_keeps_serving(dnsd_query, query_udp):
    """`reload` sends SIGHUP to self — dnsd stays up + keeps answering."""
    r = dnsd_query("reload")
    assert r.get("type") == "ok", r

    import time
    time.sleep(0.3)  # give dnsd a moment to process the SIGHUP

    # Still serving: query resolves.
    ans = query_udp("www.iana.org")
    assert not ans.get("timeout"), "dnsd stopped serving after reload"
    assert ans.get("rcode") == "NOERROR"


def test_sighup_via_signal_keeps_serving(ssh, query_udp):
    """Equivalent of the reload command but sent as a real UNIX signal
    — confirms the signal handler is wired, not just the control RPC."""
    rc, _, _ = ssh("pkill -HUP dnsd")
    assert rc == 0, "pkill -HUP failed"

    import time
    time.sleep(0.3)

    ans = query_udp("www.iana.org")
    assert not ans.get("timeout"), "dnsd didn't survive SIGHUP"
    assert ans.get("rcode") == "NOERROR"


def test_upstream_trace_stub(dnsd_query):
    """The `upstream` command is a stub in v1 (full tracing is a
    follow-up). It should still return a well-formed response so the
    CLI wrapper doesn't choke."""
    r = dnsd_query("upstream", "www.iana.org")
    assert r.get("type") == "trace"
    assert isinstance(r.get("steps"), list)
    assert r["steps"], "expected at least one trace step"
