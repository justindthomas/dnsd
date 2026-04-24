"""Smoke tests — dnsd + VPP come up and answer a forwarded query.

Focus is verifying the daemon itself works end-to-end:
  - Control socket responds (→ dnsd is alive)
  - Listener is bound on the VCL side (→ VPP app-namespace wiring OK)
  - A UDP + TCP query for a forwarded name gets answered (→ upstream
    forwarding + wire codec)
"""

import pytest


def test_control_socket_returns_stats(dnsd_query):
    """dnsd-query stats returns a well-formed snapshot."""
    resp = dnsd_query("stats")
    assert "_error" not in resp, resp
    assert "_raw" not in resp, resp
    # Top-level tag and counters we defined in metrics::MetricsSnapshot.
    assert resp.get("type") == "stats" or "queries_udp" in resp, resp


def test_forwarders_listing(dnsd_query):
    """Control socket reports the configured forwarder."""
    resp = dnsd_query("forwarders")
    assert "_error" not in resp, resp
    forwarders = resp.get("forwarders", [])
    assert any(
        f.get("domain", "").rstrip(".") == "iana.org" for f in forwarders
    ), f"expected iana.org forwarder, got: {forwarders!r}"


def test_vpp_session_layer_alive(ssh):
    """Confirms VPP's session layer registered dnsd as an app."""
    rc, out, _ = ssh("vppctl -s /run/vpp/cli.sock show app 2>&1")
    assert rc == 0, f"vppctl failed: {out}"
    assert "dnsd" in out, f"dnsd not registered with VPP: {out}"


def test_udp_query_forwarded_domain_returns_answer(query_udp):
    """A UDP query for iana.org (forwarded to 1.1.1.1) returns
    NOERROR with at least one answer."""
    r = query_udp("www.iana.org")
    assert not r.get("timeout"), "query timed out — dnsd didn't respond"
    assert r.get("rcode") == "NOERROR", f"unexpected: {r}"
    assert r.get("an", 0) >= 1, f"no answers: {r}"


def test_tcp_query_forwarded_domain_returns_answer(query_tcp):
    """Same query over TCP exercises the VclListener path."""
    r = query_tcp("www.iana.org")
    assert not r.get("timeout"), "TCP query timed out"
    assert r.get("rcode") == "NOERROR", f"unexpected: {r}"
    assert r.get("an", 0) >= 1, f"no answers: {r}"


def test_unmatched_name_resolves_via_recursion(recursive_query):
    """Names outside the `iana.org` forwarder fall through to
    iterative recursion (enabled in router.yaml) and resolve against
    the real root → TLD → authoritative chain.

    Uses `example.com` specifically because its delegation has full
    v4 glue all the way through — several other commonly-cited names
    (example.org, iana.com) hit glueless NS sub-walks that the
    current recursor doesn't always complete."""
    r = recursive_query("example.com")
    assert not r.get("timeout"), "query timed out"
    assert r.get("rcode") == "NOERROR", f"expected NOERROR, got: {r}"
    assert r.get("an", 0) >= 1, f"no answers: {r}"


def test_cache_second_query_is_hit(query_udp, dnsd_query):
    """Second query for the same name should register as a cache hit."""
    # Start from a clean slate.
    dnsd_query("cache", "--op", "flush")
    before = dnsd_query("stats")
    hits_before = before.get("cache_hits", 0) if "_error" not in before else 0

    # Miss then hit.
    r1 = query_udp("www.iana.org")
    assert r1.get("rcode") == "NOERROR"
    r2 = query_udp("www.iana.org")
    assert r2.get("rcode") == "NOERROR"

    after = dnsd_query("stats")
    hits_after = after.get("cache_hits", 0) if "_error" not in after else 0
    assert hits_after > hits_before, (
        f"cache hit counter didn't move: before={hits_before} after={hits_after}"
    )
