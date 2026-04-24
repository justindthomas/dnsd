"""DNS64 AAAA synthesis (RFC 6147).

router.yaml configures `dns64: true` on the v6 listener (wan-v6,
[2001:db8:99::2]:53) but NOT on the v4 listener — so queries for
v4-only names behave differently per listener:

  * v6 listener + v4-only name → synthesised AAAA `64:ff9b::<v4>`
  * v4 listener + same name → empty AAAA (no synthesis)

These tests use `ipv4.google.com` as the canonical v4-only name.
Google maintains it as a permanent v4-only fixture; it returns
CNAMEs that end in A records with no AAAA at the terminal.
"""

import ipaddress
import socket
import struct
import time


def _query_aaaa(target: str, name: str, timeout: float = 15.0):
    """Raw-DNS AAAA query. Returns a dict with rcode, answer count,
    and decoded AAAA list (v4-in-v6 when synthesised)."""
    fam = socket.AF_INET6 if ":" in target else socket.AF_INET
    parts = name.rstrip(".").split(".")
    qname = b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"
    msg = (
        struct.pack(">HHHHHH", 0x6464, 0x0100, 1, 0, 0, 0)
        + qname
        + struct.pack(">HH", 28, 1)  # AAAA, IN
    )
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
    flags = int.from_bytes(data[2:4], "big")
    rcodes = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"]
    rc = flags & 0x0F
    an = int.from_bytes(data[6:8], "big")

    def skip_name(buf: bytes, off: int) -> int:
        """Walk a DNS name until root-null OR a 2-byte compression
        pointer. Mixed (uncompressed labels + trailing pointer) is
        common in real responses; a naive "null-or-pointer" check
        misreads them and corrupts the offset for later records."""
        while off < len(buf):
            lbl = buf[off]
            if lbl == 0:
                return off + 1
            if lbl & 0xC0 == 0xC0:
                return off + 2
            off += 1 + lbl
        return off

    # Walk answer section looking for AAAA records.
    aaaas = []
    cnames = 0
    if an > 0 and rc == 0:
        i = skip_name(data, 12)
        i += 4  # qtype + qclass
        for _ in range(an):
            if i + 12 > len(data):
                break
            i = skip_name(data, i)
            atype = int.from_bytes(data[i:i + 2], "big")
            i += 2 + 2 + 4  # type + class + ttl
            rdl = int.from_bytes(data[i:i + 2], "big")
            i += 2
            if atype == 28 and rdl == 16:
                aaaas.append(str(ipaddress.IPv6Address(data[i:i + 16])))
            elif atype == 5:
                cnames += 1
            i += rdl
    return {
        "rcode": rcodes[rc] if rc < len(rcodes) else f"RCODE{rc}",
        "an": an,
        "aaaa": aaaas,
        "cnames": cnames,
    }


V6_LISTENER = "2001:db8:99::2"
V4_LISTENER = "10.99.0.2"


def test_dns64_synthesises_aaaa_for_v4_only_name(dnsd_query):
    """v6 listener has `dns64: true`; a v4-only name returns
    synthesised AAAAs embedded in `64:ff9b::/96`."""
    dnsd_query("cache", "--op", "flush")
    r = _query_aaaa(V6_LISTENER, "ipv4.google.com")
    assert not r.get("timeout"), r
    assert r.get("rcode") == "NOERROR", r
    assert r.get("aaaa"), f"no synthesised AAAAs in answer: {r}"
    # Every synth'd AAAA must fall within 64:ff9b::/96.
    wkp = ipaddress.IPv6Network("64:ff9b::/96")
    for a in r["aaaa"]:
        assert ipaddress.IPv6Address(a) in wkp, f"AAAA {a} outside WKP prefix"


def test_dns64_preserves_cname_chain(dnsd_query):
    """Synthesised responses keep the CNAME chain from the A
    response so clients see why the AAAAs are at a different owner
    name than they queried."""
    dnsd_query("cache", "--op", "flush")
    r = _query_aaaa(V6_LISTENER, "ipv4.google.com")
    assert not r.get("timeout")
    assert r.get("rcode") == "NOERROR"
    # ipv4.google.com CNAMEs to an internal Google name; the chain
    # plus the synthesised AAAAs means total an >= 2.
    assert r.get("an", 0) >= 2, f"expected CNAME + AAAAs, got {r}"
    assert r.get("cnames", 0) >= 1, f"CNAME chain stripped: {r}"


def test_dns64_excluded_name_stays_unsynthesised(dnsd_query):
    """`ipv4only.arpa.` is on the DNS64 exclusion list per RFC 7050
    — clients probe it to detect whether they're behind a
    synthesiser. We MUST return the upstream's answer (typically
    empty AAAA) unmodified."""
    dnsd_query("cache", "--op", "flush")
    r = _query_aaaa(V6_LISTENER, "ipv4only.arpa")
    assert not r.get("timeout"), r
    assert r.get("rcode") == "NOERROR", r
    # Upstream returns empty AAAA — we must NOT synthesise.
    assert not r.get("aaaa"), (
        f"ipv4only.arpa got synthesised AAAAs (should have been excluded): {r}"
    )


def test_dns64_not_triggered_on_v4_listener(dnsd_query):
    """v4 listener has no `dns64:` key — the same v4-only name
    should NOT be synthesised there even if the same name's AAAA
    was synth'd on the v6 listener earlier (no cross-listener
    cache pollution)."""
    dnsd_query("cache", "--op", "flush")
    # Warm via v6 so a cached A exists.
    r_v6 = _query_aaaa(V6_LISTENER, "ipv4.google.com")
    assert r_v6.get("aaaa"), "precondition: v6 listener should synthesise"

    # Same name on v4 listener — no DNS64, no synthesis.
    r_v4 = _query_aaaa(V4_LISTENER, "ipv4.google.com")
    assert not r_v4.get("timeout")
    assert r_v4.get("rcode") == "NOERROR", r_v4
    assert not r_v4.get("aaaa"), (
        f"v4 listener leaked synth'd AAAAs from v6 cache: {r_v4}"
    )


def test_dns64_cache_served_without_resynth(dnsd_query):
    """Second query on the DNS64 listener hits cache (via the A
    record's cached response) and synthesises on the fly — should
    be near-instant."""
    dnsd_query("cache", "--op", "flush")
    # Warm.
    _query_aaaa(V6_LISTENER, "ipv4.google.com")

    t0 = time.time()
    r = _query_aaaa(V6_LISTENER, "ipv4.google.com")
    elapsed = time.time() - t0
    assert r.get("aaaa"), f"expected synth'd AAAAs on cached query: {r}"
    assert elapsed < 0.5, (
        f"cached DNS64 query took {elapsed:.2f}s — expected <500 ms"
    )


def test_dns64_counter_increments(dnsd_query):
    """metrics.dns64_synthesised bumps on each synthesised query."""
    dnsd_query("cache", "--op", "flush")
    before = dnsd_query("stats")
    synth_before = before.get("dns64_synthesised", 0)

    r = _query_aaaa(V6_LISTENER, "ipv4.google.com")
    assert r.get("aaaa"), f"no synthesis happened: {r}"

    after = dnsd_query("stats")
    synth_after = after.get("dns64_synthesised", 0)
    assert synth_after > synth_before, (
        f"dns64_synthesised didn't advance: {synth_before} -> {synth_after}"
    )
