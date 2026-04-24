"""Protocol parity — TCP and UDP should return the same answers for
the same question, and large responses should survive the TCP
length-prefix framing (RFC 1035 §4.2.2)."""


def test_tcp_and_udp_agree_on_rcode(query_udp, query_tcp):
    """The same question over both transports yields the same rcode
    + answer count."""
    udp = query_udp("www.iana.org")
    tcp = query_tcp("www.iana.org")
    assert not udp.get("timeout") and not tcp.get("timeout"), (udp, tcp)
    assert udp.get("rcode") == tcp.get("rcode") == "NOERROR"
    # IANA serves multiple A records; both responses should have >=1.
    assert udp.get("an", 0) >= 1
    assert tcp.get("an", 0) >= 1


def test_tcp_length_framing_correct(query_tcp):
    """Malformed 2-byte length prefix would cause the client to
    see a short response; our client already enforces that and
    returns 'error: short length prefix' if so."""
    r = query_tcp("www.iana.org")
    assert "error" not in r, f"length framing broken: {r}"
    # Response has to include header + question + answers — minimum
    # ~60 bytes for a single A record.
    assert r.get("bytes", 0) >= 60, f"suspiciously short: {r}"


def test_udp_header_flags(query_udp):
    """A forwarded NOERROR response should have QR=1, RA=1 (we're a
    recursive server); rcode=0. The header parser in conftest gives
    us rcode text — we can cross-check via the raw bytes."""
    r = query_udp("www.iana.org")
    raw = r.get("raw")
    assert raw and len(raw) >= 12
    flags = int.from_bytes(raw[2:4], "big")
    assert flags & 0x8000, "QR not set — dnsd didn't respond as a server"
    assert flags & 0x0080, "RA not set — dnsd says it's non-recursive"
    assert (flags & 0x000F) == 0, "rcode != NOERROR"


def test_response_txid_matches_query(query_udp):
    """TXID preservation: the client generated TXID must come back
    unchanged, even though dnsd rewrites it for the upstream query."""
    r = query_udp("www.iana.org")
    raw = r.get("raw")
    assert raw and len(raw) >= 2
    # conftest.query_udp uses TXID 0x1234.
    assert raw[0] == 0x12 and raw[1] == 0x34, (
        f"TXID mangled: {raw[:2].hex()}"
    )
