# dnsd notes

## DoH HTTP/1.1 server is hand-rolled

`src/io/doh.rs` does NOT use hyper or axum. Four different attempts to
get hyper's `serve_connection` working under VCL/libvppcom on the
real-network path failed (see git log around 9de2152..98ffc73 for the
breadcrumb). The current implementation is a minimal HTTP/1.1 parser
written against the same `read_exact`/`write_all` primitives that DoT
uses — DoT works fine on the same substrate, so mirroring its shape
sidesteps whatever wakeup quirk hyper hits.

If a future change reaches for axum / hyper to "simplify" DoH:
**don't**. The hand-roll exists because the framework path wedges on
the production transport.

Constraints baked in by this design:

- HTTP/1.1 with keep-alive (`feabec9`).
- `MAX_HEADER_BYTES = 8192`, `MAX_BODY_BYTES = 65535` (parity with
  DoT's `MAX_TCP_MESSAGE`).
- ALPN advertises `dot` and `http/1.1` only — **not** `h2`
  (`a02bad9` dropped it: clients that negotiate h2 and then see the
  server speak HTTP/1.1 treat the resolver as broken instead of
  retrying).

## HTTP/2 for DoH is deferred by choice, not difficulty

dnsd does not implement HTTP/2. That is a deliberate scoping
decision — no consumer has needed it yet, so the work was not
justified — **not** a judgement that it is too hard. Whenever a
concrete need appears, h2 should be implemented: it would be a
frame-level h2 layer over the existing `read_exact`/`write_all`
stream primitives, *not* a return to hyper (which wedges — see
above).

Known trigger to revisit: a DoH-only client that will not fall back
to HTTP/1.1. The concrete case is RFC 9463 DNR for Windows —
Windows's system encrypted DNS is DoH-only, so reaching it via the
DNR option needs dnsd to speak h2. If that path (or any other)
becomes worth unblocking, h2 is firmly on the table.

## Encrypted-DNS discovery (RFC 9462 DDR)

`src/recursor/ddr.rs` answers `_dns.resolver.arpa` SVCB locally —
the in-band path Apple platforms use to discover an encrypted
resolver. The matching out-of-band advertisement (RFC 9463 DNR) is
emitted by sibling daemons: the IPv6 RA option by the `sfw` VPP
plugin, the DHCPv4 option (162) by `dhcpd`.
