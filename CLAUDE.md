# dnsd notes

## DoH server is hand-rolled — no hyper, no axum

`src/io/doh.rs` does NOT use hyper or axum. Four different attempts to
get hyper's `serve_connection` working under VCL/libvppcom on the
real-network path failed (see git log around 9de2152..98ffc73 for the
breadcrumb). The HTTP/1.1 side is a minimal parser written against the
same `read_exact`/`write_all` primitives that DoT uses — DoT works
fine on the same substrate, so mirroring its shape sidesteps whatever
wakeup quirk hyper hits.

If a future change reaches for axum / hyper to "simplify" DoH:
**don't**. The hand-roll exists because the framework path wedges on
the production transport.

Constraints baked in by this design:

- HTTP/1.1 with keep-alive (`feabec9`).
- `MAX_HEADER_BYTES = 8192`, `MAX_BODY_BYTES = 65535` (parity with
  DoT's `MAX_TCP_MESSAGE`).

## HTTP/2 for DoH — implemented via the `h2` crate

dnsd serves both HTTP/1.1 and HTTP/2 for DoH. ALPN advertises `dot`,
`h2`, and `http/1.1`; rustls negotiates by server preference, so
h2-capable clients get h2 and h1.1-only clients still get h1.1. The
h2 path (`serve_h2` / `handle_h2_request` in `src/io/doh.rs`) uses the
`h2` framing crate — a pure frame codec layered over the same
`TlsStream` the HTTP/1.1 path uses. It is **not** a return to hyper
(hyper wedges on VCL — see above); `h2` is the framing layer hyper
itself uses internally, taken on its own.

Why h2 was needed: Windows's system encrypted-DNS client is
DoH-only and offers **only** the `h2` ALPN — it will not fall back to
HTTP/1.1. Before h2, a Windows DoH ClientHello shared no ALPN protocol
with dnsd and the TLS handshake failed outright. This was wire-proven
on jt-router (a `bvi100` capture of the Windows host retrying
`[2602:f90e::101]:443` every ~2s). Earlier (`a02bad9`) `h2` was
*dropped* from the ALPN precisely because dnsd could not serve it;
that constraint is now lifted.

If `h2` is ever found to wedge on VCL the way hyper did, the fix is at
the framing layer, not a framework swap — but the hand-rolled HTTP/1.1
path remains the proven fallback for any client that offers it.

## Encrypted-DNS discovery (RFC 9462 DDR)

`src/recursor/ddr.rs` answers `_dns.resolver.arpa` SVCB locally —
the in-band path Apple platforms use to discover an encrypted
resolver. The matching out-of-band advertisement (RFC 9463 DNR) is
emitted by sibling daemons: the IPv6 RA option by the `sfw` VPP
plugin, the DHCPv4 option (162) by `dhcpd`.
