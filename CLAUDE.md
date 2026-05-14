# dnsd notes

## DoH HTTP/1.1 server is hand-rolled

`src/io/doh.rs` does NOT use hyper or axum. Four different attempts to
get hyper's `serve_connection` working under VCL/libvppcom on the
real-network path failed (see git log around 9de2152..98ffc73 for the
breadcrumb). The current implementation is a minimal HTTP/1.1 parser
written against the same `read_exact`/`write_all` primitives that DoT
uses — DoT works fine on the same substrate, so mirroring its shape
sidesteps whatever wakeup quirk hyper hits.

Constraints baked in by this design:

- One request per connection (no keep-alive). Real DoH clients open
  a fresh connection per query in practice.
- HTTP/1.1 only. ALPN advertises `h2` for forward-compatibility but
  we close cleanly if a client actually negotiates h2 — they fall
  back to h1.1 on retry. Adding h2 means a frame-level parser; not
  yet done.
- `MAX_HEADER_BYTES = 8192`, `MAX_BODY_BYTES = 65535` (parity with
  DoT's `MAX_TCP_MESSAGE`).

If a future change reaches for axum / hyper to "simplify" DoH:
**don't**. The hand-roll exists because the framework path wedges on
the production transport.
