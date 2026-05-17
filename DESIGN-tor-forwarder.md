# Design — DoT-over-Tor forwarders (`via: tor`)

Status: **proposed**, not yet implemented. This documents the dnsd
side of the tord integration (tord — the VPP-native anonymising SOCKS5
proxy — is built and integrated into imp already).

## 1. Goal

Let a per-domain forwarder send its upstream queries through Tor, so
the operator's ISP cannot see which names dnsd resolves. A forwarder
server gains a `via: tor` option: dnsd opens a TCP stream to tord's
SOCKS5 endpoint, `CONNECT`s to the upstream resolver, runs DoT inside
that tunnel, and speaks ordinary length-prefixed DNS.

Result: the ISP sees only Tor traffic; the Tor exit sees only TLS to
`<resolver>:853`; the upstream resolver sees the queries but a Tor
exit IP, not the subscriber.

## 2. Why this shape

- **Tor is TCP-only.** The `via: tor` path cannot use dnsd's UDP-first
  upstream — it forces TCP from the first leg.
- **DoT, not plain TCP.** Plain DNS over a Tor circuit would let the
  exit node read the queries. TLS-in-the-tunnel keeps the exit blind.
- **SOCKS5, not a bespoke link.** tord is a standard SOCKS5 server;
  dnsd is just another SOCKS5 client (the LAN-gateway case in tord's
  DESIGN.md §5 — except dnsd reaches it as a co-located VCL app).

## 3. Config schema

Today: `Forwarder { domain: String, servers: Vec<IpAddr> }`.

Proposed — a server is **either** a bare IP (back-compat: direct UDP,
exactly as now) **or** a full spec:

```yaml
dns:
  tor_socks: "127.0.0.1:9050"      # tord's SOCKS5 endpoint (default)
  forwarders:
    - domain: jdt.io
      servers: [10.42.128.19]      # bare IP — direct UDP, unchanged
    - domain: .
      servers:
        - address: 9.9.9.9
          transport: dot           # udp (default) | tcp | dot
          tls_name: dns.quad9.net  # required when transport = dot
          via: tor                 # direct (default) | tor
      # fail-closed is automatic when any server is `via: tor` (§6)
```

Rust (`config.rs`):

```rust
#[serde(untagged)]
enum ServerSpec { Bare(IpAddr), Full(ForwarderServer) }

struct ForwarderServer {
    address: IpAddr,
    #[serde(default)] transport: Transport,   // Udp | Tcp | Dot
    tls_name: Option<String>,                 // required iff Dot
    #[serde(default)] via: Via,               // Direct | Tor
}
```

`Forwarder.servers` becomes `Vec<ServerSpec>`, normalised on load to
`Vec<ForwarderServer>` (a bare IP → `{address, Udp, None, Direct}`).
Validation at load time: `transport: dot` requires `tls_name`;
`via: tor` requires `transport` ∈ {tcp, dot} (reject `udp`).

`tor_socks` is a new `dns:`-level field — dnsd reads `dns:`, not the
`tor:` block, so it needs its own pointer at tord's SOCKS address.
Default `127.0.0.1:9050` (the cut-through case — see §7).

## 4. The config-type ripple

`forwarder.rs` currently threads `Vec<IpAddr>` / `&[IpAddr]` through
`ForwarderEntry.servers`, `Forwarders::lookup() -> &[IpAddr]`,
`Forwarders::snapshot()`, and `UpstreamClient::query(servers: &[IpAddr])`.
All of these change to carry `ForwarderServer` instead. This is the
bulk of the diff and the part to review carefully — it touches the
hot path's types end to end. No behaviour changes for bare-IP
servers; the new variants are additive.

## 5. Two new modules

### 5.1 SOCKS5 client (`recursor/socks.rs` or `io/`)

~60 lines. Given a connected stream to tord and a target
`(host, port)`: send the RFC 1928 greeting (`NO AUTH`, optionally
username/password for circuit isolation — §8), read the method
reply, send a `CONNECT` request (ATYP domain or IP), read the reply,
return the now-tunnelled stream. Mirror of tord's SOCKS5 *server*
(`socks/server.rs`), inverted.

### 5.2 DoT client

DoT = TLS + the 2-byte-length DNS framing dnsd's TCP path already
uses. So the DoT client is: a `rustls::ClientConfig` (webpki roots,
verify the cert against `tls_name`, ALPN `dot`), wrap the
(SOCKS-tunnelled) stream in a `tokio_rustls` client connection, then
reuse the existing length-prefixed query logic. dnsd already links
rustls (DoT/DoH *server*) and has TCP-DNS framing — this is mostly
assembly, not new protocol.

## 6. Forwarder integration & fail-closed

`UpstreamClient::query_one` branches on the server's `transport`/`via`:

- `via: direct, transport: udp` — today's path (UDP-first, TC→TCP).
- `via: direct, transport: tcp|dot` — skip UDP, go straight to TCP /
  DoT (the `force_tcp` case the current code comments anticipate).
- `via: tor` — connect to `dns.tor_socks` (via `VclStream::connect_async`,
  same as the existing TCP upstream), SOCKS5-`CONNECT` to
  `(address, 853)`, rustls handshake against `tls_name`, then the
  length-prefixed query. Never UDP.

**Fail-closed (critical, not optional).** A `via: tor` server must
never fall back to a direct path. If tord is unreachable, the circuit
is not bootstrapped, or the SOCKS/TLS handshake fails, the query for
that server fails — and the forwarder does **not** try a `via: direct`
sibling that would leak; it returns SERVFAIL. This is **forced**
whenever any server on the forwarder is `via: tor`; it is not an
operator-settable flag, because opting into a leak should not be a
one-line config typo. A silent direct fallback is a deanonymisation
bug, not a resilience feature.

## 7. tord reachability (VRF note)

Default-VRF dnsd reaching default-VRF tord: `dns.tor_socks` is a
loopback (`127.0.0.1:9050`); `VclStream::connect` gives a VPP
cut-through session — no NIC, no kernel. Per-VRF `imp-dnsd@<vrf>`
reaching tord is the routable-`socks_listen` case (tord DESIGN.md
§5.1) — out of scope here; v1 targets the default VRF.

## 8. Interactions

- **0x20 / TXID.** Keep both. TXID still matters over TCP. 0x20 over a
  TLS channel is belt-and-braces but cheap — leave it on.
- **TC fallback.** Irrelevant for DoT (already TCP); the TC→TCP retry
  is skipped on the `via: tor` path.
- **Circuit isolation.** Optionally pass a per-forwarder SOCKS
  username so tord (with `isolation: per-upstream`) gives each
  forwarder its own circuits. v1 may omit this (shared circuits).
- **Latency.** Tor adds 100 ms–1 s+. The moka cache absorbs repeats;
  a persistent DoT connection over a long-lived circuit (connection
  reuse) is the mitigation — v1 may open per-query and optimise later.
- **DNSSEC.** DoT carries RRSIG/DNSKEY fine; no interaction with the
  validator beyond the larger-response/TCP path it already handles.

## 9. Test plan

- Config: round-trip bare-IP and full-spec servers; reject
  `dot` without `tls_name` and `via: tor` with `udp`.
- SOCKS5 client: unit-test the handshake against a stub server
  (tord's own SOCKS5 server is the reference).
- DoT client: against a known DoT resolver in the `kernel-sockets`
  build.
- Fail-closed: with tord absent, a `via: tor` forwarder returns
  SERVFAIL and never emits a direct upstream packet (assert via the
  upstream socket counters / a capture).
- Integration: `pytests_dnsd` slim suite — a `via: tor` forwarder
  against a real tord on the build host.

## 10. Phasing

1. ✅ **Done.** Config schema + the `Vec<IpAddr>` →
   `Vec<ForwarderServer>` ripple, no behaviour change for bare-IP
   servers; `Forwarder::resolved_servers()` validates and rejects
   not-yet-wired combinations (tcp/dot/`via: tor`). Parse +
   validation tests; 112 dnsd tests green.
2. SOCKS5 client module + unit tests.
3. DoT client module + unit tests.
4. `query_one` integration + fail-closed; the `force_tcp` and DoT
   direct paths fall out of the same branching.
5. Circuit-isolation username, connection reuse, the slim suite.

## 11. Decisions & open questions

Resolved (operator-approved):

- **`tor_socks` is a single global `dns:`-level field**, not
  per-forwarder. Per-VRF `imp-dnsd@<vrf>` would want per-instance;
  deferred with the broader VRF story.
- **Fail-closed is forced**, not an operator flag: any forwarder with
  a `via: tor` server returns SERVFAIL rather than leaking to a
  direct sibling (§6).

Open:

- Connection reuse / circuit pinning vs per-query connect — v1 does
  per-query for simplicity; measure before optimising.
