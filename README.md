# dnsd

A recursive DNS resolver / forwarder with DNS64, DNSSEC validation
(RFC 4035), automated trust-anchor rotation (RFC 5011), Response
Rate Limiting, and DoT/DoH listeners. Designed to run either inside
a VPP dataplane (the original imp-router use case) or standalone on
plain Linux/macOS sockets — same recursor core, two compile-time
transport backends.

## What's in the box

* Iterative recursor with persisted root hints, in-flight query
  coalescing, parallel sub-walk racing, and a per-zone DNSKEY cache.
* DNSSEC validator. Returns AD on Secure responses, SERVFAIL with
  EDE 6 on Bogus, AD-cleared NoError on Insecure delegations.
* Trust-anchor lifecycle (RFC 5011) — periodic root-DNSKEY refresh,
  30-day hold-down for new KSKs, REVOKE-bit handling, atomic state
  rewrites. Self-bootstraps from build-time-embedded IANA KSKs on
  first run, no out-of-band setup required.
* DNS64 synthesis (RFC 6147) per listener, including ip6.arpa PTR
  rewriting and AD-bit suppression.
* RFC 8880 §7.2 local-answer for `ipv4only.arpa` plus the matching
  `170.0.0.192.in-addr.arpa` / `171.0.0.192.in-addr.arpa` PTRs.
* RFC 6303 local-answer NXDOMAIN for private-IP reverse zones and
  RFC 8375 `home.arpa` — keeps mDNS spam off AS112.
* UDP, TCP, DoT (RFC 7858), and DoH (RFC 8484) listeners. Per-
  listener DNS64 toggle, per-listener allow-list ACLs, hot-reload
  on SIGHUP without rebinding sockets.
* Per-client RRL, EDNS0 cookies (RFC 7873), 0x20 case randomisation
  on outbound queries.
* Operator CLI `dnsd query` (a subcommand of the daemon binary)
  over a Unix control socket: live
  stats, cache inspection, cache flush, forwarder list, SIGHUP-
  equivalent reload.

## Build modes

`dnsd` picks its network transport at compile time via cargo features.
Exactly one of `vcl` (default) or `kernel-sockets` must be enabled.

### `vcl` (default) — through VPP/VCL

```bash
cargo build --release
```

Listeners and upstream queries go through VPP's session layer via
`vcl-rs` (`libvppcom`). The router-deployment path: VPP owns the
LAN-side dataplane address (e.g. an address that lives only inside
VPP, never on the kernel networking stack). Requires VPP running
and `vcl.conf` reachable at startup.

### `kernel-sockets` — standalone

```bash
cargo build --release --no-default-features --features kernel-sockets
```

Listeners and upstream queries use `tokio::net::*` directly on the
kernel TCP/IP stack. No `libvppcom` link, no VPP needed. Use for
plain server / container / VM / desktop deployments.

A compile-time feature guard in `src/io/transport/mod.rs` enforces
the mutual-exclusion.

## Running standalone

The simplest possible config — UDP/TCP on loopback, DNSSEC
validation enabled, anchors auto-bootstrapped:

```yaml
# /etc/dnsd.yaml
hostname: my-resolver
dns:
  enabled: true
  listeners:
    - name: lo
      address: 127.0.0.1
      port: 53
      protocols: [udp, tcp]
      allow_from:
        - 127.0.0.0/8
  recursion:
    enabled: true
    dnssec: validate
```

Launch:

```bash
./target/release/dnsd \
  --config /etc/dnsd.yaml \
  --data-dir /var/lib/dnsd \
  --control-socket /run/dnsd.sock
```

Verify:

```bash
dig @127.0.0.1 example.com
dig @127.0.0.1 cloudflare.com +dnssec   # expect ad flag
dig @127.0.0.1 dnssec-failed.org +dnssec   # expect SERVFAIL + EDE 6
```

That's it. On first start `dnsd` writes `/var/lib/dnsd/anchor/active.key`
+ `active.key.state` (the IANA root KSKs and their RFC 5011 lifecycle
state). The hourly refresh task keeps them current; rolling out of
service or losing connectivity is non-fatal.

### Optional flags

| Flag | Default | Purpose |
|---|---|---|
| `--config` | `/persistent/config/router.yaml` | Path to the YAML config. |
| `--data-dir` | `/persistent/data/dnsd` | Persistent state (root hints, anchor dir, ACME certs). Created on first boot. |
| `--control-socket` | `/run/dnsd.sock` | Unix socket for `dnsd query`. |

`SIGHUP` reloads config in place — listeners that didn't change
keep their existing sockets, recursor state (cache, neg-resolve,
in-flight coalescer) carries over.

`SIGTERM` shuts down cleanly.

### Listening on a privileged port

UDP/TCP 53 needs `CAP_NET_BIND_SERVICE` on Linux. Grant it once
on the binary or use a systemd unit:

```ini
[Service]
ExecStart=/usr/local/bin/dnsd --config /etc/dnsd.yaml \
                              --data-dir /var/lib/dnsd \
                              --control-socket /run/dnsd.sock
AmbientCapabilities=CAP_NET_BIND_SERVICE
DynamicUser=yes
StateDirectory=dnsd
RuntimeDirectory=dnsd
```

## Config reference

The YAML config supports far more than the minimal example. Full
documented reference template is in
`config/router.template.yaml` (or in the upstream `imp` repo when
running on a router). Key blocks:

```yaml
dns:
  enabled: true

  # One or more listeners. Each gets its own ACL + DNS64 toggle.
  listeners:
    - name: lan
      address: 192.168.1.1
      port: 53
      protocols: [udp, tcp, dot, doh]   # any subset
      allow_from:
        - 192.168.1.0/24
      dns64: false                       # default false; per-listener
      max_inflight: 1024                 # UDP load-shed cap; REFUSED above

  # Conditional forwarders. Longest-suffix match on the qname.
  forwarders:
    - domain: corp.local
      servers: [10.0.0.53, 10.0.0.54]

  # Iterative recursion. Defaults to enabled when this block is
  # absent. Set enabled: false to be a forward-only daemon.
  recursion:
    enabled: true
    dnssec: validate                     # passthrough | strip | validate
    # trust_anchor: /etc/dnsd/root.key   # optional override; otherwise self-managed
    ipv6_upstream: true
    # source_v6: "2001:db8::1"           # pin v6 egress source
    upstream_timeout_ms: 2500
    max_cname_depth: 8

  cache:
    max_entries: 10000
    min_ttl: 0
    max_ttl: 604800
    negative_ttl: 3600

  # NAT64 / DNS64 (RFC 6147). Per-listener toggle above selects which
  # listeners synthesise.
  dns64:
    prefix: "64:ff9b::/96"               # RFC 6052 WKP default
    exclusions:
      - corp.local

  # TLS for DoT/DoH. cert_source = file | acme.
  tls:
    cert_source: file
    cert_path: /etc/dnsd/cert.pem
    key_path: /etc/dnsd/key.pem

  rate_limit:
    per_client_qps: 100
    per_client_burst: 200
```

## Operator CLI

`dnsd query` is a subcommand of the daemon binary — it connects to
the control socket. Same `--control-socket` flag as the daemon.

```bash
dnsd query stats           # counter snapshot
dnsd query forwarders      # configured forwarder table
dnsd query cache --op stats
dnsd query cache --op flush
dnsd query reload          # SIGHUP-equivalent
```

## DNSSEC: zero-config

`recursion.dnssec: validate` is all that's needed. On first start,
the daemon materialises the current IANA root KSKs (KSK-2017 and
KSK-2024 as of this writing) from a build-time-embedded constant
into `<data_dir>/anchor/active.key`. The RFC 5011 refresh loop runs
hourly to pick up rotations:

* New KSKs observed in a validated `. DNSKEY` response start a
  30-day hold-down before being promoted to active.
* KSKs that come back with the REVOKE bit set are removed
  immediately.
* State persists in `<data_dir>/anchor/active.key.state` (JSON).

Operators who want to override with a manually-managed anchor file
can set `recursion.trust_anchor: /path/to/root.key`. Manual file
takes precedence over the self-managed directory.

The validator handles multi-zone-shortcut referrals (root NSes that
are also auth for `arpa.` and below sometimes collapse zone cuts
into a single referral or AA=1 NXDOMAIN response) by bootstrapping
intermediate zones on demand.

## DNS64 + RFC 8880

Per-listener opt-in. When a listener has `dns64: true`:

* AAAA queries that come back NODATA / NXDOMAIN re-fire as A,
  results synthesised under the configured `dns64.prefix`.
* `ip6.arpa` PTR queries that fall under the prefix are rewritten
  to `in-addr.arpa` before forwarding.
* `ipv4only.arpa` (RFC 8880) is answered locally — A returns
  192.0.0.170 + 192.0.0.171; AAAA on a DNS64 listener returns the
  synthesised pair, on a non-DNS64 listener returns NODATA. PTR
  queries for the matching reverse names return `ipv4only.arpa.`.

## RFCs implemented

Validation / chain: 4034, 4035, 5011, 5702, 6605, 6840, 6147,
7873 (cookies), 8198 (aggressive NSEC use), 8624 (algorithm
implementation requirements via hickory-proto's `dnssec-ring`).

Names / local answers: 6303, 7050 (obsoleted), 8375 (`home.arpa`),
8880 §7.2 (`ipv4only.arpa` local answer).

Transport: 1035, 7766 (TCP), 7858 (DoT), 8484 (DoH), 8482 (ANY/HINFO),
8767 (serve-stale knob).

## Source layout

```
src/
  config.rs              # YAML schema + load/validate
  handler.rs             # SharedHandler + ArcSwap reload glue
  control.rs             # Unix-socket protocol for `dnsd query`
  io/
    transport/{vcl,kernel}.rs   # backend-selected socket types
    udp.rs / tcp.rs / dot.rs / doh.rs   # listener loops
  recursor/
    mod.rs               # RecursorHandler + handle_bytes pipeline
    cache.rs             # response cache (moka-backed)
    forwarder.rs         # async UDP multiplexer + TCP fallback
    iterative.rs         # delegation walk + WalkChain construction
    dnssec.rs            # validator + chain bootstrap
    anchor.rs            # trust-anchor lifecycle (RFC 5011 + bootstrap)
    dns64.rs             # RFC 6147 synthesis
    ipv4only.rs          # RFC 8880 §7.2 local answer
    local_zones.rs       # RFC 6303 / 8375 NXDOMAIN synthesis
    rrl.rs               # response rate limiter
    cookies.rs           # EDNS0 cookies
    zeroxtwenty.rs       # 0x20 case randomisation
    normalize.rs         # response shape sanity checks
```

## Tests

```bash
cargo test --lib --no-default-features --features kernel-sockets
```

Runs the recursor unit tests on the kernel backend (works on
macOS without podman). Integration tests under `tests/integration`
target the VCL backend and require a Bookworm container or VM.

## License

See `LICENSE`.
