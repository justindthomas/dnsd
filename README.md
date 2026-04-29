# dnsd

Recursive DNS resolver + forwarder + DNS64 + DNSSEC validator.

## Two transport backends

`dnsd` ships with a compile-time choice of network transport. Pick
exactly one cargo feature.

### `vcl` (default) — VPP/VCL

```bash
cargo build --release
```

Listeners and upstream queries flow through VPP's session layer via
`vcl-rs` (`libvppcom`). Used in router deployments where VPP owns
the dataplane addresses (e.g. a LAN-side address that lives only
inside VPP, never on the kernel networking stack). Requires VPP
running and `vcl.conf` reachable at startup.

### `kernel-sockets` — plain Linux/macOS sockets

```bash
cargo build --release --no-default-features --features kernel-sockets
```

Listeners and upstream queries use `tokio::net::*` directly on the
kernel TCP/IP stack. No `libvppcom` link, no VPP needed. Useful for:

- Running `dnsd` as a recursive resolver in a non-router context
  (a regular Linux box, a container, a FreeBSD jail without VPP).
- Local development and `cargo test --lib` on macOS without podman.

The two backends are mutually exclusive — the cargo feature guard in
`src/io/transport/mod.rs` enforces this at compile time.

## Minimal kernel-sockets config

```yaml
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
    # Optional. When unset, kernel routing picks the source
    # automatically. Set explicitly to pin egress to a specific
    # GUA when the host has multiple v6 addresses.
    # source_v6: "2001:db8::1"
```

Run:

```bash
./target/release/dnsd \
  --config /etc/dnsd.yaml \
  --data-dir /var/lib/dnsd \
  --control-socket /run/dnsd.sock
```

Then:

```bash
dig @127.0.0.1 example.com
```

## DNSSEC validation

Add to the `recursion:` block:

```yaml
  recursion:
    enabled: true
    dnssec: validate
    trust_anchor: /var/lib/dnsd/root.key
```

Stage the IANA root anchor:

```bash
# Debian/Ubuntu
apt install dns-root-data
install -m 644 /usr/share/dns/root.key /var/lib/dnsd/root.key
```

`SIGHUP` reloads config in place — no restart needed.

## Differences vs the VCL backend

- Source-address discovery via VPP's binary API is VCL-only; the
  kernel backend lets the FIB pick the source unless an explicit
  `source_v4` / `source_v6` is set.
- The LAN-listener-on-VPP-only-address pattern doesn't apply —
  the listener address must be assigned to a kernel interface
  in kernel mode.
- Otherwise: identical recursor, cache, forwarder, DNS64, DNSSEC,
  and ACL semantics.
