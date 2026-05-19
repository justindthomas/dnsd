//! Load the `dns:` block from router.yaml.
//!
//! Mirrors the subset of fields we care about from impd's `DnsConfig`.
//! Unknown keys are ignored so forward-compatibility with new impd
//! additions is automatic — we only need to add fields here when we
//! start honouring them.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

/// Outer shape of router.yaml — we only care about `dns:`.
#[derive(Debug, Clone, Deserialize)]
struct RouterYaml {
    #[serde(default)]
    dns: Option<DnsConfig>,
    /// Top-level VRF declarations. dnsd doesn't program FIB
    /// entries (it speaks DNS, not routing), but per-VRF
    /// instances bind sockets in the matching VPP session-layer
    /// namespace via VCL_CONFIG. The vrfs: block is here so the
    /// per-VRF loader can validate that `--vrf <name>` references
    /// a declared VRF.
    #[serde(default)]
    vrfs: Vec<VrfYaml>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VrfYaml {
    pub name: String,
    #[serde(default)]
    pub table_id_v4: u32,
    #[serde(default)]
    pub table_id_v6: u32,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    pub enabled: bool,
    #[serde(default)]
    pub listeners: Vec<Listener>,
    #[serde(default)]
    pub forwarders: Vec<Forwarder>,
    #[serde(default)]
    pub recursion: Option<Recursion>,
    #[serde(default)]
    pub cache: Option<Cache>,
    #[serde(default)]
    pub dns64: Option<Dns64>,
    #[serde(default)]
    pub tls: Option<Tls>,
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
    #[serde(default)]
    pub sfw: Option<SfwHint>,
    /// Number of TCP-listener worker threads (DoT / DoH / TCP/53).
    /// Each worker registers as its own VCL app-worker context and
    /// owns a dedicated `VclReactor`, so VPP's per-VPP-worker
    /// session distribution lands on a co-located app-worker. UDP
    /// stays on the main thread regardless — its session pool is
    /// flat. Unset → 1 (current single-thread behavior). Set higher
    /// to spread connection-oriented load across CPUs; values above
    /// `available_parallelism()` waste VPP-side fifo segments without
    /// adding parallelism.
    #[serde(default)]
    pub tcp_workers: Option<u32>,
    /// tord's SOCKS5 endpoint, used by `via: tor` forwarder servers.
    /// A `dns:`-level field (not under the router-wide `tor:` block)
    /// because dnsd parses only `dns:` and needs its own pointer at
    /// tord. Default `127.0.0.1:9050` — the co-located cut-through
    /// case where dnsd reaches tord over a VPP loopback session.
    #[serde(default = "default_tor_socks")]
    pub tor_socks: SocketAddr,
    /// Per-VRF DNS instances. Each entry has its own listeners /
    /// forwarders / cache / etc. plus a `name` matching a
    /// top-level `vrfs[].name`. impd's supervisor spawns one
    /// dnsd@<name> child per entry. Default-VRF DNS lives in the
    /// flat top-level fields above.
    #[serde(default)]
    pub vrfs: Vec<DnsVrfConfig>,
}

/// Default SOCKS5 endpoint for `via: tor` forwarders — tord's
/// loopback listener.
fn default_tor_socks() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9050))
}

impl Default for DnsConfig {
    fn default() -> Self {
        // Hand-written because `SocketAddr` has no `Default` impl, so
        // the derive can't cover `tor_socks`. Every other field is
        // its type's natural default.
        Self {
            enabled: false,
            listeners: Vec::new(),
            forwarders: Vec::new(),
            recursion: None,
            cache: None,
            dns64: None,
            tls: None,
            rate_limit: None,
            sfw: None,
            tcp_workers: None,
            tor_socks: default_tor_socks(),
            vrfs: Vec::new(),
        }
    }
}

/// One per-VRF DNS instance. Same shape as `DnsConfig` minus
/// nested `vrfs`, plus a required `name`.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsVrfConfig {
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listeners: Vec<Listener>,
    #[serde(default)]
    pub forwarders: Vec<Forwarder>,
    #[serde(default)]
    pub recursion: Option<Recursion>,
    #[serde(default)]
    pub cache: Option<Cache>,
    #[serde(default)]
    pub dns64: Option<Dns64>,
    #[serde(default)]
    pub tls: Option<Tls>,
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
    #[serde(default)]
    pub sfw: Option<SfwHint>,
    #[serde(default)]
    pub tcp_workers: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Listener {
    pub name: String,
    pub address: IpAddr,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub allow_from: Vec<IpNet>,
    #[serde(default)]
    pub dns64: bool,
    /// Maximum concurrent in-flight UDP queries on this listener.
    /// New queries above this cap are answered REFUSED immediately
    /// without spawning a walk task. Defends against task pile-up
    /// during upstream blackouts (every cache miss hangs ~5s, the
    /// single tokio thread otherwise fills with timed-out tasks).
    /// Unset → 1024.
    #[serde(default)]
    pub max_inflight: Option<u32>,
    /// DoH bearer token. When set, this listener serves DoH only at
    /// the path `/dns-query/<auth_token>`; a request to bare
    /// `/dns-query` (or with the wrong token) gets 404. Closes the
    /// open-resolver gap on internet-facing listeners — the WAN
    /// listeners have `allow_from: ::/0`, so without this any host
    /// can use the resolver. Ignored by non-DoH protocols.
    #[serde(default)]
    pub auth_token: Option<String>,
}

fn default_port() -> u16 { 53 }

pub const DEFAULT_MAX_INFLIGHT: u32 = 1024;

/// Upstream transport for a forwarder server.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Classic DNS over UDP, with TC→TCP fallback. The default.
    #[default]
    Udp,
    /// DNS over TCP only.
    Tcp,
    /// DNS over TLS, RFC 7858.
    Dot,
}

/// How a forwarder server is reached.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Via {
    /// Straight out the upstream path. The default.
    #[default]
    Direct,
    /// Through tord's SOCKS5 endpoint — anonymised over Tor.
    Tor,
}

/// A forwarder server in normalised form — see
/// `Forwarder::resolved_servers`.
#[derive(Debug, Clone)]
pub struct ForwarderServer {
    pub address: IpAddr,
    pub transport: Transport,
    /// TLS server name to verify; required when `transport` is `Dot`.
    pub tls_name: Option<String>,
    pub via: Via,
}

/// On-disk forwarder server: either a bare IP string (back-compat —
/// direct UDP) or a full mapping.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ServerSpec {
    Bare(IpAddr),
    Full(ServerSpecFull),
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerSpecFull {
    pub address: IpAddr,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub tls_name: Option<String>,
    #[serde(default)]
    pub via: Via,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Forwarder {
    pub domain: String,
    #[serde(default)]
    pub servers: Vec<ServerSpec>,
}

impl Forwarder {
    /// Normalise the on-disk server list into `ForwarderServer`s and
    /// validate it. A bare IP becomes a direct-UDP server (unchanged
    /// behaviour).
    ///
    /// Wired into the query path (phase 4): `udp/direct`,
    /// `dot/direct`, `dot/tor`. Combinations not yet implemented are
    /// rejected here, so a config can never promise a property dnsd
    /// does not deliver — see DESIGN-tor-forwarder.md §10.4.
    ///
    /// Fail-closed is *structural*: a forwarder may not mix `via: tor`
    /// and `via: direct` servers, so no query-path code can ever fall
    /// from a tor server to a direct sibling. `via: tor` additionally
    /// requires `transport: dot` — plain TCP would expose the queries
    /// to the Tor exit node.
    pub fn resolved_servers(&self) -> Result<Vec<ForwarderServer>> {
        let mut out = Vec::with_capacity(self.servers.len());
        for spec in &self.servers {
            let srv = match spec {
                ServerSpec::Bare(ip) => ForwarderServer {
                    address: *ip,
                    transport: Transport::Udp,
                    tls_name: None,
                    via: Via::Direct,
                },
                ServerSpec::Full(f) => ForwarderServer {
                    address: f.address,
                    transport: f.transport,
                    tls_name: f.tls_name.clone(),
                    via: f.via,
                },
            };
            if srv.transport == Transport::Dot && srv.tls_name.is_none() {
                anyhow::bail!(
                    "forwarder {}: server {} sets transport: dot but no tls_name",
                    self.domain,
                    srv.address,
                );
            }
            // Plain TCP is not yet wired into the upstream query path
            // (the forwarder path is UDP / DoT only). Reject loudly
            // rather than silently doing UDP.
            if srv.transport == Transport::Tcp {
                anyhow::bail!(
                    "forwarder {}: server {}: transport: tcp is not yet wired \
                     (see DESIGN-tor-forwarder.md)",
                    self.domain,
                    srv.address,
                );
            }
            // `via: tor` requires DoT. Plain DNS over a Tor circuit
            // would let the exit node read every query — defeating
            // the entire point. UDP-over-Tor is impossible anyway
            // (Tor is TCP-only); spell both out.
            if srv.via == Via::Tor && srv.transport != Transport::Dot {
                anyhow::bail!(
                    "forwarder {}: server {}: via: tor requires transport: dot \
                     (plain {} would expose queries to the Tor exit; \
                     see DESIGN-tor-forwarder.md)",
                    self.domain,
                    srv.address,
                    transport_name(srv.transport),
                );
            }
            out.push(srv);
        }
        // No-mix rule: a forwarder is either all-tor or all-direct.
        // This is what makes fail-closed structural — with no mixed
        // forwarder there is no code path that can fall from a tor
        // server to a direct sibling and leak. Enforced here so a
        // single mistyped `via: direct` line can't quietly create a
        // de-anonymisation hole.
        let any_tor = out.iter().any(|s| s.via == Via::Tor);
        let any_direct = out.iter().any(|s| s.via == Via::Direct);
        if any_tor && any_direct {
            anyhow::bail!(
                "forwarder {}: mixes via: tor and via: direct servers — \
                 a forwarder must be all-tor or all-direct so a tor query \
                 can never fall back to a leaking direct sibling \
                 (see DESIGN-tor-forwarder.md §10.4)",
                self.domain,
            );
        }
        Ok(out)
    }
}

fn transport_name(t: Transport) -> &'static str {
    match t {
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
        Transport::Dot => "dot",
    }
}

/// Operator-facing DNSSEC mode. Maps 1:1 onto
/// `recursor::dnssec::DnssecPolicy`.
///
/// `passthrough` (default): leave the upstream's AD bit alone.
/// Right when the operator trusts the configured forwarder to
/// validate on their behalf.
///
/// `strip`: clear AD unconditionally, regardless of upstream. Use
/// when the forwarder is NOT trusted for validation and clients
/// should never see AD=1 for data dnsd didn't check itself.
///
/// `validate`: chain-validate every iterative response against the
/// configured trust anchor; Secure → AD=1, Bogus → SERVFAIL with
/// EDE 6. Forwarder path still runs PassThrough-ish but logs a
/// warning at startup that forwarded responses aren't revalidated.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnssecMode {
    #[default]
    PassThrough,
    Strip,
    Validate,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Recursion {
    pub enabled: bool,
    /// DNSSEC policy. Accepts the string `passthrough` / `strip` /
    /// `validate`. For backward-compat with pre-v1 configs, the
    /// boolean `dnssec_validate: true` still promotes to Validate
    /// via `finalize()` below.
    pub dnssec: DnssecMode,
    /// Legacy boolean knob kept for existing router.yaml files.
    /// `dnssec_validate: true` is equivalent to `dnssec: validate`.
    /// When set, it overrides `dnssec` only if `dnssec` is the
    /// default (PassThrough); otherwise the explicit `dnssec`
    /// value wins.
    #[serde(default)]
    pub dnssec_validate: bool,
    pub trust_anchor: Option<String>,
    pub serve_stale_seconds: Option<u32>,
    pub upstream_timeout_ms: Option<u32>,
    pub max_cname_depth: Option<u32>,
    /// Whether the iterative recursor may contact IPv6 upstream
    /// servers (root hints + glue AAAAs). Defaults to true. Set
    /// false in environments where the dataplane has no IPv6 route
    /// — the v6 bind/send fails cost time and VCL sessions per
    /// query. Has no effect on downstream listeners.
    pub ipv6_upstream: bool,
    /// Explicit source IP for outbound IPv6 upstream queries.
    ///
    /// IPv4 source selection is automatic: dnsd binds to the first
    /// listener address that matches the family and lets VPP/NAT
    /// handle translation to the egress interface. That works because
    /// NAT44 is in the picture and the LAN-side bind avoids ephemeral
    /// port conflicts with the NAT pool.
    ///
    /// IPv6 has no NAT, so the bound source has to be a globally-
    /// routable address VPP knows about. dnsd has no way to ask VPP
    /// "what would your FIB pick as the source for outbound v6?" via
    /// the VCL API (`vppcom_session_attr GET_LCL_ADDR` only echoes
    /// the bound address, not the FIB-derived one), so this needs to
    /// be set explicitly when the operator wants v6 upstream queries.
    /// Typically the wan interface's global v6, e.g. `2602:f90e::100`.
    ///
    /// When unset and no v6 listener provides a source, the iterative
    /// recursor logs a startup warning and v6 NS queries time out.
    pub source_v6: Option<std::net::Ipv6Addr>,
}

impl Recursion {
    /// Resolve the effective DNSSEC mode, accounting for the legacy
    /// `dnssec_validate` boolean.
    pub fn effective_dnssec(&self) -> DnssecMode {
        // Explicit `dnssec: strip|validate` wins over the legacy
        // boolean. The only case where legacy matters is when
        // `dnssec` is left at its default (PassThrough) but the
        // operator wrote `dnssec_validate: true` in a pre-v1 config.
        if self.dnssec == DnssecMode::PassThrough && self.dnssec_validate {
            DnssecMode::Validate
        } else {
            self.dnssec
        }
    }
}

impl Default for Recursion {
    fn default() -> Self {
        Self {
            // True so that `dns.recursion: { dnssec: validate }` (or
            // any partial recursion block that omits `enabled`) does
            // NOT silently disable iterative resolution — the
            // operator clearly wants the recursor to keep running.
            // Same default as when `dns.recursion` is absent
            // entirely. To explicitly turn off the recursor, set
            // `enabled: false`.
            enabled: true,
            dnssec: DnssecMode::PassThrough,
            dnssec_validate: false,
            trust_anchor: None,
            serve_stale_seconds: None,
            upstream_timeout_ms: None,
            max_cname_depth: None,
            ipv6_upstream: true,
            source_v6: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Cache {
    pub max_entries: Option<u32>,
    pub min_ttl: Option<u32>,
    pub max_ttl: Option<u32>,
    /// Fallback negative-cache TTL — applied when an upstream
    /// NXDOMAIN/NoData response doesn't carry a SOA the resolver can
    /// derive a MINIMUM field from.
    pub negative_ttl: Option<u32>,
    /// Hard cap on cached negative-response lifetime. Distinct from
    /// `max_ttl` (the positive-cache cap) because the operational
    /// cost of a stale negative — a client repeatedly being told
    /// "this host does not exist" — is much higher than a stale
    /// positive. Default is 600s; raise only if you have a specific
    /// reason. Mirrors Unbound's `cache-max-negative-ttl` /
    /// BIND9's `max-ncache-ttl` / PowerDNS Recursor's
    /// `max-negative-ttl`, all of which default to roughly an hour.
    pub max_negative_ttl: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Dns64 {
    pub prefix: Option<String>,
    pub exclusions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Tls {
    pub cert_source: String,
    pub acme: Option<Acme>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Acme {
    pub directory: String,
    pub email: String,
    pub domains: Vec<String>,
    pub challenge: String,
    pub dns01: Option<AcmeDns01>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AcmeDns01 {
    pub provider: String,
    pub endpoint: Option<String>,
    pub tsig_key_name: Option<String>,
    pub tsig_key_secret: Option<String>,
    pub api_token: Option<String>,
    pub zone: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct RateLimit {
    pub per_client_qps: Option<u32>,
    pub per_client_burst: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct SfwHint {
    pub auto: bool,
}

impl DnsConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let doc: RouterYaml = serde_yaml::from_str(&raw)
            .with_context(|| format!("parsing {}", path.display()))?;
        Ok(doc.dns.unwrap_or_default())
    }

    /// Per-VRF loader: pick `dns.vrfs[name]`, return it as a flat
    /// `DnsConfig`. Errors when `name` doesn't match a `dns.vrfs[]`
    /// entry or the corresponding top-level `vrfs[]` declaration is
    /// missing.
    pub fn load_for_vrf(path: &Path, vrf_name: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let doc: RouterYaml = serde_yaml::from_str(&raw)
            .with_context(|| format!("parsing {}", path.display()))?;
        // Validate that the VRF is declared at the router level.
        if !doc.vrfs.iter().any(|v| v.name == vrf_name) {
            return Err(anyhow::anyhow!(
                "--vrf {}: VRF not declared in router.yaml's vrfs: block",
                vrf_name
            ));
        }
        let dns = doc.dns.unwrap_or_default();
        // tord is a router-wide service; per-VRF DNS instances inherit
        // the top-level `dns.tor_socks` pointer rather than declaring
        // their own (per-VRF SOCKS endpoints are the deferred routable
        // case — see DESIGN-tor-forwarder.md §7).
        let tor_socks = dns.tor_socks;
        let v = dns
            .vrfs
            .into_iter()
            .find(|v| v.name == vrf_name)
            .ok_or_else(|| anyhow::anyhow!(
                "--vrf {}: no matching dns.vrfs[] block in config",
                vrf_name
            ))?;
        Ok(DnsConfig {
            enabled: v.enabled,
            listeners: v.listeners,
            forwarders: v.forwarders,
            recursion: v.recursion,
            cache: v.cache,
            dns64: v.dns64,
            tls: v.tls,
            rate_limit: v.rate_limit,
            sfw: v.sfw,
            tcp_workers: v.tcp_workers,
            tor_socks,
            vrfs: Vec::new(),
        })
    }
}

impl Listener {
    pub fn has_protocol(&self, proto: &str) -> bool {
        self.protocols.iter().any(|p| p.eq_ignore_ascii_case(proto))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vyos_shape() {
        let raw = r#"
dns:
  enabled: true
  listeners:
    - name: v4-lan
      address: 192.168.37.1
      port: 53
      interface: loop0
      protocols: [udp, tcp]
      allow_from: [10.0.0.0/8, 192.168.0.0/16]
    - name: v6-lan
      address: "2602:f90e::1"
      protocols: [udp, tcp, dot, doh]
      allow_from: ["::/0"]
      dns64: true
  forwarders:
    - domain: jdt.io
      servers: [10.42.128.19]
    - domain: emeraldbroadband.net
      servers: ["10.10.90.35", "2604:2940:f1b0::1:53"]
  recursion:
    enabled: true
    dnssec_validate: true
  dns64:
    prefix: "64:ff9b::/96"
"#;
        let doc: RouterYaml = serde_yaml::from_str(raw).unwrap();
        let dns = doc.dns.unwrap();
        assert!(dns.enabled);
        assert_eq!(dns.listeners.len(), 2);
        assert_eq!(dns.listeners[0].port, 53);
        assert!(dns.listeners[1].has_protocol("dot"));
        assert!(dns.listeners[1].dns64);
        assert_eq!(dns.forwarders.len(), 2);
        assert_eq!(dns.forwarders[1].servers.len(), 2);
        let rec = dns.recursion.unwrap();
        assert!(rec.enabled && rec.dnssec_validate);
    }

    #[test]
    fn forwarder_bare_and_full_specs() {
        let raw = r#"
dns:
  forwarders:
    - domain: a.example
      servers: [10.0.0.1, 10.0.0.2]
    - domain: b.example
      servers:
        - { address: "10.0.0.3", transport: udp, via: direct }
"#;
        let dns = serde_yaml::from_str::<RouterYaml>(raw).unwrap().dns.unwrap();
        // Bare IPs normalise to direct UDP.
        let a = dns.forwarders[0].resolved_servers().unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].transport, Transport::Udp);
        assert_eq!(a[0].via, Via::Direct);
        // An explicit udp/direct full spec also resolves.
        let b = dns.forwarders[1].resolved_servers().unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].address.to_string(), "10.0.0.3");
    }

    #[test]
    fn forwarder_rejects_dot_without_tls_name() {
        // transport: dot without tls_name.
        let dns = serde_yaml::from_str::<RouterYaml>(
            "dns:\n  forwarders:\n    - domain: x\n      servers:\n        - { address: \"9.9.9.9\", transport: dot }\n",
        )
        .unwrap()
        .dns
        .unwrap();
        let err = dns.forwarders[0].resolved_servers().unwrap_err();
        assert!(
            err.to_string().contains("tls_name"),
            "got: {err}"
        );
    }

    #[test]
    fn forwarder_rejects_via_tor_without_dot() {
        // via: tor with the default (udp) transport — must be DoT.
        let dns = serde_yaml::from_str::<RouterYaml>(
            "dns:\n  forwarders:\n    - domain: x\n      servers:\n        - { address: \"9.9.9.9\", via: tor }\n",
        )
        .unwrap()
        .dns
        .unwrap();
        let err = dns.forwarders[0].resolved_servers().unwrap_err();
        assert!(
            err.to_string().contains("via: tor requires transport: dot"),
            "got: {err}"
        );

        // via: tor + explicit tcp — also rejected (TCP is rejected
        // outright before the tor check, but either way it errors).
        let dns = serde_yaml::from_str::<RouterYaml>(
            "dns:\n  forwarders:\n    - domain: x\n      servers:\n        - { address: \"9.9.9.9\", transport: tcp, via: tor }\n",
        )
        .unwrap()
        .dns
        .unwrap();
        assert!(dns.forwarders[0].resolved_servers().is_err());
    }

    #[test]
    fn forwarder_rejects_mixed_tor_and_direct() {
        // A forwarder may not mix via: tor and via: direct servers —
        // the no-mix rule is what makes fail-closed structural.
        let dns = serde_yaml::from_str::<RouterYaml>(
            "dns:\n  forwarders:\n    - domain: x\n      servers:\n        \
             - { address: \"9.9.9.9\", transport: dot, tls_name: dns.quad9.net, via: tor }\n        \
             - { address: \"1.1.1.1\", transport: dot, tls_name: cloudflare-dns.com, via: direct }\n",
        )
        .unwrap()
        .dns
        .unwrap();
        let err = dns.forwarders[0].resolved_servers().unwrap_err();
        assert!(
            err.to_string().contains("mixes via: tor and via: direct"),
            "got: {err}"
        );
    }

    #[test]
    fn forwarder_accepts_dot_direct_and_dot_tor() {
        // dot/direct.
        let dns = serde_yaml::from_str::<RouterYaml>(
            "dns:\n  forwarders:\n    - domain: x\n      servers:\n        \
             - { address: \"9.9.9.9\", transport: dot, tls_name: dns.quad9.net }\n",
        )
        .unwrap()
        .dns
        .unwrap();
        let srv = dns.forwarders[0].resolved_servers().unwrap();
        assert_eq!(srv.len(), 1);
        assert_eq!(srv[0].transport, Transport::Dot);
        assert_eq!(srv[0].via, Via::Direct);
        assert_eq!(srv[0].tls_name.as_deref(), Some("dns.quad9.net"));

        // dot/tor — an all-tor forwarder.
        let dns = serde_yaml::from_str::<RouterYaml>(
            "dns:\n  forwarders:\n    - domain: .\n      servers:\n        \
             - { address: \"9.9.9.9\", transport: dot, tls_name: dns.quad9.net, via: tor }\n",
        )
        .unwrap()
        .dns
        .unwrap();
        let srv = dns.forwarders[0].resolved_servers().unwrap();
        assert_eq!(srv.len(), 1);
        assert_eq!(srv[0].transport, Transport::Dot);
        assert_eq!(srv[0].via, Via::Tor);
    }

    #[test]
    fn tor_socks_default_and_override() {
        // Default when unset.
        let dns = serde_yaml::from_str::<RouterYaml>("dns:\n  enabled: true\n")
            .unwrap()
            .dns
            .unwrap();
        assert_eq!(
            dns.tor_socks,
            "127.0.0.1:9050".parse::<SocketAddr>().unwrap()
        );
        // Operator override round-trips.
        let dns = serde_yaml::from_str::<RouterYaml>(
            "dns:\n  enabled: true\n  tor_socks: \"10.0.0.1:9150\"\n",
        )
        .unwrap()
        .dns
        .unwrap();
        assert_eq!(
            dns.tor_socks,
            "10.0.0.1:9150".parse::<SocketAddr>().unwrap()
        );
    }

    fn vrf_yaml() -> &'static str {
        r#"
vrfs:
  - name: cust-a
    table_id_v4: 100
    table_id_v6: 200
dns:
  enabled: false
  vrfs:
    - name: cust-a
      enabled: true
      listeners:
        - name: cust-a-lan
          address: 10.42.0.1
          protocols: [udp, tcp]
      forwarders:
        - domain: cust-a.local
          servers: [10.42.0.53]
"#
    }

    fn write_yaml(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn per_vrf_loader_picks_named_slice() {
        let f = write_yaml(vrf_yaml());
        let cfg = DnsConfig::load_for_vrf(f.path(), "cust-a").unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.listeners[0].name, "cust-a-lan");
        assert_eq!(cfg.forwarders.len(), 1);
        assert_eq!(cfg.forwarders[0].domain, "cust-a.local");
    }

    #[test]
    fn per_vrf_loader_rejects_unknown_vrf() {
        let f = write_yaml(vrf_yaml());
        let err = DnsConfig::load_for_vrf(f.path(), "cust-b").unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("cust-b"), "got {}", msg);
    }

    #[test]
    fn default_loader_ignores_per_vrf_config() {
        // The flat top-level `dns:` block is what `load()` returns;
        // any `dns.vrfs[]` entries are surfaced via vrfs but the
        // top-level identity doesn't inherit from them.
        let f = write_yaml(vrf_yaml());
        let cfg = DnsConfig::load(f.path()).unwrap();
        assert!(!cfg.enabled);
        assert!(cfg.listeners.is_empty());
        // The vrfs[] block is preserved on the parsed default-VRF
        // config so the supervisor can introspect it (though dnsd
        // itself ignores it once running).
        assert_eq!(cfg.vrfs.len(), 1);
        assert_eq!(cfg.vrfs[0].name, "cust-a");
    }
}
