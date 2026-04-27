//! Load the `dns:` block from router.yaml.
//!
//! Mirrors the subset of fields we care about from impd's `DnsConfig`.
//! Unknown keys are ignored so forward-compatibility with new impd
//! additions is automatic — we only need to add fields here when we
//! start honouring them.

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

/// Outer shape of router.yaml — we only care about `dns:`.
#[derive(Debug, Clone, Deserialize)]
struct RouterYaml {
    #[serde(default)]
    dns: Option<DnsConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
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
}

fn default_port() -> u16 { 53 }

#[derive(Debug, Clone, Deserialize)]
pub struct Forwarder {
    pub domain: String,
    #[serde(default)]
    pub servers: Vec<IpAddr>,
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
            enabled: false,
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
    pub negative_ttl: Option<u32>,
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
}
