//! `dns-01` ACME challenge — stub.
//!
//! Design: `instant-acme` drives the order/authorization/challenge
//! state machine. A provider trait abstracts "write a TXT record at
//! _acme-challenge.<domain>":
//!
//!   trait Dns01Writer {
//!       async fn write(&self, fqdn: &str, value: &str) -> Result<()>;
//!       async fn clear(&self, fqdn: &str) -> Result<()>;
//!   }
//!
//! Initial providers we want: RFC 2136 dynamic update (with TSIG),
//! Cloudflare API, Route53. Each gets its own impl in this module.
//! The provider is selected via `dns.tls.acme.dns01.provider` and
//! the provider-specific fields on `DnsAcmeDns01`.
//!
//! Not wired up in v1 — operators who need dns-01 today should use
//! an external ACME client (certbot, lego) to mint certs and point
//! dnsd at the PEM pair via `dns.tls.cert_source: file`.
