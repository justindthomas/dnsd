//! tls-alpn-01 (RFC 8737) — landed via `rustls-acme` low-level API.
//!
//! See `acme/mod.rs`. The integration uses `AcmeConfig → AcmeState →
//! resolver` and lets the resolver serve both the production cert
//! and the tls-alpn-01 challenge cert from a single rustls
//! `ServerConfig`. No code here; this module is kept for symmetry
//! with `dns_01.rs` and as a pointer for the next maintainer.
