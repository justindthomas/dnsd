//! `tls-alpn-01` (RFC 8737) ACME challenge — stub.
//!
//! Design: a `rustls_acme::caches::DirCache`-backed challenge cache
//! under `/persistent/data/dnsd/acme/` gives persistence across
//! reloads/restarts. `rustls_acme::AcmeConfig::new(domains).cache(...)`
//! + the resulting `Incoming` wrapper demuxes `acme-tls/1` ALPN at
//! the TLS ClientHello so port 443 can simultaneously serve DoH and
//! ACME challenges on one listener.
//!
//! The missing piece for VCL: rustls-acme expects its own listener
//! type (an async stream of accepted TCP connections). We need a
//! thin adapter that wraps `VclListener::accept()` as the source.
//! That's ~50 LOC and lands in the follow-up that makes this module
//! operational.
