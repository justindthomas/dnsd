//! TLS configuration sourced from either an on-disk PEM pair or
//! ACME. v1 implements the file-based path end-to-end; the ACME
//! pluggings (`tls_alpn_01.rs` + `dns_01.rs`) stub out what
//! `rustls-acme` + `instant-acme` wiring will look like so the main
//! path already knows the shape when ACME lands.

pub mod tls_alpn_01;
pub mod dns_01;

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

use crate::config::DnsConfig;

/// Build the `rustls::ServerConfig` used by DoT and DoH listeners.
/// Today this only supports `cert_source: file`; `acme` logs a
/// "not yet implemented" warning and returns None so listeners
/// asking for DoT/DoH cleanly skip bringup instead of panicking.
pub fn server_config_from_dns(cfg: &DnsConfig) -> Result<Option<Arc<ServerConfig>>> {
    let Some(tls) = &cfg.tls else {
        return Ok(None);
    };
    match tls.cert_source.as_str() {
        "file" => {
            let cert_path = tls.cert_path.as_deref().ok_or_else(|| {
                anyhow!("dns.tls.cert_source=file requires dns.tls.cert_path")
            })?;
            let key_path = tls.key_path.as_deref().ok_or_else(|| {
                anyhow!("dns.tls.cert_source=file requires dns.tls.key_path")
            })?;
            Ok(Some(load_file_pair(cert_path, key_path)?))
        }
        "acme" => {
            // ACME with tls-alpn-01 is the plan; the rustls-acme
            // Incoming wrapper sniffs the ClientHello ALPN and
            // intercepts `acme-tls/1` handshakes at the TLS layer.
            // Wiring that with a VclStream needs one more indirection
            // we haven't built yet (rustls-acme takes its own listener
            // type; we'd want a thin adapter). File path is the
            // operator-side workaround until then.
            tracing::warn!(
                "dns.tls.cert_source=acme is not yet implemented; DoT/DoH listeners won't start. \
                 Use cert_source: file with an externally-managed cert pair as a stopgap."
            );
            Ok(None)
        }
        other => Err(anyhow!("unknown dns.tls.cert_source: {other:?}")),
    }
}

fn load_file_pair(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("reading cert {cert_path}"))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("reading key {key_path}"))?;

    let mut cert_reader: &[u8] = &cert_pem;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parsing cert PEM {cert_path}"))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {cert_path}"));
    }

    let mut key_reader: &[u8] = &key_pem;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .with_context(|| format!("parsing key PEM {key_path}"))?
        .ok_or_else(|| anyhow!("no private key found in {key_path}"))?;

    // Ensure ring is installed as the default crypto provider.
    // rustls 0.23 requires an explicit choice; do it once, idempotent.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building ServerConfig")?;

    // ALPN: advertise 'dot' for DoT and 'h2' + 'http/1.1' for DoH.
    // Both listeners share the same ServerConfig today (the ALPN
    // protocol the client selected tells us which path to serve).
    cfg.alpn_protocols = vec![
        b"dot".to_vec(),
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
    ];
    Ok(Arc::new(cfg))
}
