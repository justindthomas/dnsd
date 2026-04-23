//! TLS configuration sourced from either an on-disk PEM pair or
//! ACME (tls-alpn-01 via `rustls-acme`).
//!
//! The ACME integration uses the **low-level** rustls-acme API so the
//! existing DoT/DoH accept loops (tokio-rustls over VclStream) stay
//! unchanged:
//!
//! 1. `AcmeConfig::new(domains).cache(DirCache).directory(url).state()`
//!    builds an `AcmeState`.
//! 2. `state.resolver()` returns an `Arc<ResolvesServerCertAcme>`
//!    that implements rustls 0.23's `ResolvesServerCert`.
//! 3. We plug that resolver into our own `rustls::ServerConfig` and
//!    add `acme-tls/1` to the ALPN list.
//! 4. The resolver serves the normal cert on `alpn=dot|h2|http/1.1`
//!    and the challenge cert on `alpn=acme-tls/1` — same handshake,
//!    different cert per ClientHello.
//! 5. A background tokio task drives the `AcmeState` stream so
//!    orders + renewals progress (the stream is where the ACME HTTP
//!    traffic happens internally).
//!
//! This means: no VclListener-level adapter is needed. Both DoH (on
//! 443) and DoT (on 853) naturally serve ACME challenges for their
//! own ports via the resolver — Let's Encrypt will reach whichever
//! listener is on port 443 (only DoH).

pub mod tls_alpn_01;
pub mod dns_01;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;

use crate::config::DnsConfig;

const DEFAULT_ACME_CACHE: &str = "/persistent/data/dnsd/acme";

/// TLS materials used by DoT/DoH. Holds the ServerConfig the
/// listeners accept into; when ACME is active, the driver task
/// handle is kept so the caller can abort on shutdown.
pub struct TlsSetup {
    pub server_config: Arc<ServerConfig>,
    #[allow(dead_code)]
    pub acme_driver: Option<tokio::task::JoinHandle<()>>,
}

/// Build the `TlsSetup` used by DoT and DoH listeners. Returns
/// `Ok(None)` when no `dns.tls:` block is configured (listeners skip
/// binding for DoT/DoH; operator intent is to stay TLS-less).
pub fn build_tls(cfg: &DnsConfig) -> Result<Option<TlsSetup>> {
    let Some(tls) = &cfg.tls else {
        return Ok(None);
    };
    match tls.cert_source.as_str() {
        "file" => {
            let cert_path = tls
                .cert_path
                .as_deref()
                .ok_or_else(|| anyhow!("dns.tls.cert_source=file requires dns.tls.cert_path"))?;
            let key_path = tls
                .key_path
                .as_deref()
                .ok_or_else(|| anyhow!("dns.tls.cert_source=file requires dns.tls.key_path"))?;
            let server_config = load_file_pair(cert_path, key_path)?;
            Ok(Some(TlsSetup {
                server_config,
                acme_driver: None,
            }))
        }
        "acme" => {
            let acme = tls
                .acme
                .as_ref()
                .ok_or_else(|| anyhow!("dns.tls.cert_source=acme requires dns.tls.acme"))?;
            if acme.domains.is_empty() {
                return Err(anyhow!("dns.tls.acme.domains must not be empty"));
            }
            match acme.challenge.as_str() {
                "tls-alpn-01" | "" => build_acme_tls_alpn_01(cfg, acme),
                "dns-01" => Err(anyhow!(
                    "dns.tls.acme.challenge=dns-01 is scaffolded but not \
                     yet wired. Use challenge=tls-alpn-01 or cert_source=file."
                )),
                other => Err(anyhow!("unknown ACME challenge {other:?}")),
            }
        }
        other => Err(anyhow!("unknown dns.tls.cert_source: {other:?}")),
    }
}

fn build_acme_tls_alpn_01(_cfg: &DnsConfig, acme: &crate::config::Acme) -> Result<Option<TlsSetup>> {
    // Ensure the rustls default provider is installed once for the
    // whole process (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cache_dir: PathBuf = PathBuf::from(DEFAULT_ACME_CACHE);
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating ACME cache dir {}", cache_dir.display()))?;

    let mut builder = AcmeConfig::new(acme.domains.iter().map(|s| s.as_str()))
        .contact_push(format!("mailto:{}", acme.email))
        .cache(DirCache::new(cache_dir));

    if !acme.directory.is_empty() {
        builder = builder.directory(&acme.directory);
    }

    let mut state = builder.state();
    let resolver = state.resolver();

    // Same ALPN set as the file-cert path, plus `acme-tls/1` so the
    // resolver can serve challenge certs when the ACME CA connects.
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    server_config.alpn_protocols = vec![
        b"dot".to_vec(),
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
        b"acme-tls/1".to_vec(),
    ];
    let server_config = Arc::new(server_config);

    // Drive the AcmeState stream in the background. Each yielded
    // event is a state transition (order started, challenge served,
    // certificate obtained, renewal due) — we log but don't act on
    // them; rustls-acme handles everything else internally.
    let driver = tokio::spawn(async move {
        while let Some(res) = state.next().await {
            match res {
                Ok(ok) => tracing::info!(?ok, "acme state"),
                Err(err) => tracing::warn!(%err, "acme error"),
            }
        }
        tracing::warn!("acme state stream ended");
    });

    Ok(Some(TlsSetup {
        server_config,
        acme_driver: Some(driver),
    }))
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
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building ServerConfig")?;

    cfg.alpn_protocols = vec![
        b"dot".to_vec(),
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
    ];
    Ok(Arc::new(cfg))
}

/// Legacy name kept for main.rs — returns the ServerConfig only
/// (callers that don't care about the ACME driver handle). Prefer
/// `build_tls` which returns both.
pub fn server_config_from_dns(cfg: &DnsConfig) -> Result<Option<Arc<ServerConfig>>> {
    Ok(build_tls(cfg)?.map(|s| s.server_config))
}
