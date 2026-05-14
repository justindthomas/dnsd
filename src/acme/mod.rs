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
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;

use crate::config::DnsConfig;

const DEFAULT_ACME_CACHE: &str = "/persistent/data/dnsd/acme";

/// TLS materials used by DoT/DoH. Holds the ServerConfig the
/// listeners accept into; when ACME is active, the driver task
/// handle is kept so the caller can abort on shutdown. `info`
/// summarises the cert source for the control socket — operators
/// query it via `imp-dnsd-query tls`.
pub struct TlsSetup {
    pub server_config: Arc<ServerConfig>,
    #[allow(dead_code)]
    pub acme_driver: Option<tokio::task::JoinHandle<()>>,
    pub info: crate::control::TlsInfo,
}

/// Inspect a rustls leaf certificate (DER) and fill in the
/// human-readable parts of `TlsInfo`. Best-effort: if parsing fails
/// the fields stay `None` and the operator at least gets
/// `cert_source` + `alpn`.
fn fill_cert_fields(leaf_der: &[u8], info: &mut crate::control::TlsInfo) {
    use x509_parser::prelude::*;
    let Ok((_, cert)) = X509Certificate::from_der(leaf_der) else {
        return;
    };
    info.subject = Some(cert.subject().to_string());
    info.issuer = Some(cert.issuer().to_string());
    // ASN1Time::to_rfc2822 is fine for display; the unix-timestamp
    // form is parseable everywhere.
    let unix = cert.validity().not_after.timestamp();
    info.not_after = chrono_rfc3339(unix);
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for entry in &san.value.general_names {
            match entry {
                GeneralName::DNSName(s) => info.sans.push(format!("DNS:{s}")),
                GeneralName::IPAddress(b) => {
                    let s = match b.len() {
                        4 => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
                        16 => {
                            // Render as RFC 5952 / Ipv6Addr's Display.
                            let mut segs = [0u16; 8];
                            for (i, c) in b.chunks_exact(2).enumerate() {
                                segs[i] = u16::from_be_bytes([c[0], c[1]]);
                            }
                            std::net::Ipv6Addr::from(segs).to_string()
                        }
                        _ => continue,
                    };
                    info.sans.push(format!("IP:{s}"));
                }
                _ => {}
            }
        }
    }
}

/// Tiny RFC 3339 formatter for a unix timestamp. dnsd already pulls
/// in `time` transitively through hickory; using it directly would
/// add another feature-gated dep. Build the string by hand from
/// civil components — fine for "is this cert about to expire?"
/// operator output.
fn chrono_rfc3339(unix: i64) -> Option<String> {
    // Days since the unix epoch + seconds-of-day. The civil-date
    // breakdown uses the standard 1970-01-01 anchor and the
    // proleptic Gregorian calendar (RFC 3339 §1).
    if unix < 0 {
        return None;
    }
    let secs_per_day: i64 = 86_400;
    let mut days = unix / secs_per_day;
    let secs_of_day = (unix % secs_per_day) as u32;
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;

    // Convert days-since-epoch to (Y, M, D). Algorithm from
    // Howard Hinnant's date library (public-domain) — same one the
    // chrono crate uses.
    days += 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z"
    ))
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
            let (server_config, leaf_der) = load_file_pair(cert_path, key_path)?;
            let mut info = crate::control::TlsInfo {
                present: true,
                cert_source: "file".into(),
                alpn: server_config
                    .alpn_protocols
                    .iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect(),
                ..Default::default()
            };
            fill_cert_fields(&leaf_der, &mut info);
            Ok(Some(TlsSetup {
                server_config,
                acme_driver: None,
                info,
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

    // ACME info reflects the *configured* state, not a fetched cert
    // — rustls-acme owns the cert lifecycle and there's no
    // synchronous API to crack open the resolver. Once a cert
    // arrives, the driver task logs it and operators can also see
    // it on the wire via `openssl s_client -alpn h2 -connect ...`.
    let info = crate::control::TlsInfo {
        present: true,
        cert_source: "acme".into(),
        sans: acme
            .domains
            .iter()
            .map(|d| format!("DNS:{d}"))
            .collect(),
        alpn: server_config
            .alpn_protocols
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect(),
        ..Default::default()
    };

    Ok(Some(TlsSetup {
        server_config,
        acme_driver: Some(driver),
        info,
    }))
}

/// Build the `ServerConfig` plus return the leaf cert DER so the
/// caller can decode Subject / Issuer / NotAfter / SAN for the
/// `tls` control command.
fn load_file_pair(
    cert_path: &str,
    key_path: &str,
) -> Result<(Arc<ServerConfig>, Vec<u8>)> {
    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("reading cert {cert_path}"))?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("reading key {key_path}"))?;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parsing cert PEM {cert_path}"))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {cert_path}"));
    }
    let leaf_der = certs[0].as_ref().to_vec();

    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_slice(&key_pem)
        .with_context(|| format!("parsing key PEM {key_path}"))?;

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
    Ok((Arc::new(cfg), leaf_der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_formatter_renders_known_epoch() {
        assert_eq!(
            chrono_rfc3339(0),
            Some("1970-01-01T00:00:00Z".to_string())
        );
        // 2026-05-14T00:00:00Z
        assert_eq!(
            chrono_rfc3339(1_778_716_800),
            Some("2026-05-14T00:00:00Z".to_string())
        );
        // 2024-02-29T12:34:56Z — leap-year boundary
        assert_eq!(
            chrono_rfc3339(1_709_210_096),
            Some("2024-02-29T12:34:56Z".to_string())
        );
    }

    #[test]
    fn fill_cert_fields_extracts_subject_san_and_not_after() {
        // Generate a self-signed cert with two DNS SANs.
        let mut params = rcgen::CertificateParams::new(vec![
            "dns.example.com".to_string(),
            "dot.example.com".to_string(),
        ])
        .expect("CertificateParams::new");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "dns.example.com");
        let key = rcgen::KeyPair::generate().expect("KeyPair::generate");
        let cert = params.self_signed(&key).expect("self_signed");
        let leaf_der = cert.der().as_ref().to_vec();

        let mut info = crate::control::TlsInfo::default();
        fill_cert_fields(&leaf_der, &mut info);

        let subj = info.subject.expect("subject");
        assert!(subj.contains("dns.example.com"), "subject was {subj:?}");
        assert!(info.issuer.is_some());
        let nb = info.not_after.expect("not_after");
        // Self-signed via rcgen defaults to a future date; we
        // don't pin the year, just that it parses back to RFC3339.
        assert!(nb.ends_with('Z') && nb.contains('T'), "not_after {nb:?}");
        assert!(
            info.sans.iter().any(|s| s == "DNS:dns.example.com"),
            "missing DNS:dns.example.com in {:?}",
            info.sans
        );
        assert!(info.sans.iter().any(|s| s == "DNS:dot.example.com"));
    }
}
