//! DoT (DNS-over-TLS, RFC 7858) client — the TLS leg of the
//! `via: tor` forwarder path.
//!
//! `query_dot()` takes a stream already connected (and, for the
//! `via: tor` path, SOCKS-tunnelled through tord) to an upstream
//! resolver, runs the TLS handshake against `tls_name`, and exchanges
//! one length-prefixed DNS message — RFC 1035 §4.2.2 framing, the
//! same 2-byte prefix dnsd's plain-TCP upstream path uses.
//!
//! The resolver certificate is verified against the bundled Mozilla
//! root set (`webpki-roots`) — no OS trust store, so the trust
//! anchors are identical on every build target (Debian, FreeBSD, …).
//!
//! This module does the wire exchange only; TXID / 0x20 verification
//! stays with the caller. Wired into the forwarder by phase 4 (see
//! DESIGN-tor-forwarder.md).
#![allow(dead_code)] // phase 4 wires query_dot; the framing is tested now.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;

/// A DNS-over-TCP/DoT message is bounded by its 2-byte length prefix.
const MAX_MESSAGE: usize = 65535;

/// Process-wide DoT client config: bundled Mozilla roots, ALPN `dot`.
/// Built once — `ClientConfig` is designed to be constructed once and
/// shared behind an `Arc`.
fn client_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        // Match dnsd's existing rustls setup (acme/mod.rs): the ring
        // provider, installed idempotently so init order doesn't
        // matter — `install_default` errors harmlessly if the server
        // side already installed it.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"dot".to_vec()];
        Arc::new(cfg)
    })
    .clone()
}

/// Send one DNS query to an upstream resolver over DoT and return the
/// response wire bytes.
///
/// `stream` must already be connected to the resolver — directly, or
/// SOCKS-tunnelled via tord for `via: tor`. `tls_name` is the name
/// the resolver's certificate is verified against.
pub async fn query_dot<S>(
    stream: S,
    tls_name: &str,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    tokio::time::timeout(timeout, query_dot_inner(stream, tls_name, query))
        .await
        .map_err(|_| anyhow!("DoT query to {tls_name} timed out"))?
}

async fn query_dot_inner<S>(stream: S, tls_name: &str, query: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let server_name = ServerName::try_from(tls_name.to_owned())
        .with_context(|| format!("DoT: invalid TLS server name {tls_name:?}"))?;
    let mut tls = TlsConnector::from(client_config())
        .connect(server_name, stream)
        .await
        .with_context(|| format!("DoT: TLS handshake to {tls_name}"))?;
    write_message(&mut tls, query)
        .await
        .context("DoT: send query")?;
    read_message(&mut tls).await.context("DoT: read response")
}

/// Write a DNS message with the RFC 1035 §4.2.2 2-byte length prefix.
async fn write_message<W>(w: &mut W, msg: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if msg.len() > MAX_MESSAGE {
        bail!("DoT: query too large ({} bytes)", msg.len());
    }
    w.write_all(&(msg.len() as u16).to_be_bytes()).await?;
    w.write_all(msg).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed DNS message.
async fn read_message<R>(r: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    // A valid DNS message is at least a 12-byte header.
    if len < 12 {
        bail!("DoT: response too short ({len} bytes)");
    }
    let mut msg = vec![0u8; len];
    r.read_exact(&mut msg).await?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn framing_roundtrips() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let sent: Vec<u8> = (0..40u8).collect(); // 40-byte "message" (>= 12)
        let writer = {
            let sent = sent.clone();
            tokio::spawn(async move {
                write_message(&mut a, &sent).await.unwrap();
            })
        };
        let got = read_message(&mut b).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, sent);
    }

    #[tokio::test]
    async fn read_rejects_short_message() {
        // Length prefix says 5 — shorter than a DNS header.
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = a.write_all(&[0x00, 0x05, 1, 2, 3, 4, 5]).await;
        });
        assert!(read_message(&mut b).await.is_err());
    }

    #[tokio::test]
    async fn write_rejects_oversize_message() {
        let (mut a, _b) = tokio::io::duplex(64);
        let huge = vec![0u8; MAX_MESSAGE + 1];
        assert!(write_message(&mut a, &huge).await.is_err());
    }

    #[test]
    fn client_config_builds() {
        // Exercises the ring-provider install + webpki-roots load.
        let cfg = client_config();
        assert_eq!(cfg.alpn_protocols, vec![b"dot".to_vec()]);
    }
}
