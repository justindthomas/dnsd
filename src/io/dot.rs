//! DNS-over-TLS (RFC 7858) listener.
//!
//! `VclListener` accepts TCP/853 through VPP's session layer. Each
//! connection is wrapped in `tokio-rustls` using the operator's
//! certificate. Inside the TLS stream, the wire protocol is the
//! same 2-byte-length-prefixed DNS of TCP/53 (RFC 1035 §4.2.2) — we
//! reuse the same framing loop.
//!
//! ALPN: we advertise `dot` (IANA-registered for DoT) so a client
//! using `kdig +tls` or `unbound` with `forward-tls-upstream` ends up
//! on the DNS path rather than HTTP.
//!
//! Cert source today is a PEM file pair (operator puts cert + key
//! under a path referenced by `dns.tls.cert_path` / `key_path`).
//! ACME is a separate module (`acme/`) and bolts into the same
//! `Arc<ServerConfig>` once it's wired.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use vcl_rs::{VclListener, VclReactor};

use crate::acl::ClientAcl;
use crate::config::Listener;
use crate::handler::{ListenerContext, SharedHandler};
use crate::metrics::Metrics;

const MAX_TCP_MESSAGE: usize = 65535;

pub struct DotListener;

impl DotListener {
    pub async fn spawn(
        listener_cfg: Listener,
        reactor: VclReactor,
        handler: SharedHandler,
        metrics: Arc<Metrics>,
        tls_config: Arc<rustls::ServerConfig>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let bind = std::net::SocketAddr::new(listener_cfg.address, listener_cfg.port);
        let listener = VclListener::bind(bind, reactor.clone())
            .with_context(|| format!("DoT bind {bind}"))?;
        let acl = Arc::new(ClientAcl::new(listener_cfg.allow_from.clone()));
        let ctx = Arc::new(ListenerContext::new(&listener_cfg.name, listener_cfg.dns64));
        let acceptor = TlsAcceptor::from(tls_config);
        tracing::info!(listener = %listener_cfg.name, addr = %bind, dns64 = ctx.dns64, "DoT listener up");

        let handle = tokio::spawn(async move {
            accept_loop(listener, acceptor, acl, handler, metrics, ctx).await;
        });
        Ok(handle)
    }
}

async fn accept_loop(
    listener: VclListener,
    acceptor: TlsAcceptor,
    acl: Arc<ClientAcl>,
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    ctx: Arc<ListenerContext>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(listener = %ctx.name, "DoT accept: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        if !acl.allows(peer.ip()) {
            metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
            drop(stream);
            continue;
        }

        let handler = handler.clone();
        let metrics = metrics.clone();
        let ctx = ctx.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = serve_tls(tls_stream, peer, handler, metrics, &ctx).await {
                        tracing::debug!(listener = %ctx.name, %peer, "DoT conn: {e}");
                    }
                }
                Err(e) => {
                    tracing::debug!(listener = %ctx.name, %peer, "TLS handshake: {e}");
                }
            }
        });
    }
}

async fn serve_tls<S>(
    mut stream: tokio_rustls::server::TlsStream<S>,
    peer: std::net::SocketAddr,
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    ctx: &ListenerContext,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let mut lenbuf = [0u8; 2];
        match stream.read_exact(&mut lenbuf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u16::from_be_bytes(lenbuf) as usize;
        if len == 0 || len > MAX_TCP_MESSAGE {
            return Err(anyhow::anyhow!("invalid DoT DNS length {len}"));
        }
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await?;
        metrics.queries_dot.fetch_add(1, Ordering::Relaxed);

        if let Some(response) = handler.handle_bytes(&query, peer.ip(), ctx).await {
            let mut framed = Vec::with_capacity(2 + response.len());
            framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
            framed.extend_from_slice(&response);
            stream.write_all(&framed).await?;
            stream.flush().await?;
        }
    }
}
