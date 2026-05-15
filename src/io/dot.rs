//! DNS-over-TLS (RFC 7858) listener.
//!
//! `DnsTcpListener` (transport-backend-selected) accepts TCP/853;
//! each connection is wrapped in `tokio-rustls` using the operator's
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
//!
//! `acl` / `ctx` are `ArcSwap`-backed for hot-config reload (see
//! tcp.rs and udp.rs for the pattern).

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use crate::handler::{AclSwap, CtxSwap, SharedHandler};
use crate::io::transport::{DnsTcpListener, ReactorCtx};
use crate::metrics::Metrics;

const MAX_TCP_MESSAGE: usize = 65535;

pub struct DotListener;

impl DotListener {
    pub async fn spawn(
        bind: SocketAddr,
        reactor: ReactorCtx,
        handler: SharedHandler,
        metrics: Arc<Metrics>,
        tls_config: Arc<rustls::ServerConfig>,
        acl: AclSwap,
        ctx: CtxSwap,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let listener = DnsTcpListener::bind(bind, reactor.clone())
            .with_context(|| format!("DoT bind {bind}"))?;
        let acceptor = TlsAcceptor::from(tls_config);
        {
            let snap = ctx.load();
            tracing::info!(listener = %snap.name, addr = %bind, dns64 = snap.dns64, "DoT listener up");
        }

        let handle = tokio::spawn(async move {
            accept_loop(listener, acceptor, acl, handler, metrics, ctx).await;
        });
        Ok(handle)
    }
}

async fn accept_loop(
    listener: DnsTcpListener,
    acceptor: TlsAcceptor,
    acl: AclSwap,
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    ctx: CtxSwap,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(listener = %ctx.load().name, "DoT accept: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        if !acl.load().allows(peer.ip()) {
            metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
            // debug, not warn — operators don't need to see every
            // rejected scan packet at info, but blind-debugging a
            // TLS-handshake-cut-short symptom is much easier when
            // the dropped peer IP is one grep away.
            tracing::debug!(%peer, listener = %ctx.load().name, "DoT: ACL denied pre-handshake");
            drop(stream);
            continue;
        }
        // Pre-ready short-circuit — see doh.rs for the rationale.
        if !handler.is_ready() {
            drop(stream);
            continue;
        }

        let handler = handler.clone();
        let metrics = metrics.clone();
        let acl = acl.clone();
        let ctx = ctx.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) =
                        serve_tls(tls_stream, peer, handler, metrics, acl, ctx).await
                    {
                        tracing::debug!(%peer, "DoT conn: {e}");
                    }
                }
                Err(e) => {
                    tracing::debug!(%peer, "TLS handshake: {e}");
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
    acl: AclSwap,
    ctx: CtxSwap,
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

        if !acl.load().allows(peer.ip()) {
            metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        metrics.queries_dot.fetch_add(1, Ordering::Relaxed);

        let ctx_snap = ctx.load_full();
        if let Some(response) = handler.handle_bytes(&query, peer.ip(), &ctx_snap).await {
            // RFC 1035 §4.2.2 length prefix is u16; defensive guard
            // against the silent `as u16` truncation. dnsd's handler
            // pipeline never produces an oversize response in
            // practice — bounded by EDNS payload size on success and
            // tiny on error — but the cast would otherwise wrap.
            if response.len() > MAX_TCP_MESSAGE {
                tracing::warn!(
                    %peer,
                    response_len = response.len(),
                    "dropping oversize DoT response (>65535 bytes)"
                );
                return Ok(());
            }
            let mut framed = Vec::with_capacity(2 + response.len());
            framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
            framed.extend_from_slice(&response);
            stream.write_all(&framed).await?;
            stream.flush().await?;
        }
    }
}
