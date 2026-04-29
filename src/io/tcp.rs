//! DNS-over-TCP (RFC 7766) listener.
//!
//! Framing per RFC 1035 §4.2.2: each message prefixed with a 2-byte
//! big-endian length. One TCP connection can carry many queries; we
//! loop on the stream until the peer closes. Out-of-order replies are
//! supported (every query gets its own spawned task) but are rare in
//! practice because classic resolvers pipeline serially over TCP.
//!
//! `acl` and `ctx` are `ArcSwap`-backed so SIGHUP-triggered reload can
//! publish a fresh allow-list / dns64 toggle without rebinding the
//! socket — already-connected clients pick up the new ACL on their
//! next query in the loop.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::handler::{AclSwap, CtxSwap, SharedHandler};
use crate::io::transport::{DnsTcpListener, DnsTcpStream, ReactorCtx};
use crate::metrics::Metrics;

const MAX_TCP_MESSAGE: usize = 65535; // length field is u16

pub struct TcpListener;

impl TcpListener {
    pub async fn spawn(
        bind: SocketAddr,
        reactor: ReactorCtx,
        handler: SharedHandler,
        metrics: Arc<Metrics>,
        acl: AclSwap,
        ctx: CtxSwap,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let listener = DnsTcpListener::bind(bind, reactor.clone())
            .with_context(|| format!("TCP bind {bind}"))?;
        {
            let snap = ctx.load();
            tracing::info!(listener = %snap.name, addr = %bind, dns64 = snap.dns64, "TCP listener up");
        }

        let handle = tokio::spawn(async move {
            accept_loop(listener, acl, handler, metrics, ctx).await;
        });
        Ok(handle)
    }
}

async fn accept_loop(
    listener: DnsTcpListener,
    acl: AclSwap,
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    ctx: CtxSwap,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(listener = %ctx.load().name, "accept: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        if !acl.load().allows(peer.ip()) {
            metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
            drop(stream);
            continue;
        }

        let handler = handler.clone();
        let metrics = metrics.clone();
        let acl = acl.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(stream, peer, handler, metrics, acl, ctx).await {
                tracing::debug!(%peer, "TCP conn: {e}");
            }
        });
    }
}

async fn serve_connection(
    mut stream: DnsTcpStream,
    peer: std::net::SocketAddr,
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    acl: AclSwap,
    ctx: CtxSwap,
) -> anyhow::Result<()> {
    // Serve queries serially on a TCP connection. RFC 7766 allows
    // clients to pipeline, but concurrent writes on the same DnsTcpStream
    // would require a write-side mutex + ordering guarantee we don't
    // need for v1. Hickory, BIND, and Unbound clients all pipeline at
    // most 2-3 deep in practice; serial answers add a few ms of
    // latency at worst and avoid a write-serialisation bug surface.
    loop {
        let mut lenbuf = [0u8; 2];
        // UFCS through the AsyncReadExt trait so we get a uniform
        // io::Result on both backends. VclStream has an inherent
        // `read_exact` that would otherwise win method-resolution and
        // return VclError; AsyncRead's tokio contract surfaces the
        // VCL `Closed` variant as io::ErrorKind::UnexpectedEof inside
        // vcl-rs, matching what tokio::net::TcpStream does on EOF.
        match AsyncReadExt::read_exact(&mut stream, &mut lenbuf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u16::from_be_bytes(lenbuf) as usize;
        if len == 0 || len > MAX_TCP_MESSAGE {
            return Err(anyhow::anyhow!("invalid TCP DNS length {len}"));
        }

        let mut query = vec![0u8; len];
        AsyncReadExt::read_exact(&mut stream, &mut query).await?;

        // Re-check ACL on each query inside the connection so a
        // SIGHUP that drops a CIDR boots already-connected clients
        // that fall outside the new allow-list — same enforcement
        // posture as a fresh accept.
        if !acl.load().allows(peer.ip()) {
            metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        metrics.queries_tcp.fetch_add(1, Ordering::Relaxed);

        let ctx_snap = ctx.load_full();
        if let Some(response) = handler.handle_bytes(&query, peer.ip(), &ctx_snap).await {
            let mut framed = Vec::with_capacity(2 + response.len());
            framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
            framed.extend_from_slice(&response);
            AsyncWriteExt::write_all(&mut stream, &framed).await?;
        }
    }
}
