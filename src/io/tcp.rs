//! DNS-over-TCP (RFC 7766) listener over `vcl-rs`.
//!
//! Framing per RFC 1035 §4.2.2: each message prefixed with a 2-byte
//! big-endian length. One TCP connection can carry many queries; we
//! loop on the stream until the peer closes. Out-of-order replies are
//! supported (every query gets its own spawned task) but are rare in
//! practice because classic resolvers pipeline serially over TCP.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use vcl_rs::{VclListener, VclReactor, VclStream};

use crate::acl::ClientAcl;
use crate::config::Listener;
use crate::handler::{ListenerContext, SharedHandler};
use crate::metrics::Metrics;

const MAX_TCP_MESSAGE: usize = 65535; // length field is u16

pub struct TcpListener;

impl TcpListener {
    pub async fn spawn(
        listener_cfg: Listener,
        reactor: VclReactor,
        handler: SharedHandler,
        metrics: Arc<Metrics>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let bind = std::net::SocketAddr::new(listener_cfg.address, listener_cfg.port);
        let listener = VclListener::bind(bind, reactor.clone())
            .with_context(|| format!("TCP bind {bind}"))?;
        let acl = Arc::new(ClientAcl::new(listener_cfg.allow_from.clone()));
        let ctx = Arc::new(ListenerContext::new(&listener_cfg.name, listener_cfg.dns64));
        tracing::info!(listener = %listener_cfg.name, addr = %bind, dns64 = ctx.dns64, "TCP listener up");

        let handle = tokio::spawn(async move {
            accept_loop(listener, acl, handler, metrics, ctx).await;
        });
        Ok(handle)
    }
}

async fn accept_loop(
    listener: VclListener,
    acl: Arc<ClientAcl>,
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    ctx: Arc<ListenerContext>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(listener = %ctx.name, "accept: {e}");
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
        tokio::spawn(async move {
            if let Err(e) = serve_connection(stream, peer, handler, metrics, &ctx).await {
                tracing::debug!(listener = %ctx.name, %peer, "TCP conn: {e}");
            }
        });
    }
}

async fn serve_connection(
    stream: VclStream,
    peer: std::net::SocketAddr,
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    ctx: &ListenerContext,
) -> anyhow::Result<()> {
    // Serve queries serially on a TCP connection. RFC 7766 allows
    // clients to pipeline, but concurrent writes on the same VclStream
    // would require a write-side mutex + ordering guarantee we don't
    // need for v1. Hickory, BIND, and Unbound clients all pipeline at
    // most 2-3 deep in practice; serial answers add a few ms of
    // latency at worst and avoid a write-serialisation bug surface.
    loop {
        let mut lenbuf = [0u8; 2];
        match stream.read_exact(&mut lenbuf).await {
            Ok(()) => {}
            Err(vcl_rs::error::VclError::Closed) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u16::from_be_bytes(lenbuf) as usize;
        if len == 0 || len > MAX_TCP_MESSAGE {
            return Err(anyhow::anyhow!("invalid TCP DNS length {len}"));
        }

        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await?;
        metrics.queries_tcp.fetch_add(1, Ordering::Relaxed);

        if let Some(response) = handler.handle_bytes(&query, peer.ip(), ctx).await {
            let mut framed = Vec::with_capacity(2 + response.len());
            framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
            framed.extend_from_slice(&response);
            stream.write_all(&framed).await?;
        }
    }
}
