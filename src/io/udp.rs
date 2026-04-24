//! UDP/53 listener over `vcl-rs`.
//!
//! One `VclDgramSocket` per listener. Every recv → ACL → dispatch →
//! send is handled on the caller's Tokio task; heavy lifting happens
//! inside the handler (which is expected to spawn its own tasks for
//! upstream queries). Datagrams up to 4096 B are accepted — enough
//! for an EDNS0-advertised MTU that fits in our normal MTU, larger
//! responses drop TC=1 and the client retries over TCP.
//!
//! `acl` and `ctx` are `ArcSwap`-backed so SIGHUP-triggered reload can
//! publish a fresh allow-list / dns64 toggle without rebinding the
//! socket — every recv loads the current snapshot.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use vcl_rs::{VclDgramSocket, VclReactor};

use crate::handler::{AclSwap, CtxSwap, SharedHandler};
use crate::metrics::Metrics;

const UDP_BUF_SIZE: usize = 4096;

pub struct UdpListener;

impl UdpListener {
    /// Bind the listener via VCL and spawn the serve loop on the
    /// current Tokio runtime. Returns once the socket is bound; the
    /// loop runs until `reactor` / `handler` are dropped.
    pub async fn spawn(
        bind: SocketAddr,
        reactor: VclReactor,
        handler: SharedHandler,
        metrics: Arc<Metrics>,
        acl: AclSwap,
        ctx: CtxSwap,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let sock = VclDgramSocket::bind(bind, reactor)
            .with_context(|| format!("UDP bind {bind}"))?;
        {
            let snap = ctx.load();
            tracing::info!(listener = %snap.name, addr = %bind, dns64 = snap.dns64, "UDP listener up");
        }

        let handle = tokio::spawn(async move {
            serve_loop(sock, acl, handler, metrics, ctx).await;
        });
        Ok(handle)
    }
}

async fn serve_loop(
    sock: VclDgramSocket,
    acl: AclSwap,
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    ctx: CtxSwap,
) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; UDP_BUF_SIZE];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(listener = %ctx.load().name, "recv_from: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            }
        };

        if !acl.load().allows(peer.ip()) {
            metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(listener = %ctx.load().name, %peer, "ACL denied");
            continue;
        }

        metrics.queries_udp.fetch_add(1, Ordering::Relaxed);

        let handler = handler.clone();
        let sock = sock.clone();
        // Snapshot ctx for the duration of this query. A concurrent
        // reload can update the swap mid-flight; the in-flight query
        // keeps the version it started with.
        let ctx_snap = ctx.load_full();
        let query = buf[..n].to_vec();
        tokio::spawn(async move {
            if let Some(response) = handler.handle_bytes(&query, peer.ip(), &ctx_snap).await {
                if let Err(e) = sock.send_to(&response, peer).await {
                    tracing::debug!(listener = %ctx_snap.name, %peer, "send_to: {e}");
                }
            }
        });
    }
}
