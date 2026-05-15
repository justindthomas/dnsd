//! UDP/53 listener.
//!
//! One `DnsDgramSocket` (transport-backend-selected — VCL or kernel)
//! per listener. Every recv → ACL → dispatch → send is handled on
//! the caller's Tokio task; heavy lifting happens inside the handler
//! (which is expected to spawn its own tasks for upstream queries).
//! Datagrams up to 4096 B are accepted — enough for an EDNS0-
//! advertised MTU that fits in our normal MTU, larger responses
//! drop TC=1 and the client retries over TCP.
//!
//! `acl` and `ctx` are `ArcSwap`-backed so SIGHUP-triggered reload can
//! publish a fresh allow-list / dns64 toggle without rebinding the
//! socket — every recv loads the current snapshot.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;

use crate::handler::{build_refused, AclSwap, CtxSwap, SharedHandler};
use crate::io::transport::{DnsDgramSocket, ReactorCtx};
use crate::metrics::Metrics;

const UDP_BUF_SIZE: usize = 4096;

pub struct UdpListener;

impl UdpListener {
    /// Bind the listener via VCL and spawn the serve loop on the
    /// current Tokio runtime. Returns once the socket is bound; the
    /// loop runs until `reactor` / `handler` are dropped.
    ///
    /// `max_inflight` caps concurrent walk tasks spawned by this
    /// listener. When the cap is hit, incoming queries are answered
    /// REFUSED inline (counted in `metrics.udp_inflight_shed`) — the
    /// recv loop never blocks. Defends against the upstream-blackout
    /// failure mode where every cache miss hangs ~5s and the single
    /// tokio thread otherwise fills with timed-out tasks.
    pub async fn spawn(
        bind: SocketAddr,
        reactor: ReactorCtx,
        handler: SharedHandler,
        metrics: Arc<Metrics>,
        acl: AclSwap,
        ctx: CtxSwap,
        max_inflight: u32,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let sock = DnsDgramSocket::bind(bind, reactor)
            .with_context(|| format!("UDP bind {bind}"))?;
        {
            let snap = ctx.load();
            tracing::info!(
                listener = %snap.name,
                addr = %bind,
                dns64 = snap.dns64,
                max_inflight,
                "UDP listener up"
            );
        }

        let inflight = Arc::new(Semaphore::new(max_inflight as usize));
        let handle = tokio::spawn(async move {
            serve_loop(sock, acl, handler, metrics, ctx, inflight).await;
        });
        Ok(handle)
    }
}

async fn serve_loop(
    sock: DnsDgramSocket,
    acl: AclSwap,
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    ctx: CtxSwap,
    inflight: Arc<Semaphore>,
) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; UDP_BUF_SIZE];
    loop {
        // Drain-greedy pattern (same shape as the recursor's upstream
        // demux loop): pull every queued datagram in a tight sync
        // loop, then park on the reactor. Under load, `recv_from(...).await`
        // yields per datagram and the listener task only gets to
        // process ~20 queries per second across the runtime — the
        // VPP RX FIFO climbs into the kilobytes and clients time out
        // on queries that are sitting unread.
        //
        // Per-spawn cap of 256 datagrams keeps the listener from
        // starving the spawned handler tasks if a flood arrives.
        let mut drained = 0u32;
        loop {
            if drained >= 256 {
                tokio::task::yield_now().await;
                drained = 0;
            }
            let (n, peer) = match sock.try_recv_from(&mut buf) {
                Ok(Some(pair)) => pair,
                Ok(None) => break, // FIFO drained — go park
                Err(e) => {
                    tracing::error!(listener = %ctx.load().name, "try_recv_from: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    break;
                }
            };
            drained += 1;

            if !acl.load().allows(peer.ip()) {
                metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(listener = %ctx.load().name, %peer, "ACL denied");
                continue;
            }

            metrics.queries_udp.fetch_add(1, Ordering::Relaxed);

            // Try to reserve a walk slot. If the per-listener cap is
            // saturated (likely because upstream is wedged and earlier
            // walks are still timing out), reply REFUSED inline so the
            // client fails fast instead of contributing to the pile-up.
            let permit = match Arc::clone(&inflight).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    metrics.udp_inflight_shed.fetch_add(1, Ordering::Relaxed);
                    if let Some(refused) = build_refused(&buf[..n]) {
                        if let Err(e) = sock.send_to(&refused, peer).await {
                            tracing::debug!(listener = %ctx.load().name, %peer, "shed send_to: {e}");
                        }
                    }
                    continue;
                }
            };

            let handler = handler.clone();
            let sock = sock.clone();
            // Snapshot ctx for the duration of this query. A concurrent
            // reload can update the swap mid-flight; the in-flight query
            // keeps the version it started with.
            let ctx_snap = ctx.load_full();
            let query = buf[..n].to_vec();
            tokio::spawn(async move {
                let _permit = permit;
                if let Some(response) = handler.handle_bytes(&query, peer.ip(), &ctx_snap).await {
                    if let Err(e) = sock.send_to(&response, peer).await {
                        tracing::debug!(listener = %ctx_snap.name, %peer, "send_to: {e}");
                    }
                }
            });
        }
        if let Err(e) = sock.wait_readable().await {
            tracing::error!(listener = %ctx.load().name, "wait_readable: {e}");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
