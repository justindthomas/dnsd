//! UDP/53 listener over `vcl-rs`.
//!
//! One `VclDgramSocket` per listener. Every recv → ACL → dispatch →
//! send is handled on the caller's Tokio task; heavy lifting happens
//! inside the handler (which is expected to spawn its own tasks for
//! upstream queries). Datagrams up to 4096 B are accepted — enough
//! for an EDNS0-advertised MTU that fits in our normal MTU, larger
//! responses drop TC=1 and the client retries over TCP.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use vcl_rs::{VclDgramSocket, VclReactor};

use crate::acl::ClientAcl;
use crate::config::Listener;
use crate::handler::SharedHandler;
use crate::metrics::Metrics;

const UDP_BUF_SIZE: usize = 4096;

pub struct UdpListener;

impl UdpListener {
    /// Bind the listener via VCL and spawn the serve loop on the
    /// current Tokio runtime. Returns once the socket is bound; the
    /// loop runs until `reactor` / `handler` are dropped.
    pub async fn spawn(
        listener_cfg: Listener,
        reactor: VclReactor,
        handler: SharedHandler,
        metrics: Arc<Metrics>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let bind = std::net::SocketAddr::new(listener_cfg.address, listener_cfg.port);
        let sock = VclDgramSocket::bind(bind, reactor)
            .with_context(|| format!("UDP bind {bind}"))?;
        let acl = ClientAcl::new(listener_cfg.allow_from.clone());
        let name = listener_cfg.name.clone();
        tracing::info!(listener = %name, addr = %bind, "UDP listener up");

        let handle = tokio::spawn(async move {
            serve_loop(sock, acl, handler, metrics, name).await;
        });
        Ok(handle)
    }
}

async fn serve_loop(
    sock: VclDgramSocket,
    acl: ClientAcl,
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    name: String,
) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; UDP_BUF_SIZE];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(listener = %name, "recv_from: {e}");
                // Transient VCL errors shouldn't kill the loop.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            }
        };

        if !acl.allows(peer.ip()) {
            metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(listener = %name, %peer, "ACL denied");
            continue;
        }

        metrics.queries_udp.fetch_add(1, Ordering::Relaxed);

        // Offload to a spawned task so slow handlers don't back up
        // the receive loop. `sock` is cheap to clone through Arc.
        let handler = handler.clone();
        let sock = sock.clone();
        let name = name.clone();
        let query = buf[..n].to_vec();
        tokio::spawn(async move {
            if let Some(response) = handler.handle_bytes(&query, peer.ip()).await {
                if let Err(e) = sock.send_to(&response, peer).await {
                    tracing::debug!(listener = %name, %peer, "send_to: {e}");
                }
            }
        });
    }
}
