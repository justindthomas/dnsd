//! VCL transport backend.
//!
//! Re-exports `vcl-rs` types under the backend-neutral names that
//! the rest of dnsd uses. Keeps the production path zero-overhead
//! — these are pure type aliases, no wrapper allocation, no extra
//! virtual dispatch.

pub use vcl_rs::VclDgramSocket as DnsDgramSocket;
pub use vcl_rs::VclListener as DnsTcpListener;
pub use vcl_rs::VclStream as DnsTcpStream;

/// Per-process I/O context. On VCL this is the `VclReactor` that
/// drives the `vppcom_mq_epoll_fd` event loop; every bind/connect
/// needs a clone. The `kernel-sockets` backend defines this as `()`
/// so the same call signatures work on both backends without a
/// generic parameter at every site.
pub type ReactorCtx = vcl_rs::VclReactor;

/// Construct the per-process reactor. Backend-neutral wrapper so
/// `main.rs` doesn't need a `cfg` arm. On VCL, builds a fresh
/// `VclReactor` (which spawns the mq-eventfd epoll loop). On kernel,
/// returns `()`.
pub fn new_reactor() -> anyhow::Result<ReactorCtx> {
    vcl_rs::VclReactor::new().map_err(Into::into)
}

/// One-shot TCP DNS query (RFC 1035 §4.2.2 framing). Used by the
/// forwarder when UDP gets TC=1 or when we explicitly prefer TCP
/// for a particular upstream. Returns the raw response bytes (length
/// prefix stripped). On VCL this is `vcl_rs::query_tcp_dns_async`;
/// the `kernel-sockets` backend supplies its own equivalent built
/// on `tokio::net::TcpStream`.
pub async fn query_tcp_dns_async(
    peer: std::net::SocketAddr,
    source: Option<std::net::IpAddr>,
    query: &[u8],
    ctx: ReactorCtx,
    timeout: std::time::Duration,
) -> anyhow::Result<Vec<u8>> {
    vcl_rs::query_tcp_dns_async(peer, source, query, ctx, timeout)
        .await
        .map_err(Into::into)
}
