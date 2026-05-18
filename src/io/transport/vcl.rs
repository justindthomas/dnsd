//! VCL transport backend.
//!
//! Re-exports `vcl-rs` types under the backend-neutral names that
//! the rest of dnsd uses. Keeps the production path zero-overhead
//! — these are pure type aliases, no wrapper allocation, no extra
//! virtual dispatch.

pub use vcl_rs::VclDgramSocket as DnsDgramSocket;
pub use vcl_rs::VclListener as DnsTcpListener;
pub use vcl_rs::VclStream as DnsTcpStream;

/// A bare connected client stream — the primitive the `via: tor` /
/// DoT forwarder path layers SOCKS5 + TLS onto. On VCL this is a
/// `VclStream` (a VPP session); it implements tokio's
/// `AsyncRead + AsyncWrite + Unpin + Send`, which is exactly the
/// bound `socks::connect` and `dot_client::query_dot` require.
pub use vcl_rs::VclStream as ClientStream;

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

/// Open a bare TCP stream to `peer` and hand it back unframed — no
/// DNS framing, no TLS, just a connected session. The forwarder's
/// DoT / `via: tor` path layers SOCKS5 + rustls onto the returned
/// stream itself; `query_tcp_dns_async` (connect + frame + query in
/// one call) can't be split that way, hence this primitive.
///
/// On VCL this is `VclStream::connect_async` — a non-blocking VPP
/// session with the reactor driving connect/read/write completion.
/// Must run on a registered VCL worker thread (the caller dispatches
/// onto a vcl-io worker, same as `query_one_tcp`).
pub async fn connect_stream(
    peer: std::net::SocketAddr,
    source: Option<std::net::IpAddr>,
    ctx: ReactorCtx,
    timeout: std::time::Duration,
) -> anyhow::Result<ClientStream> {
    let source = source.map(|ip| std::net::SocketAddr::new(ip, 0));
    vcl_rs::VclStream::connect_async(peer, source, ctx, timeout)
        .await
        .map_err(Into::into)
}
