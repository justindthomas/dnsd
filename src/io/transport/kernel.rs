//! Kernel-sockets transport backend.
//!
//! Newtype wrappers around `tokio::net::{UdpSocket, TcpListener,
//! TcpStream}` exposing the same call surface as the VCL backend so
//! `io/{udp,tcp,dot,doh}.rs` and `recursor/forwarder.rs` are
//! backend-agnostic. The kernel does source selection and FIB
//! routing for us — no VPP API or shared-library state to set up.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Zero-sized — the kernel backend has no per-process reactor to
/// thread through. Code that takes `ReactorCtx` just gets `()`.
pub type ReactorCtx = ();

/// Backend-neutral reactor construction. No-op for kernel sockets.
pub fn new_reactor() -> anyhow::Result<ReactorCtx> {
    Ok(())
}

// =============================================================================
// UDP
// =============================================================================

/// Datagram socket — kernel UDP. `bind` matches the VCL backend's
/// synchronous signature so the call site (`forwarder.rs`'s ephemeral
/// retry loop, `io/udp.rs`'s listener startup) doesn't change.
pub struct DnsDgramSocket {
    inner: tokio::net::UdpSocket,
}

impl DnsDgramSocket {
    pub fn bind(addr: SocketAddr, _ctx: ReactorCtx) -> anyhow::Result<Self> {
        let std_sock = std::net::UdpSocket::bind(addr)
            .with_context(|| format!("UDP bind {addr}"))?;
        std_sock.set_nonblocking(true)?;
        let inner = tokio::net::UdpSocket::from_std(std_sock)
            .with_context(|| "tokio UdpSocket::from_std")?;
        Ok(Self { inner })
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }

    pub async fn send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(buf, peer).await
    }

    /// Mirror of the VCL backend: non-blocking single-datagram read
    /// for the recursor's drain-greedy demux loop.
    pub fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        match self.inner.try_recv_from(buf) {
            Ok(pair) => Ok(Some(pair)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn wait_readable(&self) -> io::Result<()> {
        self.inner.readable().await
    }
}

// =============================================================================
// TCP listener
// =============================================================================

pub struct DnsTcpListener {
    inner: tokio::net::TcpListener,
}

impl DnsTcpListener {
    pub fn bind(addr: SocketAddr, _ctx: ReactorCtx) -> anyhow::Result<Self> {
        let std_listener = std::net::TcpListener::bind(addr)
            .with_context(|| format!("TCP bind {addr}"))?;
        std_listener.set_nonblocking(true)?;
        let inner = tokio::net::TcpListener::from_std(std_listener)
            .with_context(|| "tokio TcpListener::from_std")?;
        Ok(Self { inner })
    }

    pub async fn accept(&self) -> io::Result<(DnsTcpStream, SocketAddr)> {
        let (inner, peer) = self.inner.accept().await?;
        Ok((DnsTcpStream { inner }, peer))
    }
}

// =============================================================================
// TCP stream
// =============================================================================

/// Newtype around `tokio::net::TcpStream`. AsyncRead/AsyncWrite are
/// delegated via Pin projection so `tokio_rustls::TlsAcceptor` can
/// wrap us for DoT/DoH; io/tcp.rs uses the AsyncReadExt/AsyncWriteExt
/// extension methods through UFCS (so the call site is identical to
/// the VCL backend, which has an inherent `read_exact` that would
/// otherwise win method-resolution).
pub struct DnsTcpStream {
    inner: tokio::net::TcpStream,
}

impl AsyncRead for DnsTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DnsTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// =============================================================================
// Bare connected client stream (for the DoT / via: tor forwarder path)
// =============================================================================

/// A bare connected client stream — the primitive the `via: tor` /
/// DoT forwarder path layers SOCKS5 + TLS onto. On the kernel
/// backend this is a plain `tokio::net::TcpStream`, which already
/// implements `AsyncRead + AsyncWrite + Unpin + Send`.
pub type ClientStream = tokio::net::TcpStream;

/// Open a bare TCP stream to `peer` and hand it back unframed — no
/// DNS framing, no TLS, just a connected socket. The forwarder's
/// DoT / `via: tor` path layers SOCKS5 + rustls onto the returned
/// stream itself; `query_tcp_dns_async` (connect + frame + query in
/// one call) can't be split that way, hence this primitive.
pub async fn connect_stream(
    peer: SocketAddr,
    source: Option<IpAddr>,
    _ctx: ReactorCtx,
    timeout: Duration,
) -> anyhow::Result<ClientStream> {
    use tokio::time::timeout as tk_timeout;
    let connect_fut = async {
        if let Some(src_ip) = source {
            // Explicit source bind, mirroring `query_tcp_dns_async`.
            let socket = if src_ip.is_ipv4() {
                tokio::net::TcpSocket::new_v4()?
            } else {
                tokio::net::TcpSocket::new_v6()?
            };
            socket.bind(SocketAddr::new(src_ip, 0))?;
            Ok::<_, anyhow::Error>(socket.connect(peer).await?)
        } else {
            Ok(tokio::net::TcpStream::connect(peer).await?)
        }
    };
    tk_timeout(timeout, connect_fut)
        .await
        .map_err(|_| anyhow!("connect timeout to {peer}"))?
}

// =============================================================================
// One-shot TCP DNS query
// =============================================================================

/// One-shot TCP DNS query (RFC 1035 §4.2.2 length-prefixed framing).
/// Connect with optional source bind, write query, read response,
/// hang up. Used by the forwarder when UDP comes back TC=1.
pub async fn query_tcp_dns_async(
    peer: SocketAddr,
    source: Option<IpAddr>,
    query: &[u8],
    _ctx: ReactorCtx,
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    use tokio::time::timeout as tk_timeout;

    let connect_fut = async {
        if let Some(src_ip) = source {
            // Explicit source bind: use TcpSocket to bind before
            // connect. Kernel routing would normally pick the source
            // from the FIB, but operators may want to pin it (e.g.
            // a specific GUA when multiple are configured).
            let socket = if src_ip.is_ipv4() {
                tokio::net::TcpSocket::new_v4()?
            } else {
                tokio::net::TcpSocket::new_v6()?
            };
            socket.bind(SocketAddr::new(src_ip, 0))?;
            Ok::<_, anyhow::Error>(socket.connect(peer).await?)
        } else {
            Ok(tokio::net::TcpStream::connect(peer).await?)
        }
    };

    let mut stream = tk_timeout(timeout, connect_fut)
        .await
        .map_err(|_| anyhow!("connect timeout to {peer}"))??;

    // Write length-prefixed query.
    let len = u16::try_from(query.len())
        .map_err(|_| anyhow!("query too large: {} bytes", query.len()))?;
    tk_timeout(timeout, async {
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(query).await?;
        stream.flush().await?;
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| anyhow!("write timeout to {peer}"))??;

    // Read length-prefixed response.
    let mut len_buf = [0u8; 2];
    tk_timeout(timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| anyhow!("read timeout from {peer}"))??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    tk_timeout(timeout, stream.read_exact(&mut resp))
        .await
        .map_err(|_| anyhow!("read timeout from {peer}"))??;
    Ok(resp)
}
