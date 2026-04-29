//! Kernel-sockets transport backend (stub).
//!
//! Phase 4 fills this in — newtype wrappers around
//! `tokio::net::{UdpSocket, TcpListener, TcpStream}` that expose
//! the same API surface as `vcl.rs` so I/O modules don't care
//! which backend they're talking to.
//!
//! Until then this file just declares the type names so
//! `mod.rs`'s re-export compiles. Building with
//! `--features kernel-sockets` is intentionally broken in phase 1;
//! the default `vcl` build is unaffected.

use std::marker::PhantomData;

/// Placeholder. Replaced in phase 4 with a `tokio::net::UdpSocket`
/// wrapper whose `bind`/`recv_from`/`send_to` mirror `VclDgramSocket`.
pub struct DnsDgramSocket(PhantomData<()>);

/// Placeholder. Replaced in phase 4 with a `tokio::net::TcpListener`
/// wrapper.
pub struct DnsTcpListener(PhantomData<()>);

/// Placeholder. Replaced in phase 4 with a `tokio::net::TcpStream`
/// wrapper that implements `AsyncRead + AsyncWrite` so
/// `tokio_rustls` can wrap it for DoT/DoH.
pub struct DnsTcpStream(PhantomData<()>);

/// Zero-sized — the kernel backend has no per-process reactor to
/// thread through. Code that takes `ReactorCtx` just gets `()`.
pub type ReactorCtx = ();
