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
