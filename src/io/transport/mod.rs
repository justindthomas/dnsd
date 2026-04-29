//! Transport-backend abstraction for listener + upstream sockets.
//!
//! Two implementations, mutually exclusive at compile time:
//!
//! * `vcl` (default): everything flows through VPP's session layer
//!   via `vcl-rs`. The production path on the router.
//! * `kernel-sockets`: everything flows through `tokio::net::*` on
//!   the kernel networking stack. Used for non-VPP deployments and
//!   for cross-platform development (no libvppcom link).
//!
//! Callers use `DnsDgramSocket` / `DnsTcpListener` / `DnsTcpStream`
//! / `ReactorCtx` from this module — never the underlying types
//! directly. Each backend re-exports the same public names so
//! downstream code is backend-agnostic.

#[cfg(all(feature = "vcl", feature = "kernel-sockets"))]
compile_error!("dnsd: features `vcl` and `kernel-sockets` are mutually exclusive");

#[cfg(not(any(feature = "vcl", feature = "kernel-sockets")))]
compile_error!("dnsd: enable exactly one of `vcl` or `kernel-sockets`");

#[cfg(feature = "vcl")]
mod vcl;
#[cfg(feature = "vcl")]
pub use self::vcl::*;

#[cfg(feature = "kernel-sockets")]
mod kernel;
#[cfg(feature = "kernel-sockets")]
pub use self::kernel::*;
