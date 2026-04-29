//! Transport layer — one sub-module per listener kind.
//!
//! Sockets come from `transport`, which selects between the VCL
//! backend (default, all traffic through VPP's session layer) and
//! the kernel-sockets backend (`tokio::net::*` directly) at compile
//! time via cargo features.

pub mod transport;

pub mod udp;
pub mod tcp;
pub mod dot;
pub mod doh;
