//! dnsd — DNS caching recursor + forwarder.
//!
//! Runs as a supervised child of `impd` inside the dataplane netns.
//! Every socket goes through VPP's session layer via `vcl-rs` — no
//! linux_cp TAP, no punt path, no kernel sockets.
//!
//! Public surface is small by design; most types live in sub-modules
//! and are wired together by `main.rs`.

pub mod acl;
pub mod acme;
pub mod config;
pub mod control;
pub mod handler;
pub mod io;
pub mod metrics;
pub mod recursor;

pub use config::{DnsConfig, Listener};
pub use handler::{DnsHandler, RefusedHandler, SharedHandler};
