//! Transport layer — one sub-module per listener kind.
//!
//! Every transport runs on top of `vcl-rs` so all traffic flows
//! through VPP's session layer. Task #7 populates `udp` and `tcp`;
//! task #10 adds `dot` and `doh`.

pub mod udp;
pub mod tcp;
pub mod dot;
pub mod doh;
