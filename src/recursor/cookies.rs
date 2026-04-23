//! DNS Cookies (RFC 7873) — primitives, integration TBD.
//!
//! **Status**: scaffold only. The integration into `UpstreamClient`
//! needs a parse-modify-encode pass on every outbound query (to
//! add/update the EDNS COOKIE option), BADCOOKIE extended-RCODE
//! retry handling, and per-upstream server-cookie state. That's a
//! real chunk of work that competes with the byte-level 0x20 path
//! we already use; landing it cleanly wants a single-path refactor
//! of the upstream flow (hickory-proto Message end-to-end).
//!
//! The primitives below are enough to drop into that refactor when
//! it happens. This module intentionally doesn't do any I/O.
//!
//! Cookie layout on the wire (EDNS option code 10):
//!
//! ```text
//!   Client-Cookie (8 B) [ Server-Cookie (8–32 B) ]
//! ```
//!
//! Client cookie is typically a keyed HMAC of (client-IP, server-IP,
//! secret) so we can forget+rediscover across restarts. Server
//! cookie is opaque to us — whatever the server hands back, we send
//! on the next query to prove freshness. On BADCOOKIE we retry once
//! with the new server cookie from the response's OPT.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use rand::RngCore;

/// EDNS option code for COOKIE (RFC 7873 §9).
pub const OPT_COOKIE: u16 = 10;

/// Fixed client-cookie length per RFC 7873.
pub const CLIENT_COOKIE_LEN: usize = 8;

/// A per-process client cookie + per-upstream server cookie cache.
/// Cheap to keep around unconditionally; the wire integration decides
/// whether to actually emit the option.
pub struct CookieState {
    client_cookie: [u8; CLIENT_COOKIE_LEN],
    server_cookies: Mutex<HashMap<IpAddr, Vec<u8>>>,
}

impl CookieState {
    pub fn new() -> Self {
        let mut c = [0u8; CLIENT_COOKIE_LEN];
        rand::thread_rng().fill_bytes(&mut c);
        Self {
            client_cookie: c,
            server_cookies: Mutex::new(HashMap::new()),
        }
    }

    pub fn client_cookie(&self) -> [u8; CLIENT_COOKIE_LEN] {
        self.client_cookie
    }

    /// Returns the server cookie we last saw from `server`, if any.
    pub fn server_cookie_for(&self, server: IpAddr) -> Option<Vec<u8>> {
        self.server_cookies.lock().unwrap().get(&server).cloned()
    }

    /// Remember a new server cookie received from `server`.
    pub fn remember(&self, server: IpAddr, server_cookie: Vec<u8>) {
        self.server_cookies
            .lock()
            .unwrap()
            .insert(server, server_cookie);
    }

    /// Clear state for `server` — e.g. after a cookie auth failure.
    pub fn forget(&self, server: IpAddr) {
        self.server_cookies.lock().unwrap().remove(&server);
    }
}

impl Default for CookieState {
    fn default() -> Self {
        Self::new()
    }
}

/// Compose the raw COOKIE option payload that goes into an EDNS OPT
/// record. `server_cookie` is empty for the initial probe.
pub fn build_option(client_cookie: &[u8; CLIENT_COOKIE_LEN], server_cookie: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(CLIENT_COOKIE_LEN + server_cookie.len());
    v.extend_from_slice(client_cookie);
    v.extend_from_slice(server_cookie);
    v
}

/// Parse a received COOKIE payload from an OPT RR. Returns the
/// server-side portion (empty slice on a naked client-only response).
pub fn parse_option_value(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < CLIENT_COOKIE_LEN {
        return None;
    }
    Some(&payload[CLIENT_COOKIE_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_cookie_is_stable_per_state() {
        let s = CookieState::new();
        let a = s.client_cookie();
        let b = s.client_cookie();
        assert_eq!(a, b, "client cookie must be stable within a process");
    }

    #[test]
    fn server_cookie_roundtrip() {
        let s = CookieState::new();
        let srv: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(s.server_cookie_for(srv).is_none());
        s.remember(srv, vec![1, 2, 3, 4]);
        assert_eq!(s.server_cookie_for(srv), Some(vec![1, 2, 3, 4]));
        s.forget(srv);
        assert!(s.server_cookie_for(srv).is_none());
    }

    #[test]
    fn build_and_parse_round_trip() {
        let client = [0xaa; CLIENT_COOKIE_LEN];
        let server = b"\x01\x02\x03\x04\x05\x06\x07\x08";
        let opt = build_option(&client, server);
        assert_eq!(&opt[..CLIENT_COOKIE_LEN], &client);
        assert_eq!(parse_option_value(&opt), Some(&server[..]));
    }

    #[test]
    fn short_payload_rejected() {
        assert!(parse_option_value(&[0; 4]).is_none());
    }
}
