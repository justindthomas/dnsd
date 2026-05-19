//! The `DnsHandler` trait is the boundary between the transport layer
//! (UDP / TCP / DoT / DoH) and the query-processing layer (cache,
//! forwarder, recursor, DNS64, DNSSEC).
//!
//! Transports parse a single datagram / TCP message and call
//! `handle_bytes`. The handler is expected to return a fully-formed
//! DNS wire response, or `None` if the query was malformed beyond
//! repair (in which case the transport silently drops — never reply
//! to a malformed packet, that's an amplification vector).
//!
//! Using raw bytes instead of `hickory_proto::op::Message` lets every
//! transport share the same dispatch without paying double encode/
//! decode; it also means DoH can pass POST bodies straight through.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::serialize::binary::BinDecodable;

use crate::acl::ClientAcl;

/// Hot-swappable per-listener ACL. Each listener task holds one of
/// these and `load()`s it on every recv/accept; reload publishes a
/// fresh `ClientAcl` here so a `dns.listeners[*].allow_from` change
/// takes effect on the next packet — no rebind, no lost TCP/TLS
/// connections.
pub type AclSwap = Arc<arc_swap::ArcSwap<ClientAcl>>;

/// Hot-swappable per-listener context (name, dns64 toggle). Same
/// pattern as `AclSwap` — listener tasks load a fresh snapshot per
/// query, so toggling `dns64: true|false` or renaming a listener
/// applies on the next query without rebinding.
pub type CtxSwap = Arc<arc_swap::ArcSwap<ListenerContext>>;

/// Per-listener policy carried alongside every query so the shared
/// handler can vary behaviour based on which listener accepted the
/// request. Adds (per-listener RRL thresholds, forwarder subset,
/// etc.) go here.
#[derive(Clone, Debug, Default)]
pub struct ListenerContext {
    pub name: String,
    pub dns64: bool,
    /// DoH bearer token for this listener. `Some` → the DoH handler
    /// requires the request path `/dns-query/<token>`; `None` → bare
    /// `/dns-query`. Carried in the hot-swappable context so a
    /// SIGHUP token change takes effect on the next request.
    pub doh_auth_token: Option<String>,
}

impl ListenerContext {
    pub fn new(
        name: impl Into<String>,
        dns64: bool,
        doh_auth_token: Option<String>,
    ) -> Self {
        Self { name: name.into(), dns64, doh_auth_token }
    }
}

#[async_trait]
pub trait DnsHandler: Send + Sync + 'static {
    /// Dispatch a single DNS query. `query` is the raw wire format
    /// (no transport framing). `peer` is the remote IP (the transport
    /// has already enforced the CIDR allow-list). `ctx` is the
    /// per-listener policy for this query.
    async fn handle_bytes(
        &self,
        query: &[u8],
        peer: IpAddr,
        ctx: &ListenerContext,
    ) -> Option<Vec<u8>>;

    /// Startup readiness probe. TCP-style listeners (TCP/DoT/DoH)
    /// MUST check this at accept time and close the connection
    /// immediately if it returns false, before any TLS handshake or
    /// HTTP parse. Without this gate, a busy upstream client (e.g.
    /// Firefox DoH) can fire many parallel connections during the
    /// pre-ready window; each accepted connection runs TLS handshake
    /// work (rustls + libvppcom MQ-drain per read) that monopolises
    /// the single-thread runtime, starving the recursor's own
    /// prewarm task and preventing dnsd from ever becoming ready.
    /// UDP listeners don't need to early-out — `handle_bytes`
    /// returns REFUSED cheaply and a UDP recvfrom doesn't carry the
    /// same per-connection cost.
    ///
    /// Default true preserves behavior for any handler that doesn't
    /// have a meaningful readiness signal (the disabled-mode
    /// `RefusedHandler`, tests, etc.).
    fn is_ready(&self) -> bool {
        true
    }
}

/// Build a REFUSED reply mirroring the TXID + question section of
/// `query`. Returns `None` if `query` doesn't parse — the caller
/// should silently drop in that case (never reply to a malformed
/// packet, that's an amplification vector).
///
/// Used in two places:
/// * `RefusedHandler` — the disabled-mode dispatcher.
/// * UDP listener load shedding — when the per-listener inflight
///   cap is full, the listener answers REFUSED inline rather than
///   spawning a walk task.
pub fn build_refused(query: &[u8]) -> Option<Vec<u8>> {
    let msg = Message::from_bytes(query).ok()?;
    let mut resp = Message::response(msg.metadata.id, msg.metadata.op_code);
    resp.metadata.recursion_desired = msg.metadata.recursion_desired;
    resp.metadata.recursion_available = false;
    resp.metadata.response_code = match msg.metadata.op_code {
        OpCode::Query => ResponseCode::Refused,
        _ => ResponseCode::NotImp,
    };
    for q in msg.queries {
        resp.add_query(q.clone());
    }
    resp.to_vec().ok()
}

/// Stub handler: parses the query, mirrors the TXID + question section
/// into a response with RCODE=REFUSED. Used by tests and as the
/// disabled-mode handler when the operator turns recursion off — a
/// well-behaved sink that answers (so clients don't retry indefinitely)
/// without leaking anything.
pub struct RefusedHandler;

#[async_trait]
impl DnsHandler for RefusedHandler {
    async fn handle_bytes(
        &self,
        query: &[u8],
        _peer: IpAddr,
        _ctx: &ListenerContext,
    ) -> Option<Vec<u8>> {
        build_refused(query)
    }
}

/// Convenience: make any `Arc<T: DnsHandler>` work as `Arc<dyn DnsHandler>`.
pub type SharedHandler = Arc<dyn DnsHandler>;

/// Hot-swappable handler wrapper. Listener tasks hold an
/// `Arc<LiveHandler>` (which IS a `DnsHandler` itself). On reload,
/// `swap()` atomically replaces the inner handler — in-flight
/// queries finish on the old handler, new queries go to the new
/// one. Lock-free reads via `arc-swap`.
///
/// The inner `T` is parameterised so tests can put a `RefusedHandler`
/// here without dragging in the full recursor.
pub struct LiveHandler<T: DnsHandler> {
    inner: arc_swap::ArcSwap<T>,
}

impl<T: DnsHandler> LiveHandler<T> {
    pub fn new(initial: T) -> Self {
        Self {
            inner: arc_swap::ArcSwap::from_pointee(initial),
        }
    }

    /// Atomically replace the inner handler. In-flight queries on
    /// the old handler finish normally; new queries see the new
    /// handler on their next `handle_bytes` call.
    pub fn swap(&self, new: T) {
        self.inner.store(Arc::new(new));
    }

    /// Snapshot of the current inner handler. Used in places that
    /// want a temporary stable reference (e.g. for logging).
    pub fn current(&self) -> Arc<T> {
        self.inner.load_full()
    }
}

#[async_trait]
impl<T: DnsHandler> DnsHandler for LiveHandler<T> {
    async fn handle_bytes(
        &self,
        query: &[u8],
        peer: IpAddr,
        ctx: &ListenerContext,
    ) -> Option<Vec<u8>> {
        // Snapshot the inner Arc so the dispatch is stable for the
        // duration of this query, even if a concurrent reload swaps
        // mid-call.
        let h = self.inner.load_full();
        h.handle_bytes(query, peer, ctx).await
    }

    fn is_ready(&self) -> bool {
        self.inner.load().is_ready()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, Query};
    use hickory_proto::rr::{Name, RecordType};

    #[tokio::test]
    async fn refused_stub_mirrors_txid_and_question() {
        let mut req = Message::new(0x4242, MessageType::Query, OpCode::Query);
        req.metadata.recursion_desired = true;
        req.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let bytes = req.to_vec().unwrap();

        let h = RefusedHandler;
        let ctx = ListenerContext::default();
        let resp_bytes = h
            .handle_bytes(&bytes, "10.0.0.1".parse().unwrap(), &ctx)
            .await
            .unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.metadata.id, 0x4242);
        assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
        assert_eq!(resp.queries.len(), 1);
        assert!(resp.metadata.recursion_desired);
        assert!(!resp.metadata.recursion_available);
    }
}
