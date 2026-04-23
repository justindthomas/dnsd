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
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::serialize::binary::BinDecodable;

#[async_trait]
pub trait DnsHandler: Send + Sync + 'static {
    /// Dispatch a single DNS query. `query` is the raw wire format
    /// (no transport framing). `peer` is the remote IP (the transport
    /// has already enforced the CIDR allow-list).
    async fn handle_bytes(&self, query: &[u8], peer: IpAddr) -> Option<Vec<u8>>;
}

/// Stub handler: parses the query, mirrors the TXID + question section
/// into a response with RCODE=REFUSED. Replaced by the real recursor
/// in task #8. Until then imp-dnsd is a well-behaved sink — it answers
/// (so clients don't retry indefinitely) without leaking anything.
pub struct RefusedHandler;

#[async_trait]
impl DnsHandler for RefusedHandler {
    async fn handle_bytes(&self, query: &[u8], _peer: IpAddr) -> Option<Vec<u8>> {
        let msg = Message::from_bytes(query).ok()?;
        let mut resp = Message::new();
        resp.set_id(msg.id());
        resp.set_message_type(MessageType::Response);
        resp.set_op_code(msg.op_code());
        resp.set_recursion_desired(msg.recursion_desired());
        resp.set_recursion_available(false);
        resp.set_response_code(match msg.op_code() {
            OpCode::Query => ResponseCode::Refused,
            _ => ResponseCode::NotImp,
        });
        for q in msg.queries() {
            resp.add_query(q.clone());
        }
        resp.to_vec().ok()
    }
}

// Hickory's Message::to_vec is fallible; wrap the common call sites.
pub trait MessageVecExt {
    fn to_vec(&self) -> Result<Vec<u8>, hickory_proto::error::ProtoError>;
}

impl MessageVecExt for Message {
    fn to_vec(&self) -> Result<Vec<u8>, hickory_proto::error::ProtoError> {
        use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
        let mut buf = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buf);
        self.emit(&mut encoder)?;
        Ok(buf)
    }
}

/// Convenience: make any `Arc<T: DnsHandler>` work as `Arc<dyn DnsHandler>`.
pub type SharedHandler = Arc<dyn DnsHandler>;

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::op::Query;

    #[tokio::test]
    async fn refused_stub_mirrors_txid_and_question() {
        let mut req = Message::new();
        req.set_id(0x4242);
        req.set_message_type(MessageType::Query);
        req.set_op_code(OpCode::Query);
        req.set_recursion_desired(true);
        req.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let bytes = req.to_vec().unwrap();

        let h = RefusedHandler;
        let resp_bytes = h.handle_bytes(&bytes, "10.0.0.1".parse().unwrap()).await.unwrap();
        let resp = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(resp.id(), 0x4242);
        assert_eq!(resp.response_code(), ResponseCode::Refused);
        assert_eq!(resp.queries().len(), 1);
        assert!(resp.recursion_desired());
        assert!(!resp.recursion_available());
    }
}
