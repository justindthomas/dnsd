//! Query processor — the piece transports hand queries to.
//!
//! v1 resolution order:
//!   1. Parse the query, pull the first question.
//!   2. Cache lookup → on hit, rewrite TXID and return.
//!   3. Forwarder lookup → on suffix match, query upstream.
//!   4. No match → SERVFAIL (iterative recursion is follow-up).
//!
//! Later iterations bolt on: iterative root-walk resolution, RRL,
//! 0x20 case randomisation, DNS Cookies, DNSSEC validation, DNS64.

pub mod cache;
pub mod forwarder;
pub mod dns64;
pub mod dnssec;
pub mod rrl;

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::serialize::binary::BinDecodable;

use crate::config::DnsConfig;
use crate::handler::DnsHandler;
use crate::metrics::Metrics;
use vcl_rs::VclReactor;

pub use cache::{CacheKey, DnsCache};
pub use forwarder::{Forwarders, UpstreamClient};

pub struct RecursorHandler {
    cache: Arc<DnsCache>,
    forwarders: Arc<Forwarders>,
    upstream: Arc<UpstreamClient>,
    metrics: Arc<Metrics>,
}

impl RecursorHandler {
    pub fn from_config(
        cfg: &DnsConfig,
        reactor: VclReactor,
        metrics: Arc<Metrics>,
    ) -> anyhow::Result<Self> {
        let cache_cfg = cfg.cache.clone().unwrap_or_default();
        let cache = Arc::new(DnsCache::new(
            cache_cfg.max_entries.unwrap_or(10_000) as u64,
            cache_cfg.min_ttl.unwrap_or(0),
            cache_cfg.max_ttl.unwrap_or(604_800),
            cache_cfg.negative_ttl.unwrap_or(3_600),
        ));

        let forwarders = Arc::new(Forwarders::new(&cfg.forwarders)?);

        let upstream_timeout_ms = cfg
            .recursion
            .as_ref()
            .and_then(|r| r.upstream_timeout_ms);
        let upstream = Arc::new(UpstreamClient::new(reactor, upstream_timeout_ms));

        Ok(Self {
            cache,
            forwarders,
            upstream,
            metrics,
        })
    }
}

#[async_trait]
impl DnsHandler for RecursorHandler {
    async fn handle_bytes(&self, query: &[u8], _peer: IpAddr) -> Option<Vec<u8>> {
        let msg = match Message::from_bytes(query) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("malformed query: {e}");
                return None;
            }
        };
        let q = msg.queries().first()?.clone();
        let key = CacheKey::new(q.name(), q.query_type(), q.query_class());

        // 1) Cache lookup.
        if let Some(mut cached) = self.cache.get(&key).await {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            cache::rewrite_txid(&mut cached, msg.id());
            return Some(cached);
        }
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);

        // 2) Forwarder routing.
        if let Some(servers) = self.forwarders.lookup(q.name()) {
            self.metrics.forwarder_matched.fetch_add(1, Ordering::Relaxed);
            let servers = servers.to_vec(); // short borrow → owned
            match self.upstream.query(&servers, query).await {
                Ok(resp) => {
                    if let Ok(parsed) = Message::from_bytes(&resp) {
                        // Cache the response under the original
                        // question (case-insensitive).
                        self.cache.put(key, &parsed, resp.clone()).await;
                    }
                    return Some(resp);
                }
                Err(e) => {
                    tracing::warn!(qname = %q.name(), "forwarder failed: {e}");
                    return Some(servfail(&msg));
                }
            }
        }

        // 3) No forwarder matched — for v1 return SERVFAIL with EDE
        // (RFC 8914) "not authoritative / no path". Iterative
        // recursion against the root is task #9.
        Some(servfail(&msg))
    }
}

fn servfail(req: &Message) -> Vec<u8> {
    let mut resp = Message::new();
    resp.set_id(req.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_recursion_desired(req.recursion_desired());
    resp.set_recursion_available(false);
    resp.set_response_code(ResponseCode::ServFail);
    for q in req.queries() {
        resp.add_query(q.clone());
    }
    resp.to_vec().unwrap_or_else(|_| {
        // Absolute fallback — a 12-byte header with SERVFAIL and no
        // question. Clients may re-ask; that's fine.
        let mut buf = vec![0u8; 12];
        buf[0..2].copy_from_slice(&req.id().to_be_bytes());
        buf[2] = 0x80; // QR=1
        buf[3] = 0x02; // RCODE=SERVFAIL
        buf
    })
}
