//! Query processor — the piece transports hand queries to.
//!
//! Resolution order:
//!   1. Parse the query; extract its single question.
//!   2. RRL check on the peer's /24 or /64 (silent drop on throttle).
//!   3. Cache lookup → on hit, rewrite TXID and return.
//!   4. Forwarder lookup:
//!      * Longest-suffix match on the question name picks the
//!        upstream list. Servers tried in order.
//!      * DNS64 post-processing: if the listener opted in and the
//!        upstream returned NODATA/NXDOMAIN for AAAA, re-query A and
//!        synthesise AAAA per RFC 6147.
//!      * DNS64 PTR: ip6.arpa question under the NAT64 prefix is
//!        rewritten to in-addr.arpa before forwarding.
//!   5. No forwarder matched → SERVFAIL (iterative recursion is
//!      the next follow-up).
//!
//! DNSSEC policy (`pass-through` | `strip` | `validate`) is applied
//! to every outbound response. Full chain-of-trust validation needs
//! the iterative recursor; until then `validate` acts like `strip`
//! and is documented in `dnssec.rs`.

pub mod cache;
pub mod cookies;
pub mod forwarder;
pub mod dns64;
pub mod dnssec;
pub mod rrl;
pub mod zeroxtwenty;

use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_proto::serialize::binary::BinDecodable;

use crate::config::DnsConfig;
use crate::handler::{DnsHandler, ListenerContext};
use crate::metrics::Metrics;
use vcl_rs::VclReactor;

pub use cache::{CacheKey, DnsCache};
pub use dns64::Dns64Policy;
pub use dnssec::DnssecPolicy;
pub use forwarder::{Forwarders, UpstreamClient};
pub use rrl::Rrl;

pub struct RecursorHandler {
    cache: Arc<DnsCache>,
    forwarders: Arc<Forwarders>,
    upstream: Arc<UpstreamClient>,
    metrics: Arc<Metrics>,
    dns64: Option<Arc<Dns64Policy>>,
    dnssec: DnssecPolicy,
    rrl: Option<Arc<Rrl>>,
}

impl RecursorHandler {
    /// The cache, for control-socket inspection.
    pub fn cache(&self) -> Arc<DnsCache> {
        self.cache.clone()
    }

    /// The forwarder table, for control-socket inspection.
    pub fn forwarders(&self) -> Arc<Forwarders> {
        self.forwarders.clone()
    }

    /// Build the VCL-independent state (cache + forwarder table).
    /// Exposed separately from `from_config` so `main.rs` can bring
    /// up the control socket with live state before VCL/VPP is
    /// ready — the supervisor's readiness gate watches
    /// `/run/dnsd.sock` and that file needs to exist even if VPP is
    /// slow to start.
    pub fn build_cache_from_config(cfg: &DnsConfig) -> Arc<DnsCache> {
        let cache_cfg = cfg.cache.clone().unwrap_or_default();
        Arc::new(DnsCache::new(
            cache_cfg.max_entries.unwrap_or(10_000) as u64,
            cache_cfg.min_ttl.unwrap_or(0),
            cache_cfg.max_ttl.unwrap_or(604_800),
            cache_cfg.negative_ttl.unwrap_or(3_600),
        ))
    }

    pub fn build_forwarders_from_config(cfg: &DnsConfig) -> anyhow::Result<Arc<Forwarders>> {
        Forwarders::new(&cfg.forwarders).map(Arc::new)
    }

    pub fn from_config(
        cfg: &DnsConfig,
        reactor: VclReactor,
        metrics: Arc<Metrics>,
    ) -> anyhow::Result<Self> {
        let cache = Self::build_cache_from_config(cfg);
        let forwarders = Self::build_forwarders_from_config(cfg)?;
        Self::from_parts(cfg, reactor, metrics, cache, forwarders)
    }

    /// Build a RecursorHandler using a pre-constructed cache +
    /// forwarder table. Used by `main.rs` to share those Arcs with
    /// the control socket.
    pub fn from_parts(
        cfg: &DnsConfig,
        reactor: VclReactor,
        metrics: Arc<Metrics>,
        cache: Arc<DnsCache>,
        forwarders: Arc<Forwarders>,
    ) -> anyhow::Result<Self> {
        let upstream_timeout_ms = cfg
            .recursion
            .as_ref()
            .and_then(|r| r.upstream_timeout_ms);
        let upstream = Arc::new(UpstreamClient::new(reactor, upstream_timeout_ms));

        // Build a DNS64 policy if any listener has dns64 enabled,
        // OR if the operator wrote an explicit `dns.dns64:` block
        // (they may have meant to enable it on listeners they're
        // about to add). Per-query opt-in still happens through
        // `ListenerContext::dns64`.
        let any_listener_dns64 = cfg.listeners.iter().any(|l| l.dns64);
        let dns64 = if any_listener_dns64 || cfg.dns64.is_some() {
            let policy_cfg = cfg.dns64.clone().unwrap_or_default();
            Some(Arc::new(
                Dns64Policy::from_config(&policy_cfg)
                    .or_else(|_| -> anyhow::Result<_> { Ok(Dns64Policy::default_wkp()) })?,
            ))
        } else {
            None
        };

        let dnssec = DnssecPolicy::from_recursion(cfg.recursion.as_ref());

        let rrl = Rrl::from_config(cfg.rate_limit.as_ref()).map(Arc::new);

        Ok(Self {
            cache,
            forwarders,
            upstream,
            metrics,
            dns64,
            dnssec,
            rrl,
        })
    }
}

#[async_trait]
impl DnsHandler for RecursorHandler {
    async fn handle_bytes(
        &self,
        query: &[u8],
        peer: IpAddr,
        ctx: &ListenerContext,
    ) -> Option<Vec<u8>> {
        // (1) Parse.
        let msg = match Message::from_bytes(query) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("malformed query: {e}");
                return None;
            }
        };
        let q = msg.queries().first()?.clone();

        // (2) RRL — silent drop.
        if let Some(rrl) = &self.rrl {
            if !rrl.check(peer) {
                self.metrics.rrl_dropped.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }

        // (3) DNS64 PTR short-circuit: rewrite the question, send it
        // off to in-addr.arpa via the normal forwarder/cache path, then
        // wrap the v4 PTR back into an ip6.arpa answer.
        if ctx.dns64 && q.query_type() == RecordType::PTR {
            if let Some(policy) = &self.dns64 {
                if let Some(new_qname) = dns64::rewrite_ptr_question(policy, q.name()) {
                    let rewritten_query = rewrite_query_name(&msg, &new_qname);
                    if let Some(ans) = self
                        .resolve_forwarded(&rewritten_query, &new_qname, RecordType::PTR)
                        .await
                    {
                        let parsed = Message::from_bytes(&ans).ok()?;
                        let mut synth = dns64::rewrap_ptr_response(&msg, &parsed);
                        self.metrics.dns64_synthesised.fetch_add(1, Ordering::Relaxed);
                        self.dnssec.apply_to_response(&mut synth);
                        return synth.to_vec().ok();
                    }
                    return Some(servfail(&msg));
                }
            }
        }

        // (4) Normal cache + forwarder path.
        let key = CacheKey::new(q.name(), q.query_type(), q.query_class());
        if let Some(mut cached) = self.cache.get(&key).await {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            cache::rewrite_txid(&mut cached, msg.id());
            // Apply DNSSEC policy to the cached bytes too.
            if let Ok(mut parsed) = Message::from_bytes(&cached) {
                self.dnssec.apply_to_response(&mut parsed);
                if let Ok(reencoded) = parsed.to_vec() {
                    return Some(reencoded);
                }
            }
            return Some(cached);
        }
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);

        let Some(servers) = self.forwarders.lookup(q.name()) else {
            // No forwarder — SERVFAIL for now (iterative recursion
            // is the follow-up).
            return Some(servfail(&msg));
        };
        self.metrics.forwarder_matched.fetch_add(1, Ordering::Relaxed);
        let servers = servers.to_vec();

        let resp_bytes = match self.upstream.query(&servers, query).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(qname = %q.name(), "forwarder failed: {e}");
                return Some(servfail(&msg));
            }
        };
        let mut resp = match Message::from_bytes(&resp_bytes) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("upstream response parse: {e}");
                return Some(servfail(&msg));
            }
        };

        // (5) DNS64 AAAA synthesis. Trigger on NODATA / NXDOMAIN.
        if dns64::should_synthesise(
            self.dns64.as_deref(),
            ctx.dns64,
            q.name(),
            q.query_type(),
            &resp,
        ) {
            if let Some(policy) = &self.dns64 {
                let mut a_query = msg.clone();
                a_query.take_queries();
                a_query.add_query(Query::query(q.name().clone(), RecordType::A));
                let Ok(a_query_bytes) = a_query.to_vec() else {
                    // Fall through to the original AAAA response.
                    return Some(respond_with_policy(&mut resp, &self.dnssec));
                };
                match self.upstream.query(&servers, &a_query_bytes).await {
                    Ok(a_bytes) => {
                        if let Ok(a_resp) = Message::from_bytes(&a_bytes) {
                            if !a_resp.answers().is_empty() {
                                let mut synth =
                                    dns64::synthesise_from_a(policy, &msg, &a_resp);
                                self.metrics
                                    .dns64_synthesised
                                    .fetch_add(1, Ordering::Relaxed);
                                // AD already cleared inside synthesise_from_a;
                                // still run the policy for consistency.
                                self.dnssec.apply_to_response(&mut synth);
                                let bytes = synth
                                    .to_vec()
                                    .unwrap_or_else(|_| servfail(&msg));
                                // Cache the synthesised response under
                                // the AAAA key so subsequent queries
                                // don't re-trigger synthesis.
                                self.cache.put(key, &synth, bytes.clone()).await;
                                return Some(bytes);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(qname = %q.name(), "DNS64 A-side failed: {e}");
                    }
                }
            }
        }

        // Apply policy + cache the upstream response unchanged.
        self.dnssec.apply_to_response(&mut resp);
        let out = resp.to_vec().unwrap_or_else(|_| servfail(&msg));
        self.cache.put(key, &resp, out.clone()).await;
        Some(out)
    }
}

impl RecursorHandler {
    /// Used by the DNS64 PTR short-circuit: query the rewritten v4
    /// name through the forwarder + cache path, return the raw
    /// response bytes. Does not apply DNS64 post-processing itself —
    /// the caller does that with `rewrap_ptr_response`.
    async fn resolve_forwarded(
        &self,
        query_msg: &Message,
        qname: &hickory_proto::rr::Name,
        qtype: RecordType,
    ) -> Option<Vec<u8>> {
        let key = CacheKey::new(qname, qtype, hickory_proto::rr::DNSClass::IN);
        if let Some(cached) = self.cache.get(&key).await {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Some(cached);
        }
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);

        let servers = self.forwarders.lookup(qname)?;
        let servers = servers.to_vec();
        let q_bytes = query_msg.to_vec().ok()?;
        let resp_bytes = self.upstream.query(&servers, &q_bytes).await.ok()?;
        if let Ok(parsed) = Message::from_bytes(&resp_bytes) {
            self.cache.put(key, &parsed, resp_bytes.clone()).await;
        }
        Some(resp_bytes)
    }
}

fn respond_with_policy(msg: &mut Message, policy: &DnssecPolicy) -> Vec<u8> {
    policy.apply_to_response(msg);
    msg.to_vec().unwrap_or_default()
}

fn rewrite_query_name(original: &Message, new_name: &hickory_proto::rr::Name) -> Message {
    let mut new_msg = Message::new();
    new_msg.set_id(rand::random());
    new_msg.set_message_type(MessageType::Query);
    new_msg.set_op_code(OpCode::Query);
    new_msg.set_recursion_desired(original.recursion_desired());
    new_msg.add_query(Query::query(new_name.clone(), RecordType::PTR));
    new_msg
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
        let mut buf = vec![0u8; 12];
        buf[0..2].copy_from_slice(&req.id().to_be_bytes());
        buf[2] = 0x80; // QR=1
        buf[3] = 0x02; // RCODE=SERVFAIL
        buf
    })
}
