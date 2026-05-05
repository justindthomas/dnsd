//! Internal counters exposed via the control socket (`stats` command).
//!
//! Kept deliberately small — a bigger export (Prometheus /metrics via
//! axum, per-forwarder histograms, etc.) is a follow-up. For now we
//! count the events an operator will look at when debugging a new
//! install.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    pub queries_udp: AtomicU64,
    pub queries_tcp: AtomicU64,
    pub queries_dot: AtomicU64,
    pub queries_doh: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub forwarder_matched: AtomicU64,
    pub recursion_walked: AtomicU64,
    pub rrl_dropped: AtomicU64,
    pub acl_denied: AtomicU64,
    pub dns64_synthesised: AtomicU64,
    pub dnssec_validated: AtomicU64,
    pub dnssec_failed: AtomicU64,
    /// Incoming UDP queries refused because the per-listener
    /// inflight cap was full. See `Listener.max_inflight`.
    pub udp_inflight_shed: AtomicU64,
}

impl Metrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            queries_udp: self.queries_udp.load(Ordering::Relaxed),
            queries_tcp: self.queries_tcp.load(Ordering::Relaxed),
            queries_dot: self.queries_dot.load(Ordering::Relaxed),
            queries_doh: self.queries_doh.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            forwarder_matched: self.forwarder_matched.load(Ordering::Relaxed),
            recursion_walked: self.recursion_walked.load(Ordering::Relaxed),
            rrl_dropped: self.rrl_dropped.load(Ordering::Relaxed),
            acl_denied: self.acl_denied.load(Ordering::Relaxed),
            dns64_synthesised: self.dns64_synthesised.load(Ordering::Relaxed),
            dnssec_validated: self.dnssec_validated.load(Ordering::Relaxed),
            dnssec_failed: self.dnssec_failed.load(Ordering::Relaxed),
            udp_inflight_shed: self.udp_inflight_shed.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricsSnapshot {
    pub queries_udp: u64,
    pub queries_tcp: u64,
    pub queries_dot: u64,
    pub queries_doh: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub forwarder_matched: u64,
    pub recursion_walked: u64,
    pub rrl_dropped: u64,
    pub acl_denied: u64,
    pub dns64_synthesised: u64,
    pub dnssec_validated: u64,
    pub dnssec_failed: u64,
    #[serde(default)]
    pub udp_inflight_shed: u64,
}
