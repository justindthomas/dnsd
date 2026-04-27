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
pub mod iterative;
pub mod local_zones;
pub mod normalize;
pub mod rrl;
pub mod zeroxtwenty;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};

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
pub use iterative::IterativeResolver;
pub use rrl::Rrl;

pub struct RecursorHandler {
    cache: Arc<DnsCache>,
    forwarders: Arc<Forwarders>,
    upstream: Arc<UpstreamClient>,
    metrics: Arc<Metrics>,
    dns64: Option<Arc<Dns64Policy>>,
    dnssec: DnssecPolicy,
    /// When `dnssec` is `Validate`, the validator holds the trust
    /// anchors + the upstream client for DNSKEY fetches during chain
    /// walks. None in PassThrough / Strip modes.
    validator: Option<Arc<dnssec::Validator>>,
    rrl: Option<Arc<Rrl>>,
    iterative: Option<Arc<IterativeResolver>>,
    /// Short-lived "this iterative walk just failed" cache. Without
    /// it, a name like `detectportal.firefox.com` (which Firefox
    /// retries every 1-2 s for the captive-portal probe) burns a
    /// fresh full chain walk on every retry when the underlying
    /// resolution is broken — Mozilla's CNAME chain into
    /// `cloudops.mozgcp.net` whose Google-Cloud-DNS NSes our walker
    /// can't reach. 60-second TTL keeps a transient outage from
    /// pinning into "permanently broken" while still suppressing
    /// the retry storm.
    neg_resolve_cache: Arc<NegResolveCache>,
    /// Per-key mutex map for in-flight iterative walks. When N
    /// parallel queries for the same (name, type) arrive together
    /// (Microsoft's telemetry endpoint produces bursts of 5-7 in
    /// one second), without coalescing they ALL pass the response-
    /// cache + negative-cache checks together and ALL kick off
    /// independent walks — burning N× worker time for an answer
    /// only one walk actually needs to compute. With this map, the
    /// first query takes the per-key lock and walks; followers
    /// wait for the lock to release, then re-check the response
    /// cache (which the leader populated) and serve the cached
    /// bytes instead of walking themselves.
    in_flight: Arc<InFlightMap>,
}

const IN_FLIGHT_CAP: usize = 4096;

pub struct InFlightMap {
    map: std::sync::Mutex<HashMap<(hickory_proto::rr::Name, RecordType), Arc<tokio::sync::Mutex<()>>>>,
}

impl InFlightMap {
    fn new() -> Self {
        Self {
            map: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Returns a per-key mutex; multiple callers passing the same
    /// (name, rtype) get the same Arc<Mutex>, so locking it
    /// serialises them. The Arc is dropped from the map below
    /// when nothing else holds it (we sweep entries with refcount
    /// 1 on each insert) so the map doesn't grow without bound.
    fn lock_for(&self, name: &hickory_proto::rr::Name, rtype: RecordType) -> Arc<tokio::sync::Mutex<()>> {
        let key = (name.to_lowercase(), rtype);
        let mut map = self.map.lock().unwrap();
        // Cheap sweep: any entry whose Arc is held only by the map
        // itself is no longer needed. Bounded work per insert.
        if map.len() >= IN_FLIGHT_CAP {
            map.retain(|_, v| Arc::strong_count(v) > 1);
            if map.len() >= IN_FLIGHT_CAP {
                if let Some(k) = map.keys().next().cloned() {
                    map.remove(&k);
                }
            }
        }
        map.entry(key)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}

impl Default for InFlightMap {
    fn default() -> Self {
        Self::new()
    }
}

const NEG_RESOLVE_CAP: usize = 256;
/// 5 minutes. The names that fall into this cache are aggressive
/// retriers — Windows telemetry endpoints, Firefox captive-portal
/// probes — that re-fire every few seconds and chain through CNAME
/// hops to NSes our walker can't currently resolve. At 60 s the
/// storm just fired one walk per minute per name; at 5 min we
/// collapse it to ~1 walk per name per 5 min, which is roughly
/// the right cost given that the underlying chain genuinely isn't
/// resolving. If the upstream zone is fixed in the meantime, the
/// affected name's clients will see a 5-min latency tail and then
/// recover — acceptable for the kind of name that ends up here.
const NEG_RESOLVE_TTL: Duration = Duration::from_secs(300);

pub struct NegResolveCache {
    entries: RwLock<HashMap<(hickory_proto::rr::Name, RecordType), Instant>>,
}

impl NegResolveCache {
    fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    fn hit(&self, name: &hickory_proto::rr::Name, rtype: RecordType) -> bool {
        let key = (name.to_lowercase(), rtype);
        let map = self.entries.read().unwrap();
        map.get(&key).map(|e| *e > Instant::now()).unwrap_or(false)
    }

    fn insert(&self, name: hickory_proto::rr::Name, rtype: RecordType) {
        let key = (name.to_lowercase(), rtype);
        let expiry = Instant::now() + NEG_RESOLVE_TTL;
        let mut map = self.entries.write().unwrap();
        if map.len() >= NEG_RESOLVE_CAP && !map.contains_key(&key) {
            let now = Instant::now();
            let stale: Vec<_> = map
                .iter()
                .filter_map(|(k, v)| if *v <= now { Some(k.clone()) } else { None })
                .collect();
            if stale.is_empty() {
                if let Some(k) = map.keys().next().cloned() {
                    map.remove(&k);
                }
            } else {
                for k in stale {
                    map.remove(&k);
                }
            }
        }
        map.insert(key, expiry);
    }
}

impl Default for NegResolveCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RecursorHandler {
    /// The cache, for control-socket inspection.
    pub fn cache(&self) -> Arc<DnsCache> {
        self.cache.clone()
    }

    /// Background-prewarm the DNSSEC validator's DNSKEY cache by
    /// self-querying a handful of popular signed names. Without this,
    /// the first user query for a signed .com/.net/.org name after
    /// startup pays 2-4 DNSKEY round-trips serially before the answer
    /// can come back; afterward the cache stays warm. No-op when
    /// validation is off or the iterative recursor isn't built.
    pub fn spawn_dnssec_prewarm(&self) {
        let iter = match self.iterative.as_ref() {
            Some(i) => i.clone(),
            None => return,
        };
        let validator = match self.validator.as_ref() {
            Some(v) => v.clone(),
            None => return,
        };
        // Names chosen to cover the top signed gTLDs + a handful of
        // popular ccTLDs without hitting NSes that we know are
        // pathological (e.g. arin.net, whose RRL→TC=1 + broken VPP
        // TCP would burn the prewarm budget on a known-failing fetch).
        // Each entry warms one TLD's DNSKEY plus root's; failures
        // (registry-operated names that refuse our query, etc.) just
        // log at debug and skip — the next user query for that TLD
        // pays the cost normally.
        const PREWARM_NAMES: &[&str] = &[
            "iana.org.",        // .org
            "cloudflare.com.",  // .com
            "internic.net.",    // .net
            "nominet.uk.",      // .uk
            "denic.de.",        // .de
            "nic.io.",          // .io
            "google.dev.",      // .dev
            "google.app.",      // .app
        ];
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            let mut joins = Vec::with_capacity(PREWARM_NAMES.len());
            for name in PREWARM_NAMES {
                let iter = iter.clone();
                let validator = validator.clone();
                joins.push(tokio::spawn(async move {
                    let parsed = match hickory_proto::rr::Name::from_ascii(name) {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let mut q = Message::new();
                    q.set_message_type(MessageType::Query);
                    q.set_op_code(OpCode::Query);
                    q.set_recursion_desired(true);
                    q.add_query(Query::query(parsed, RecordType::A));
                    match iter.resolve_with_chain(&q).await {
                        Ok((bytes, chain)) => {
                            if let Ok(resp) = Message::from_bytes(&bytes) {
                                let _ = validator.validate_walk(&chain, &resp).await;
                                tracing::debug!(name = %name, "DNSKEY prewarm done");
                            }
                        }
                        Err(e) => {
                            tracing::debug!(name = %name, "DNSKEY prewarm failed: {e:#}");
                        }
                    }
                }));
            }
            for j in joins {
                let _ = j.await;
            }
            tracing::info!(
                elapsed_ms = started.elapsed().as_millis() as u64,
                "DNSSEC cache prewarm complete"
            );
        });
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
        Self::from_parts(cfg, reactor, metrics, cache, forwarders, None, None)
    }

    /// Build a RecursorHandler using a pre-constructed cache +
    /// forwarder table. Used by `main.rs` to share those Arcs with
    /// the control socket. `root_hints_path`, when set, lets the
    /// iterative recursor persist the primed root set across
    /// restarts (e.g. `/persistent/data/dnsd/root-hints` on imp).
    pub fn from_parts(
        cfg: &DnsConfig,
        reactor: VclReactor,
        metrics: Arc<Metrics>,
        cache: Arc<DnsCache>,
        forwarders: Arc<Forwarders>,
        root_hints_path: Option<std::path::PathBuf>,
        discovered_v6_source: Option<std::net::Ipv6Addr>,
    ) -> anyhow::Result<Self> {
        let upstream_timeout_ms = cfg
            .recursion
            .as_ref()
            .and_then(|r| r.upstream_timeout_ms);
        // Source-IP selection for outbound upstream queries.
        //
        // v4: pick the first v4 listener address. NAT44 translates
        // it to the wan IP on egress, and the LAN-side bind keeps
        // dnsd's ephemeral ports out of conflict with NAT's pool.
        //
        // v6: priority order is explicit config > v6 listener address
        // > VPP-discovered global v6. There's no NAT for v6, so the
        // source has to be globally routable; binding `::` causes
        // packets to leave with src=:: and the wire drops them. The
        // VCL API can't tell us VPP's FIB-derived source (only echoes
        // the bound address), so the discovery happens via VPP's
        // binary API in `async_main` and gets passed here.
        let mut source_v4: Option<std::net::Ipv4Addr> = None;
        let mut listener_v6: Option<std::net::Ipv6Addr> = None;
        for l in &cfg.listeners {
            match l.address {
                std::net::IpAddr::V4(v4) if source_v4.is_none() => {
                    source_v4 = Some(v4);
                }
                std::net::IpAddr::V6(v6) if listener_v6.is_none() => {
                    listener_v6 = Some(v6);
                }
                _ => {}
            }
        }
        let configured_v6 = cfg.recursion.as_ref().and_then(|r| r.source_v6);
        let source_v6 = configured_v6.or(listener_v6).or(discovered_v6_source);
        let upstream = Arc::new(UpstreamClient::new(
            reactor,
            upstream_timeout_ms,
            source_v4,
            source_v6,
        ));

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

        // Forwarders are trust boundaries: the operator configured
        // them knowing those upstreams speak for those domains. dnsd
        // does NOT re-walk the chain of trust on the forwarder path
        // — it would double every query and defeat the forwarder's
        // purpose. If validation is on AND forwarders are also set,
        // make the operator aware that forwarded responses will have
        // AD stripped (unless they switch to PassThrough).
        if matches!(dnssec, DnssecPolicy::Validate) && !cfg.forwarders.is_empty() {
            tracing::warn!(
                forwarders = cfg.forwarders.len(),
                "dnssec: validate + forwarders configured: forwarded responses will return AD=0 \
                 (validation only runs on the iterative path). Route sensitive zones through iterative \
                 or accept the forwarder's own validation via `dnssec: passthrough`."
            );
        }

        let rrl = Rrl::from_config(cfg.rate_limit.as_ref()).map(Arc::new);

        // Iterative recursion is enabled by default when no explicit
        // recursion block is present (matches operator intent: "just
        // resolve DNS"); suppressed when recursion.enabled == false.
        let iterative_enabled = cfg
            .recursion
            .as_ref()
            .map(|r| r.enabled)
            .unwrap_or(true);
        let max_cname = cfg
            .recursion
            .as_ref()
            .and_then(|r| r.max_cname_depth)
            .unwrap_or(iterative::DEFAULT_MAX_CNAME);
        let ipv6_upstream = cfg
            .recursion
            .as_ref()
            .map(|r| r.ipv6_upstream)
            .unwrap_or(true);
        // When validation is on, the iterative recursor asks for
        // RRSIG/NSEC records (DO=1) so the validator has something
        // to verify. When validation is off we keep DO=0 to cut a
        // few bytes off every response.
        let dnssec_ok = matches!(dnssec, DnssecPolicy::Validate);
        let iterative = if iterative_enabled {
            Some(Arc::new(IterativeResolver::new(
                upstream.clone(),
                cache.clone(),
                metrics.clone(),
                max_cname,
                ipv6_upstream,
                root_hints_path,
                dnssec_ok,
            )))
        } else {
            None
        };

        // Validator needs access to the live root IPs (to bootstrap
        // the root ZSK under the trust anchor's KSK). Snapshot the
        // shared Arc from the resolver if it's running; otherwise
        // seed a fresh one — the validator won't actually be called
        // without a recursor, but we keep the type non-Option.
        let validator_roots = iterative
            .as_ref()
            .map(|r| r.roots_arc())
            .unwrap_or_else(|| Arc::new(std::sync::RwLock::new(Vec::new())));

        // Load trust anchors if a path is configured AND DNSSEC
        // validation is on. Anchor-load failures log a warning but
        // don't fail startup — operators can fix the file and SIGHUP
        // once it's in place.
        let validator = if matches!(dnssec, DnssecPolicy::Validate) {
            let anchors = match cfg
                .recursion
                .as_ref()
                .and_then(|r| r.trust_anchor.as_ref())
            {
                Some(path) => match dnssec::TrustAnchors::load_from_file(
                    std::path::Path::new(path),
                ) {
                    Ok(a) => {
                        tracing::info!(
                            path = %path,
                            keys = a.len(),
                            "loaded DNSSEC trust anchors"
                        );
                        Arc::new(a)
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %path,
                            "failed to load trust anchors: {e} (validation disabled)"
                        );
                        Arc::new(dnssec::TrustAnchors::new())
                    }
                },
                None => {
                    tracing::warn!(
                        "dnssec: validate is set but no trust_anchor path configured — validation will report Insecure"
                    );
                    Arc::new(dnssec::TrustAnchors::new())
                }
            };
            Some(Arc::new(dnssec::Validator::new(
                anchors,
                upstream.clone(),
                validator_roots,
            )))
        } else {
            None
        };

        Ok(Self {
            cache,
            forwarders,
            upstream,
            metrics,
            dns64,
            dnssec,
            validator,
            rrl,
            iterative,
            neg_resolve_cache: Arc::new(NegResolveCache::new()),
            in_flight: Arc::new(InFlightMap::new()),
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
        // Per-query latency log. Drop runs at every return point and
        // emits a single line per query. Logged at info for queries
        // ≥ 50 ms (slow path: walks, coalescer waits, validation),
        // debug otherwise. Grep journal for `qtiming` to see the
        // user-visible end-to-end latency from ingestion to the
        // moment we hand the response back to the listener.
        struct QTiming {
            t0: Instant,
            qname: String,
            qtype: RecordType,
        }
        impl Drop for QTiming {
            fn drop(&mut self) {
                let ms = self.t0.elapsed().as_millis() as u64;
                if ms >= 50 {
                    tracing::info!(
                        qname = %self.qname,
                        qtype = ?self.qtype,
                        elapsed_ms = ms,
                        "qtiming"
                    );
                } else {
                    tracing::debug!(
                        qname = %self.qname,
                        qtype = ?self.qtype,
                        elapsed_ms = ms,
                        "qtiming"
                    );
                }
            }
        }
        let t0 = Instant::now();

        // (1) Parse.
        let msg = match Message::from_bytes(query) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("malformed query: {e}");
                return None;
            }
        };
        let q = msg.queries().first()?.clone();
        let _qtiming = QTiming {
            t0,
            qname: q.name().to_string(),
            qtype: q.query_type(),
        };

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
        // Recently-failed iterative resolves short-circuit to
        // SERVFAIL — Firefox's captive-portal probe + Microsoft's
        // telemetry CNAME chains both retry every 1-2 s when a
        // sub-walk on their CNAME target zone breaks, and re-walking
        // the chain each time burns sustained worker time on a
        // request the user can't see anyway.
        if self.neg_resolve_cache.hit(q.name(), q.query_type()) {
            return Some(servfail(&msg));
        }
        let key = CacheKey::new(q.name(), q.query_type(), q.query_class());
        // First, the fast unguarded path: if the cache is already
        // warm we don't need to take the per-key lock.
        if let Some(mut cached) = self.cache.get(&key).await {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            cache::rewrite_txid(&mut cached, msg.id());
            if let Ok(mut parsed) = Message::from_bytes(&cached) {
                // Cache-hit DNS64: if the cached AAAA response is
                // empty/NXDOMAIN and this listener wants DNS64,
                // synthesise from the cached A (if any). We don't
                // cache synthesised responses because DNS64 policy
                // is per-listener; the cached A is always authentic.
                if dns64::should_synthesise(
                    self.dns64.as_deref(),
                    ctx.dns64,
                    q.name(),
                    q.query_type(),
                    &parsed,
                ) {
                    if let Some(policy) = self.dns64.as_deref() {
                        if let Some(synth) =
                            self.synthesise_from_cached_a(policy, &msg, q.name()).await
                        {
                            self.metrics
                                .dns64_synthesised
                                .fetch_add(1, Ordering::Relaxed);
                            return synth.to_vec().ok();
                        }
                        // Cached A missed — fall through to regular
                        // resolution (forwarder or iterative) which
                        // will fire the A query itself.
                    }
                } else {
                    // Apply the configured DNSSEC policy on cache
                    // hit — UNLESS we're in Validate mode and the
                    // cached bytes carry the validator's verdict
                    // (AD bit was set by a prior `validate_walk`
                    // succeeding, or explicitly cleared on Insecure).
                    // Stripping AD here would lose the validator's
                    // result on every cache replay.
                    if self.validator.is_none() {
                        self.dnssec.apply_to_response(&mut parsed);
                    }
                    if let Ok(reencoded) = parsed.to_vec() {
                        return Some(reencoded);
                    }
                    return Some(cached);
                }
            } else {
                return Some(cached);
            }
        }
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);

        // Coalesce concurrent walks for the same (name, type). The
        // first arrival wins the per-key lock and runs the walk;
        // followers wait, then the recheck below picks up the
        // cached / negative-cached result instead of walking again.
        let coalesce_lock = self.in_flight.lock_for(q.name(), q.query_type());
        let _coalesce_guard = coalesce_lock.lock().await;
        if let Some(mut cached) = self.cache.get(&key).await {
            cache::rewrite_txid(&mut cached, msg.id());
            if let Ok(mut parsed) = Message::from_bytes(&cached) {
                if self.validator.is_none() {
                    self.dnssec.apply_to_response(&mut parsed);
                }
                if let Ok(reencoded) = parsed.to_vec() {
                    return Some(reencoded);
                }
            }
            return Some(cached);
        }
        if self.neg_resolve_cache.hit(q.name(), q.query_type()) {
            return Some(servfail(&msg));
        }

        let servers = match self.forwarders.lookup(q.name()) {
            Some(s) => {
                self.metrics
                    .forwarder_matched
                    .fetch_add(1, Ordering::Relaxed);
                s.to_vec()
            }
            None => {
                // No forwarder match — fall through to iterative
                // recursion if enabled, otherwise SERVFAIL.
                return match self.iterative.as_ref() {
                    Some(iter) => match iter.resolve_with_chain(&msg).await {
                        Ok((mut bytes, walk_chain)) => {
                            if let Ok(mut parsed) = Message::from_bytes(&bytes) {
                                // If DNSSEC validation is on, run the
                                // chain validator BEFORE applying the
                                // policy's AD-bit defaulting — a
                                // Secure result promotes AD=1, Bogus
                                // flips to SERVFAIL + EDE.
                                if let Some(validator) = self.validator.as_ref() {
                                    let status =
                                        validator.validate_walk(&walk_chain, &parsed).await;
                                    match status {
                                        dnssec::ValidationStatus::Secure => {
                                            self.metrics.dnssec_validated
                                                .fetch_add(1, Ordering::Relaxed);
                                            parsed.set_authentic_data(true);
                                        }
                                        dnssec::ValidationStatus::Insecure => {
                                            parsed.set_authentic_data(false);
                                        }
                                        dnssec::ValidationStatus::Bogus(reason) => {
                                            self.metrics.dnssec_failed
                                                .fetch_add(1, Ordering::Relaxed);
                                            tracing::warn!(
                                                qname = %q.name(),
                                                "DNSSEC validation bogus: {reason}"
                                            );
                                            return Some(servfail_with_ede(
                                                &msg,
                                                dnssec::EDE_DNSSEC_BOGUS,
                                                &reason,
                                            ));
                                        }
                                    }
                                } else {
                                    // Not validating — honour the
                                    // configured policy's AD handling.
                                    self.dnssec.apply_to_response(&mut parsed);
                                }

                                // DNS64 synthesis: fires when the
                                // AAAA response is empty/NXDOMAIN,
                                // the listener opted into DNS64, and
                                // the name isn't on the exclusion
                                // list. We fire a follow-up A query
                                // on the same iterative path and
                                // wrap the answers into v4-in-v6.
                                if dns64::should_synthesise(
                                    self.dns64.as_deref(),
                                    ctx.dns64,
                                    q.name(),
                                    q.query_type(),
                                    &parsed,
                                ) {
                                    if let Some(policy) = self.dns64.as_deref() {
                                        let mut a_query = msg.clone();
                                        a_query.take_queries();
                                        a_query.add_query(Query::query(
                                            q.name().clone(),
                                            RecordType::A,
                                        ));
                                        if let Ok((a_bytes, _)) =
                                            iter.resolve_with_chain(&a_query).await
                                        {
                                            if let Ok(a_resp) = Message::from_bytes(&a_bytes) {
                                                if !a_resp.answers().is_empty() {
                                                    let mut synth = dns64::synthesise_from_a(
                                                        policy, &msg, &a_resp,
                                                    );
                                                    self.metrics.dns64_synthesised.fetch_add(
                                                        1,
                                                        Ordering::Relaxed,
                                                    );
                                                    self.dnssec.apply_to_response(&mut synth);
                                                    if let Ok(synth_bytes) = synth.to_vec() {
                                                        // DON'T cache the synthesised response
                                                        // under the AAAA key — that would serve
                                                        // DNS64 answers to listeners that haven't
                                                        // opted in. The underlying A query is
                                                        // already cached by iter.resolve, so
                                                        // re-synthesising on the next query is
                                                        // cheap.
                                                        return Some(synth_bytes);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                if let Ok(re) = parsed.to_vec() {
                                    bytes = re;
                                }
                            }
                            // Re-cache the FINAL bytes (post-validator,
                            // post-policy). The iterative recursor
                            // already cached the pre-validation bytes
                            // — overwrite with the version that has the
                            // AD bit set as the validator decided so
                            // cache hits replay the right authentication
                            // status. For PassThrough/Strip modes this
                            // is a no-op overwrite (no AD changes).
                            let key = CacheKey::new(
                                q.name(),
                                q.query_type(),
                                q.query_class(),
                            );
                            if let Ok(reparsed) = Message::from_bytes(&bytes) {
                                self.cache.put(key, &reparsed, bytes.clone()).await;
                            }
                            Some(bytes)
                        }
                        Err(e) => {
                            tracing::warn!(qname = %q.name(), "iterative resolve failed: {e:#}");
                            self.neg_resolve_cache
                                .insert(q.name().clone(), q.query_type());
                            Some(servfail(&msg))
                        }
                    },
                    None => Some(servfail(&msg)),
                };
            }
        };

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
                                // Don't cache the synthesised response —
                                // see iterative branch above for why.
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
    /// Look up the cached A response for `qname`; if present,
    /// synthesise an AAAA response from its answers. Returns None
    /// when A isn't cached (caller falls through to re-resolution).
    async fn synthesise_from_cached_a(
        &self,
        policy: &Dns64Policy,
        original_query: &Message,
        qname: &hickory_proto::rr::Name,
    ) -> Option<Message> {
        let a_key = CacheKey::new(qname, RecordType::A, hickory_proto::rr::DNSClass::IN);
        let a_bytes = self.cache.get(&a_key).await?;
        let a_resp = Message::from_bytes(&a_bytes).ok()?;
        if !a_resp
            .answers()
            .iter()
            .any(|r| r.record_type() == RecordType::A)
        {
            return None;
        }
        let mut synth = dns64::synthesise_from_a(policy, original_query, &a_resp);
        self.dnssec.apply_to_response(&mut synth);
        Some(synth)
    }

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

/// SERVFAIL + EDNS0 Extended DNS Error (RFC 8914). Used for DNSSEC
/// Bogus so operators + curious clients can see *why* validation
/// failed instead of just "SERVFAIL, unknown reason".
fn servfail_with_ede(req: &Message, info_code: u16, extra_text: &str) -> Vec<u8> {
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

    // EDE encoded as an OPT record option (RFC 8914 §2): code 15,
    // payload = 2-byte info-code + UTF-8 extra-text. Text truncated
    // to 255 bytes to avoid bloating the response past the edns
    // payload size.
    let mut extra_bytes = Vec::with_capacity(2 + extra_text.len().min(255));
    extra_bytes.extend_from_slice(&info_code.to_be_bytes());
    extra_bytes.extend_from_slice(&extra_text.as_bytes()[..extra_text.len().min(255)]);

    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(1232);
    edns.set_version(0);
    edns.options_mut().insert(hickory_proto::rr::rdata::opt::EdnsOption::Unknown(
        15, // EDE option code
        extra_bytes,
    ));
    resp.set_edns(edns);

    resp.to_vec().unwrap_or_else(|_| servfail(req))
}
