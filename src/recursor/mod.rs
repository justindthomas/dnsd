//! Query processor — the piece transports hand queries to.
//!
//! Resolution order:
//!   1. Parse the query; extract its single question.
//!   2. RRL check on the peer's /24 or /64 (silent drop on throttle).
//!   3. Local short-circuits — answered without touching upstream:
//!      * RFC 8880 ipv4only.arpa A/AAAA + 170/171.0.0.192.in-addr.arpa PTR.
//!      * DNS64 PTR: ip6.arpa under the NAT64 prefix gets rewritten
//!        to in-addr.arpa before continuing to the cache/forwarder.
//!   4. Cache lookup → on hit, rewrite TXID and return.
//!   5. Forwarder lookup:
//!      * Longest-suffix match on the question name picks the
//!        upstream list. Servers tried in order.
//!      * DNS64 post-processing: if the listener opted in and the
//!        upstream returned NODATA/NXDOMAIN for AAAA, re-query A and
//!        synthesise AAAA per RFC 6147.
//!   6. No forwarder matched → iterative recursion if enabled,
//!      otherwise SERVFAIL.
//!
//! DNSSEC policy (`pass-through` | `strip` | `validate`) is applied
//! to every outbound response. Full chain-of-trust validation needs
//! the iterative recursor; until then `validate` acts like `strip`
//! and is documented in `dnssec.rs`.

pub mod anchor;
pub mod cache;
pub mod cookies;
pub mod forwarder;
pub mod ddr;
pub mod dns64;
pub mod dot_client;
pub mod dot_pool;
pub mod dnssec;
pub mod ipv4only;
pub mod iterative;
pub mod local_zones;
pub mod normalize;
pub mod rrl;
pub mod socks;
pub mod zeroxtwenty;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_proto::serialize::binary::BinDecodable;

use crate::config::DnsConfig;
use crate::handler::{DnsHandler, ListenerContext};
use crate::metrics::Metrics;
use crate::io::transport::ReactorCtx;

pub use cache::{CacheKey, DnsCache};
pub use dns64::Dns64Policy;
pub use dnssec::DnssecPolicy;
pub use forwarder::{Forwarders, UpstreamClient};
pub use iterative::IterativeResolver;
pub use rrl::Rrl;

/// Result of `resolve_validate_cache`: either a validated answer
/// (with the parsed form retained for callers that need to inspect
/// it, e.g. the DNS64 NODATA branch), a Bogus chain that the caller
/// should hand back as-is, or a walk failure that the caller
/// converts into SERVFAIL + neg-resolve insert.
enum ResolveOutcome {
    Ok { bytes: Vec<u8>, parsed: Message },
    Bogus(Vec<u8>),
    WalkFailed,
}

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
    /// Precomputed RFC 9462 DDR answer records for
    /// `_dns.resolver.arpa` / SVCB, built once from the DoT + DoH
    /// listener sets and the TLS cert domain — one record per
    /// encrypted transport. Empty disables DDR (no encrypted
    /// listener, or no global-scope address to point clients at).
    ddr_svcb: Vec<hickory_proto::rr::rdata::svcb::SVCB>,
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
    /// Startup readiness gate. Set to `true` only after at least one
    /// of the prewarm queries successfully resolves end-to-end —
    /// proves external connectivity AND that the iterative path
    /// works AND (when validation is on) the DNSSEC validator can
    /// fetch DNSKEYs. Until then, `handle_bytes` answers REFUSED
    /// to every client query so callers fail fast and retry once
    /// dnsd is actually able to serve them, instead of timing out
    /// against a half-initialized resolver. Visible via the control
    /// socket as `stats.ready`.
    ready: Arc<std::sync::atomic::AtomicBool>,
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
        self.insert_with_ttl(name, rtype, NEG_RESOLVE_TTL);
    }

    fn insert_with_ttl(
        &self,
        name: hickory_proto::rr::Name,
        rtype: RecordType,
        ttl: Duration,
    ) {
        let key = (name.to_lowercase(), rtype);
        let expiry = Instant::now() + ttl;
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
    /// True once the startup prewarm has confirmed external
    /// resolution works. Before this, `handle_bytes` answers
    /// REFUSED so clients see a hard failure quickly instead of
    /// waiting on a partially-initialised resolver.
    pub fn is_ready(&self) -> bool {
        self.ready.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn spawn_dnssec_prewarm(&self) {
        let ready_flag = self.ready.clone();
        let iter = match self.iterative.as_ref() {
            Some(i) => i.clone(),
            None => {
                // Iterative resolver disabled in this build/config;
                // nothing to warm. Mark ready immediately so we
                // don't gate forwarder-only deployments forever.
                ready_flag.store(true, std::sync::atomic::Ordering::Release);
                return;
            }
        };
        let validator = match self.validator.as_ref() {
            Some(v) => v.clone(),
            None => {
                // DNSSEC validation off. Nothing to warm and no
                // external connectivity proof to wait on at this
                // layer; the prewarm names would still resolve but
                // there's no point spending the budget. Mark ready.
                ready_flag.store(true, std::sync::atomic::Ordering::Release);
                return;
            }
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
            // Retry loop. Each pass fires all 8 prewarm names in
            // parallel and waits for them. As soon as ANY one
            // resolves we flip `ready=true` and exit — even partial
            // upstream connectivity proves the listener path is
            // viable. If everything fails this pass, wait `backoff`
            // and retry. Without this loop, a transient upstream
            // glitch during dnsd start pins us in REFUSED-mode
            // forever; with it, we self-heal once connectivity
            // returns. No upper bound on retries: an operator
            // looking at `imp-dnsd query stats` will see
            // `ready=false` and can escalate; rather that than
            // dnsd silently starting to answer queries it can't
            // actually resolve.
            let backoff = std::time::Duration::from_secs(5);
            let mut attempt: u32 = 0;
            loop {
                attempt += 1;
                let successes =
                    Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let mut joins = Vec::with_capacity(PREWARM_NAMES.len());
                for name in PREWARM_NAMES {
                    let iter = iter.clone();
                    let validator = validator.clone();
                    let successes = successes.clone();
                    joins.push(tokio::spawn(async move {
                        let parsed = match hickory_proto::rr::Name::from_ascii(name) {
                            Ok(n) => n,
                            Err(_) => return,
                        };
                        let mut q = Message::new(0, MessageType::Query, OpCode::Query);
                        q.metadata.recursion_desired = true;
                        q.add_query(Query::query(parsed, RecordType::A));
                        let started = std::time::Instant::now();
                        match iter.resolve_with_chain(&q).await {
                            Ok((bytes, chain)) => {
                                if let Ok(resp) = Message::from_bytes(&bytes) {
                                    let mut validated = Vec::new();
                                    let _ = validator
                                        .validate_walk(&chain, &resp, &mut validated)
                                        .await;
                                    iter.cache_validated_delegations(&chain, &validated);
                                    successes
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    tracing::info!(
                                        name = %name,
                                        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                                        "prewarm sub-resolve ok"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::info!(
                                    name = %name,
                                    elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                                    "prewarm sub-resolve failed: {e:#}"
                                );
                            }
                        }
                    }));
                }
                for j in joins {
                    let _ = j.await;
                }
                let ok = successes.load(std::sync::atomic::Ordering::Relaxed);
                if ok > 0 {
                    ready_flag.store(true, std::sync::atomic::Ordering::Release);
                    tracing::info!(
                        attempt,
                        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        successes = ok,
                        total = PREWARM_NAMES.len(),
                        "DNSSEC prewarm + readiness gate passed; serving queries"
                    );
                    return;
                }
                tracing::warn!(
                    attempt,
                    elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    backoff_ms = backoff.as_millis() as u64,
                    "prewarm attempt failed (zero successes); will retry — clients REFUSED until then"
                );
                tokio::time::sleep(backoff).await;
            }
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
            // Default 600s (10 min) for the negative-TTL cap —
            // shorter than every mainstream resolver's default
            // (~1h) because for a small-operator router the
            // recursive path is the only resolver in the path
            // and a stale NXDOMAIN/NODATA strands clients until
            // the entry expires. Operators can raise this in
            // `dns.cache.max_negative_ttl` if they have a reason.
            cache_cfg.max_negative_ttl.unwrap_or(600),
        ))
    }

    pub fn build_forwarders_from_config(cfg: &DnsConfig) -> anyhow::Result<Arc<Forwarders>> {
        Forwarders::new(&cfg.forwarders).map(Arc::new)
    }

    pub async fn from_config(
        cfg: &DnsConfig,
        #[cfg(not(feature = "vcl"))] reactor: ReactorCtx,
        metrics: Arc<Metrics>,
        #[cfg(feature = "vcl")] workers: Vec<(tokio::runtime::Handle, ReactorCtx)>,
    ) -> anyhow::Result<Self> {
        let cache = Self::build_cache_from_config(cfg);
        let forwarders = Self::build_forwarders_from_config(cfg)?;
        Self::from_parts(
            cfg,
            #[cfg(not(feature = "vcl"))]
            reactor,
            metrics,
            cache,
            forwarders,
            None,
            None,
            None,
            None,
            #[cfg(feature = "vcl")]
            workers,
        )
        .await
    }

    /// Build a RecursorHandler using a pre-constructed cache +
    /// forwarder table. Used by `main.rs` to share those Arcs with
    /// the control socket. `root_hints_path`, when set, lets the
    /// iterative recursor persist the primed root set across
    /// restarts (e.g. `/persistent/data/dnsd/root-hints` on imp).
    pub async fn from_parts(
        cfg: &DnsConfig,
        #[cfg(not(feature = "vcl"))] reactor: ReactorCtx,
        metrics: Arc<Metrics>,
        cache: Arc<DnsCache>,
        forwarders: Arc<Forwarders>,
        root_hints_path: Option<std::path::PathBuf>,
        discovered_v6_source: Option<std::net::Ipv6Addr>,
        discovered_v4_source: Option<std::net::Ipv4Addr>,
        anchor_dir: Option<std::path::PathBuf>,
        #[cfg(feature = "vcl")] workers: Vec<(tokio::runtime::Handle, ReactorCtx)>,
    ) -> anyhow::Result<Self> {
        let upstream_timeout_ms = cfg
            .recursion
            .as_ref()
            .and_then(|r| r.upstream_timeout_ms);
        // Source-IP selection for outbound upstream queries.
        //
        // v4: prefer VPP-discovered globally-routable v4 (wan IP) over
        // the listener address. The earlier "listener-IP + NAT44"
        // pattern works for UDP but breaks outbound TCP — VPP's TCP
        // session table is keyed on the bound source IP, while the
        // SYN/ACK arrives with the post-NAT dst IP, so the session
        // lookup misses and the handshake never completes (the SYN/
        // ACK gets punted to Linux). Binding directly to the wan IP
        // sidesteps NAT entirely; UDP works the same way.
        //
        // v6: priority order is explicit config > VPP-discovered
        // global v6 > v6 listener address — mirroring the v4
        // priority below. The point is *egress-interface
        // consistency*: v4 upstream queries source from the wan
        // interface IP, so v6 should too. The discovered value is
        // the wan interface's global v6 (found via VPP's binary API
        // in `async_main`). A v6 listener address on an internal
        // prefix is perfectly routable for egress once BGP
        // advertises that prefix — but sourcing upstream traffic
        // from it means the two families leave via different
        // interfaces, which complicates firewall rules, return-path
        // routing, and reasoning about the system. Keep both
        // families egressing from wan; the listener address is only
        // a fallback for when VPP discovery fails entirely.
        let mut listener_v4: Option<std::net::Ipv4Addr> = None;
        let mut listener_v6: Option<std::net::Ipv6Addr> = None;
        for l in &cfg.listeners {
            match l.address {
                std::net::IpAddr::V4(v4) if listener_v4.is_none() => {
                    listener_v4 = Some(v4);
                }
                std::net::IpAddr::V6(v6) if listener_v6.is_none() => {
                    listener_v6 = Some(v6);
                }
                _ => {}
            }
        }
        let configured_v6 = cfg.recursion.as_ref().and_then(|r| r.source_v6);
        let source_v6 = configured_v6.or(discovered_v6_source).or(listener_v6);
        let source_v4 = discovered_v4_source.or(listener_v4);
        let upstream = Arc::new(
            UpstreamClient::new(
                #[cfg(not(feature = "vcl"))]
                reactor,
                upstream_timeout_ms,
                source_v4,
                source_v6,
                // tord's SOCKS5 endpoint for `via: tor` forwarders.
                // The config layer always defaults this (127.0.0.1:9050),
                // so it's always Some for a real config.
                Some(cfg.tor_socks),
                #[cfg(feature = "vcl")]
                workers,
            )
            .await
            .context("UpstreamClient::new")?,
        );

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

        // Trust anchor loading — three modes:
        //
        //   1. Operator-supplied file (`trust_anchor: /path`): use as
        //      the source of truth. Refresh writes back to the same
        //      path. State sidecar lives at `<path>.state`.
        //   2. Self-managed (`trust_anchor` unset, anchor_dir provided):
        //      look in `<data_dir>/anchor/active.key`. Empty/missing →
        //      log "needs bootstrap"; phase 5 fills in. Refresh
        //      writes here too.
        //   3. Neither: warn — validation reports Insecure.
        //
        // Anchor-load failures never fail startup; operators can fix
        // the file and SIGHUP without taking the daemon down.
        let validator = if matches!(dnssec, DnssecPolicy::Validate) {
            // Resolve the active-anchor file path that the refresh
            // task will read/write.
            let anchor_path: Option<std::path::PathBuf> = cfg
                .recursion
                .as_ref()
                .and_then(|r| r.trust_anchor.as_ref())
                .map(std::path::PathBuf::from)
                .or_else(|| anchor_dir.as_ref().map(|d| d.join("active.key")));

            let anchors = match anchor_path.as_deref() {
                Some(path) if path.exists() => {
                    match dnssec::TrustAnchors::load_from_file(path) {
                        Ok(a) if !a.is_empty() => {
                            tracing::info!(
                                path = %path.display(),
                                keys = a.len(),
                                "loaded DNSSEC trust anchors"
                            );
                            Arc::new(a)
                        }
                        Ok(_) => {
                            tracing::info!(
                                path = %path.display(),
                                "trust anchor file is empty — bootstrap needed (phase 5)"
                            );
                            Arc::new(dnssec::TrustAnchors::new())
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = %path.display(),
                                "failed to load trust anchors: {e} (validation will report Insecure)"
                            );
                            Arc::new(dnssec::TrustAnchors::new())
                        }
                    }
                }
                Some(path) => {
                    // Self-managed mode + missing file → bootstrap from
                    // the embedded IANA KSKs. This is the "fresh
                    // install" path: dnsd materialises a known-good
                    // anchor set on disk, then RFC 5011 keeps it
                    // current. No network during bootstrap; trust
                    // comes from the dnsd build chain.
                    let state_path = {
                        let mut s = path.as_os_str().to_owned();
                        s.push(".state");
                        std::path::PathBuf::from(s)
                    };
                    match anchor::bootstrap_self_managed(path, &state_path) {
                        Ok(a) => {
                            tracing::info!(
                                path = %path.display(),
                                keys = a.len(),
                                "bootstrapped trust anchor from embedded IANA KSKs"
                            );
                            Arc::new(a)
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = %path.display(),
                                "bootstrap failed: {e:#} — validation will report Insecure"
                            );
                            Arc::new(dnssec::TrustAnchors::new())
                        }
                    }
                }
                None => {
                    tracing::warn!(
                        "dnssec: validate is set but no trust_anchor path configured \
                         and no anchor_dir provided — validation will report Insecure"
                    );
                    Arc::new(dnssec::TrustAnchors::new())
                }
            };
            // Wrap in arc-swap so the RFC 5011 rotation task can
            // publish updates without rebuilding the validator.
            let anchors_swap: dnssec::TrustAnchorSwap =
                Arc::new(arc_swap::ArcSwap::new(anchors));

            // Spawn the periodic refresh task whenever we have a
            // file path to persist into — operator-supplied or self-
            // managed. State sidecar lives next to the anchor file
            // as `<anchor>.state`.
            if let Some(path) = anchor_path {
                let state_path = {
                    let mut s = path.as_os_str().to_owned();
                    s.push(".state");
                    std::path::PathBuf::from(s)
                };
                anchor::AnchorRefresh {
                    anchors: anchors_swap.clone(),
                    upstream: upstream.clone(),
                    roots: validator_roots.clone(),
                    anchor_path: path,
                    state_path,
                    interval: anchor::DEFAULT_REFRESH_INTERVAL,
                    hold_down: anchor::DEFAULT_HOLD_DOWN,
                }
                .spawn();
            }

            Some(Arc::new(dnssec::Validator::new(
                anchors_swap,
                upstream.clone(),
                validator_roots,
            )))
        } else {
            None
        };

        // RFC 9462 DDR: precompute the `_dns.resolver.arpa` SVCB
        // answers from the DoT + DoH listener sets and the TLS
        // cert's primary domain — one record per transport. Empty
        // — DDR off — when there is no encrypted listener, no cert
        // domain, or no global-scope address.
        let ddr_svcb = {
            let dot_addrs: Vec<std::net::IpAddr> = cfg
                .listeners
                .iter()
                .filter(|l| {
                    l.protocols.iter().any(|p| p.eq_ignore_ascii_case("dot"))
                })
                .map(|l| l.address)
                .collect();
            // DDR only advertises DoH endpoints a discovery client
            // can reach WITHOUT a token: the dohpath we advertise
            // carries no token, so a token-gated listener (the WAN
            // DoH endpoints) would break discovery. Drop them here.
            let doh_addrs: Vec<std::net::IpAddr> = cfg
                .listeners
                .iter()
                .filter(|l| {
                    l.protocols.iter().any(|p| p.eq_ignore_ascii_case("doh"))
                })
                .filter(|l| l.auth_token.is_none())
                .map(|l| l.address)
                .collect();
            cfg.tls
                .as_ref()
                .and_then(|t| t.acme.as_ref())
                .and_then(|a| a.domains.first())
                .and_then(|d| hickory_proto::rr::Name::from_ascii(d).ok())
                .map(|name| {
                    ddr::build_ddr_records(&name, &dot_addrs, &doh_addrs)
                })
                .unwrap_or_default()
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
            ddr_svcb,
            neg_resolve_cache: Arc::new(NegResolveCache::new()),
            in_flight: Arc::new(InFlightMap::new()),
            ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }
}

#[async_trait]
impl DnsHandler for RecursorHandler {
    fn is_ready(&self) -> bool {
        self.ready.load(std::sync::atomic::Ordering::Acquire)
    }

    async fn handle_bytes(
        &self,
        query: &[u8],
        peer: IpAddr,
        ctx: &ListenerContext,
    ) -> Option<Vec<u8>> {
        // No outer timeout wrap. A prior version wrapped this in a
        // tokio::time::timeout(QUERY_BUDGET, …) but under runtime
        // starvation that timer fired 20-40 s late — the wall-clock
        // budget became misleading rather than protective. With the
        // dedicated VCL I/O thread architecture the recursor and
        // its timers run on a runtime that's free of libvppcom
        // blocking, so an inner-walk timeout will fire on time if
        // one is needed; for now we rely on per-NS upstream timeouts
        // inside the iterative walk and on neg_resolve_cache (5 min)
        // to bound retry storms.
        self.handle_bytes_inner(query, peer, ctx).await
    }
}

impl RecursorHandler {
    async fn handle_bytes_inner(
        &self,
        query: &[u8],
        peer: IpAddr,
        ctx: &ListenerContext,
    ) -> Option<Vec<u8>> {
        // Startup readiness gate. Before the prewarm has proved we
        // can resolve at least one name, refuse all client queries
        // outright. Clients see REFUSED immediately and retry
        // (macOS resolver falls back to the next configured DNS),
        // instead of timing out at 5s on a half-initialised
        // resolver — and dnsd doesn't accumulate inflight handler
        // tasks waiting on upstream that hasn't connected yet.
        if !self.ready.load(std::sync::atomic::Ordering::Acquire) {
            return crate::handler::build_refused(query);
        }
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
                let ms = u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX);
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
        let q = msg.queries.first()?.clone();
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

        // (3a) RFC 8880 §7.2: answer ipv4only.arpa A/AAAA and the
        // matching 170/171.0.0.192.in-addr.arpa PTRs locally without
        // touching upstream. AAAA depends on whether this listener
        // has DNS64 enabled — synthesised under our prefix when it
        // is, NODATA when it isn't.
        if ipv4only::is_local_question(&q.name, q.query_type()) {
            let synth = ipv4only::synth_response(&msg, self.dns64.as_deref(), ctx.dns64);
            return synth.to_vec().ok();
        }

        // (3a′) RFC 9462 DDR: answer `_dns.resolver.arpa` locally —
        // SVCB gets the designated-resolver record, every other qtype
        // NODATA — so the name never recurses to public resolver.arpa.
        if !self.ddr_svcb.is_empty() && ddr::is_ddr_question(&q.name) {
            return ddr::synth_response(&msg, &self.ddr_svcb).to_vec().ok();
        }

        // (3b) DNS64 PTR short-circuit: rewrite the question, send it
        // off to in-addr.arpa via the normal forwarder/cache path, then
        // wrap the v4 PTR back into an ip6.arpa answer.
        if ctx.dns64 && q.query_type() == RecordType::PTR {
            if let Some(policy) = &self.dns64 {
                if let Some(new_qname) = dns64::rewrite_ptr_question(policy, &q.name) {
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
        if self.neg_resolve_cache.hit(&q.name, q.query_type()) {
            return Some(servfail(&msg));
        }
        let key = CacheKey::new(&q.name, q.query_type(), q.query_class());
        // First, the fast unguarded path: if the cache is already
        // warm we don't need to take the per-key lock.
        if let Some(cached) = self.cache.get(&key).await {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            if let Some(resp) = self
                .build_from_cache_value(&msg, &q, cached, ctx)
                .await
            {
                return Some(resp);
            }
            // Cached AAAA NODATA on a DNS64 listener but the cached
            // A is missing — fall through to a fresh resolve below.
        }
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);

        // Coalesce concurrent walks for the same (name, type). The
        // first arrival wins the per-key lock and runs the walk;
        // followers wait, then the recheck below picks up the
        // cached / negative-cached result instead of walking again.
        let coalesce_lock = self.in_flight.lock_for(&q.name, q.query_type());
        // DIAG: time spent waiting on the per-key coalesce mutex.
        // A follower behind a slow leader shows up as a large
        // coalesce_wait_ms here.
        let coalesce_t0 = Instant::now();
        let _coalesce_guard = coalesce_lock.lock().await;
        let coalesce_wait_ms = coalesce_t0.elapsed().as_millis() as u64;
        if coalesce_wait_ms >= 50 {
            tracing::debug!(
                qname = %&q.name,
                qtype = ?q.query_type(),
                coalesce_wait_ms,
                "handle: waited on in_flight coalesce lock",
            );
        }
        if let Some(cached) = self.cache.get(&key).await {
            if let Some(resp) = self
                .build_from_cache_value(&msg, &q, cached, ctx)
                .await
            {
                return Some(resp);
            }
            // Same fall-through as the pre-lock path: leader cached
            // NODATA AAAA but cached A is gone, so we have to walk.
        }
        if self.neg_resolve_cache.hit(&q.name, q.query_type()) {
            return Some(servfail(&msg));
        }

        let (forwarder_domain, servers) = match self.forwarders.lookup_with_domain(&q.name) {
            Some((domain, s)) => {
                self.metrics
                    .forwarder_matched
                    .fetch_add(1, Ordering::Relaxed);
                // Pass the full ForwarderServer specs through to
                // `query_forwarder` — it branches per server on
                // transport/via (udp/direct, dot/direct, dot/tor).
                // The domain is the SOCKS isolation username for the
                // `via: tor` path.
                (domain.to_string(), s.to_vec())
            }
            None => {
                // No forwarder match — fall through to iterative
                // recursion if enabled, otherwise SERVFAIL.
                let Some(iter) = self.iterative.as_ref() else {
                    return Some(servfail(&msg));
                };
                let (bytes, parsed) = match self
                    .resolve_validate_cache(iter, &msg)
                    .await
                {
                    ResolveOutcome::Ok { bytes, parsed } => (bytes, parsed),
                    ResolveOutcome::Bogus(servfail_bytes) => {
                        return Some(servfail_bytes);
                    }
                    ResolveOutcome::WalkFailed => {
                        self.neg_resolve_cache
                            .insert(q.name().clone(), q.query_type());
                        return Some(servfail(&msg));
                    }
                };

                // DNS64 synthesis: fires when the AAAA response is
                // empty/NXDOMAIN, the listener opted into DNS64, and
                // the name isn't on the exclusion list. We fire a
                // follow-up A query through the same validate+cache
                // helper so the cached A persists for follow-up
                // followers waking from `in_flight`. The
                // synthesised AAAA itself is NOT cached under the
                // AAAA key — DNS64 is per-listener, so cache holds
                // the canonical (NODATA) AAAA and we re-synthesise
                // for each request that needs it.
                if dns64::should_synthesise(
                    self.dns64.as_deref(),
                    ctx.dns64,
                    &q.name,
                    q.query_type(),
                    &parsed,
                ) {
                    if let Some(policy) = self.dns64.as_deref() {
                        let mut a_query = msg.clone();
                        a_query.queries.clear();
                        a_query.add_query(Query::query(
                            q.name().clone(),
                            RecordType::A,
                        ));
                        if let ResolveOutcome::Ok { parsed: a_resp, .. } =
                            self.resolve_validate_cache(iter, &a_query).await
                        {
                            if !a_resp.answers.is_empty() {
                                let mut synth = dns64::synthesise_from_a(
                                    policy, &msg, &a_resp,
                                );
                                self.metrics
                                    .dns64_synthesised
                                    .fetch_add(1, Ordering::Relaxed);
                                self.dnssec.apply_to_response(&mut synth);
                                if let Ok(synth_bytes) = synth.to_vec() {
                                    return Some(synth_bytes);
                                }
                            }
                        }
                    }
                }

                return Some(bytes);
            }
        };

        let resp_bytes = match self
            .upstream
            .query_forwarder(&servers, &forwarder_domain, query)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(qname = %&q.name, "forwarder failed: {e}");
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
            &q.name,
            q.query_type(),
            &resp,
        ) {
            if let Some(policy) = &self.dns64 {
                let mut a_query = msg.clone();
                a_query.queries.clear();
                a_query.add_query(Query::query(q.name().clone(), RecordType::A));
                let Ok(a_query_bytes) = a_query.to_vec() else {
                    // Fall through to the original AAAA response.
                    return Some(respond_with_policy(&mut resp, &self.dnssec));
                };
                match self
                    .upstream
                    .query_forwarder(&servers, &forwarder_domain, &a_query_bytes)
                    .await
                {
                    Ok(a_bytes) => {
                        if let Ok(a_resp) = Message::from_bytes(&a_bytes) {
                            if !a_resp.answers.is_empty() {
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
                        tracing::debug!(qname = %&q.name, "DNS64 A-side failed: {e}");
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
    /// Iterative resolve + DNSSEC validate + cache write. Used for
    /// the user's question AND for the follow-up A query that DNS64
    /// fires when AAAA comes back NODATA.
    ///
    /// Caching here (rather than waiting for an outer post-DNS64 cache
    /// write) is what makes `in_flight` collapsing actually pay off
    /// for AAAA queries on a DNS64 listener. With the leader caching
    /// both the validated NODATA AAAA and the validated A, every
    /// follower waking from the per-key lock hits cache, runs
    /// `synthesise_from_cached_a` for ~milliseconds, and returns
    /// without burning a fresh walk.
    ///
    /// The DNSSEC chain validator is still gated by the outer
    /// `validator` field; in PassThrough/Strip modes we apply the
    /// configured AD-bit policy instead.
    async fn resolve_validate_cache(
        &self,
        iter: &Arc<IterativeResolver>,
        msg: &Message,
    ) -> ResolveOutcome {
        let q = match msg.queries.first() {
            Some(q) => q.clone(),
            None => return ResolveOutcome::WalkFailed,
        };
        // DIAG: split the walk from DNSSEC validation. The walk's
        // own per-hop DIAG lines show it completing fast; if
        // resolve_validate_cache is nonetheless slow, the time is
        // in validate_walk (DNSKEY fetches) — measured below.
        let walk_t0 = Instant::now();
        let (bytes, walk_chain) = match iter.resolve_with_chain(msg).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(qname = %&q.name, "iterative resolve failed: {e:#}");
                return ResolveOutcome::WalkFailed;
            }
        };
        let walk_ms = walk_t0.elapsed().as_millis() as u64;
        let mut parsed = match Message::from_bytes(&bytes) {
            Ok(m) => m,
            Err(_) => {
                // Couldn't decode — return the raw bytes uncached.
                // Validator can't run on garbage, and there's nothing
                // useful to put in cache.
                return ResolveOutcome::Ok { bytes, parsed: Message::new(0, MessageType::Response, OpCode::Query) };
            }
        };

        if let Some(validator) = self.validator.as_ref() {
            let val_t0 = Instant::now();
            let mut validated_zones: Vec<hickory_proto::rr::Name> = Vec::new();
            let status = validator
                .validate_walk(&walk_chain, &parsed, &mut validated_zones)
                .await;
            let val_ms = val_t0.elapsed().as_millis() as u64;
            if walk_ms + val_ms >= 200 {
                tracing::debug!(
                    qname = %&q.name,
                    qtype = ?q.query_type(),
                    walk_ms,
                    val_ms,
                    chain_steps = walk_chain.steps.len(),
                    "resolve: walk + validate",
                );
            }
            // Cache every delegation step that verified — regardless
            // of the overall status. The signed prefix of an
            // Insecure walk (TLD + signed SLD ahead of a CNAME into
            // an unsigned CDN — the common case for real web
            // traffic) is a valid, reusable trust path; a future
            // walk for a sibling name can start there. `validated_
            // zones` lists exactly the steps that verified, so a
            // step under a Bogus point is simply absent.
            iter.cache_validated_delegations(&walk_chain, &validated_zones);
            match status {
                dnssec::ValidationStatus::Secure => {
                    self.metrics
                        .dnssec_validated
                        .fetch_add(1, Ordering::Relaxed);
                    parsed.metadata.authentic_data = true;
                }
                dnssec::ValidationStatus::Insecure => {
                    parsed.metadata.authentic_data = false;
                }
                dnssec::ValidationStatus::Bogus(reason) => {
                    self.metrics
                        .dnssec_failed
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(qname = %&q.name, "DNSSEC validation bogus: {reason}");
                    return ResolveOutcome::Bogus(servfail_with_ede(
                        msg,
                        dnssec::EDE_DNSSEC_BOGUS,
                        &reason,
                    ));
                }
            }
        } else {
            self.dnssec.apply_to_response(&mut parsed);
        }

        let final_bytes = parsed.to_vec().unwrap_or(bytes);
        let key = CacheKey::new(&q.name, q.query_type(), q.query_class());
        self.cache.put(key, &parsed, final_bytes.clone()).await;
        ResolveOutcome::Ok {
            bytes: final_bytes,
            parsed,
        }
    }

    /// Build the response from an already-fetched cache entry.
    /// Handles DNS64 synthesis (re-doing it cheaply against the
    /// cached A) and DNSSEC policy on hit.
    ///
    /// Returns:
    ///   * `Some(bytes)` — final bytes for the client.
    ///   * `None` — cache held an AAAA NODATA on a DNS64 listener
    ///     but the cached A is missing; caller falls through to a
    ///     fresh resolve.
    async fn build_from_cache_value(
        &self,
        msg: &Message,
        q: &Query,
        cached: Vec<u8>,
        ctx: &ListenerContext,
    ) -> Option<Vec<u8>> {
        let mut cached = cached;
        cache::rewrite_txid(&mut cached, msg.metadata.id);
        let Ok(mut parsed) = Message::from_bytes(&cached) else {
            return Some(cached);
        };
        if dns64::should_synthesise(
            self.dns64.as_deref(),
            ctx.dns64,
            &q.name,
            q.query_type(),
            &parsed,
        ) {
            let policy = self.dns64.as_deref()?;
            let synth = self
                .synthesise_from_cached_a(policy, msg, &q.name)
                .await?;
            self.metrics
                .dns64_synthesised
                .fetch_add(1, Ordering::Relaxed);
            return synth.to_vec().ok();
        }
        if self.validator.is_none() {
            self.dnssec.apply_to_response(&mut parsed);
        }
        Some(parsed.to_vec().unwrap_or(cached))
    }

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
            .answers
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

        let (forwarder_domain, servers) = self.forwarders.lookup_with_domain(qname)?;
        let forwarder_domain = forwarder_domain.to_string();
        let servers = servers.to_vec();
        let q_bytes = query_msg.to_vec().ok()?;
        let resp_bytes = self
            .upstream
            .query_forwarder(&servers, &forwarder_domain, &q_bytes)
            .await
            .ok()?;
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
    let mut new_msg = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    new_msg.metadata.recursion_desired = original.metadata.recursion_desired;
    new_msg.add_query(Query::query(new_name.clone(), RecordType::PTR));
    new_msg
}

fn servfail(req: &Message) -> Vec<u8> {
    let mut resp = Message::response(req.metadata.id, OpCode::Query);
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.recursion_available = false;
    resp.metadata.response_code = ResponseCode::ServFail;
    for q in &req.queries {
        resp.add_query(q.clone());
    }
    resp.to_vec().unwrap_or_else(|_| {
        let mut buf = vec![0u8; 12];
        buf[0..2].copy_from_slice(&req.metadata.id.to_be_bytes());
        buf[2] = 0x80; // QR=1
        buf[3] = 0x02; // RCODE=SERVFAIL
        buf
    })
}

/// SERVFAIL + EDNS0 Extended DNS Error (RFC 8914). Used for DNSSEC
/// Bogus so operators + curious clients can see *why* validation
/// failed instead of just "SERVFAIL, unknown reason".
fn servfail_with_ede(req: &Message, info_code: u16, extra_text: &str) -> Vec<u8> {
    let mut resp = Message::response(req.metadata.id, OpCode::Query);
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.recursion_available = false;
    resp.metadata.response_code = ResponseCode::ServFail;
    for q in &req.queries {
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
