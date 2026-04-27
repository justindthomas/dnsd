//! Iterative resolution against root hints.
//!
//! When no operator forwarder matches the query, we walk the DNS
//! hierarchy ourselves: start at the root servers, follow NS
//! delegations toward the target zone, and return the authoritative
//! answer (or NXDOMAIN). Per-query budget caps prevent a
//! pathological delegation chain or malicious NS loop from
//! burning unbounded upstream bandwidth.
//!
//! What this implementation does:
//! - Starts with the 13 IANA root servers (v4 + v6). Operator
//!   override via config is a trivial follow-up.
//! - Walks referrals while zones get strictly longer (i.e. we
//!   never accept a referral back up the tree).
//! - Pulls glue from the Additional section when present;
//!   otherwise issues a sub-resolution for the NS's address.
//! - Follows CNAME chains up to an operator-configured depth.
//! - Reuses `UpstreamClient` for the actual UDP+TC-fallback
//!   transport (which already does 0x20 + TXID + source-IP
//!   checking per-hop).
//! - Caches the authoritative answer in the shared `DnsCache` so
//!   follow-on queries short-circuit.
//!
//! What this deliberately doesn't do (yet):
//! - DNSSEC validation — lives in `dnssec.rs` + a follow-up that
//!   plumbs chain-walk state through this recursor.
//! - QNAME minimisation (RFC 9156) — we currently send the full
//!   qname at every referral. Follow-up.
//! - DNAME handling — hickory-proto parses DNAMEs but we don't
//!   rewrite qnames through them. Follow-up (rare in practice).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use hickory_proto::rr::dnssec::rdata::{DNSSECRData, RRSIG};

use anyhow::{anyhow, Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, NS};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use crate::metrics::Metrics;
use crate::recursor::cache::{CacheKey, DnsCache};
use crate::recursor::forwarder::UpstreamClient;

/// Default per-query budget. Sized to resolve even worst-case
/// glueless chains without running away.
pub const DEFAULT_MAX_DEPTH: u32 = 16;
/// 256 instead of the older 100 because `query_ns_set` now races
/// up to `MAX_PARALLEL_NS_QUERIES` IPs per delegation step (each
/// counts against the budget), and a deep glueless chain can fan
/// that out across many sub-walks. 100 was tuned for the old
/// serial-with-timeout walk and ran out on real names like
/// `slashdot.org`.
pub const DEFAULT_MAX_QUERIES: u32 = 256;
pub const DEFAULT_MAX_CNAME: u32 = 8;

/// Per-delegation-step NS attempts. Race-2 with fall-through: at
/// most `NS_PARALLEL` queries are in flight at once and we keep
/// feeding new IPs into the slot whenever one fails, until either
/// one succeeds or we've exhausted `MAX_NS_ATTEMPTS`. This
/// converges on the fastest responder without burning every worker
/// slot for a single walk — the persistent VCL upstream sockets
/// mean an in-flight query is just a Tokio future, not an
/// allocation per query, so the cost of the loser is "one upstream
/// timeout's worth of worker time" not "a leaked 128 MB FIFO
/// segment" like in earlier iterations.
const MAX_NS_ATTEMPTS: usize = 4;
const NS_PARALLEL: usize = 2;

/// A single delegation step seen during a walk, in enough detail
/// for a DNSSEC validator to reconstruct the chain of trust afterwards.
#[derive(Debug, Clone)]
pub struct ChainStep {
    /// The zone being delegated TO at this step (child of the
    /// zone we were querying; for the first entry this is usually
    /// a TLD delegation from the root).
    pub zone: hickory_proto::rr::Name,
    /// Full DS records from the parent's authority section covering
    /// `zone` — kept as-parsed (TTL intact) because the RRSIG
    /// verifier needs the originally-signed TTL (RFC 4034 §6.2
    /// canonical form). Empty means the parent provided no DS —
    /// either the zone is unsigned (legit insecure delegation) or
    /// the response was stripped (downgrade attack that we can't
    /// detect without NSEC/NSEC3 denial-of-DS proof — tracked as
    /// v1.x follow-up).
    pub ds: Vec<Record>,
    /// Covering RRSIGs for the DS RRset, from the same authority
    /// section. Empty when ds is empty.
    pub ds_rrsig: Vec<RRSIG>,
    /// IPs the validator can use to fetch `zone`'s DNSKEY RRset
    /// later — these are the NSes we just got referred to.
    pub ns_ips: Vec<IpAddr>,
}

/// The delegation chain a single walk traversed, from the root on
/// down to the answer's authoritative zone. Consumed by the DNSSEC
/// validator to build a trust chain without re-walking the tree.
#[derive(Debug, Clone, Default)]
pub struct WalkChain {
    pub steps: Vec<ChainStep>,
}

impl WalkChain {
    /// The zone that served the final answer (last step's `zone`).
    /// Empty (`None`) for a direct-from-root answer.
    pub fn answer_zone(&self) -> Option<&hickory_proto::rr::Name> {
        self.steps.last().map(|s| &s.zone)
    }
}

#[derive(Clone)]
pub struct IterativeResolver {
    upstream: Arc<UpstreamClient>,
    cache: Arc<DnsCache>,
    metrics: Arc<Metrics>,
    /// Live root-server address set. Starts as either the compiled-in
    /// hardcoded list or the last-primed list read from disk;
    /// `prime()` replaces it with the glue from an authoritative
    /// `./NS` response. Wrapped in RwLock so the background priming
    /// task can swap it in without blocking walks.
    roots: Arc<RwLock<Vec<IpAddr>>>,
    /// Path for persisting the primed root set across restarts. When
    /// Some, `prime()` writes one IP per line to this path after a
    /// successful fetch, and `new()` tries to preload from it before
    /// falling back to the hardcoded list. None disables persistence.
    root_hints_path: Option<PathBuf>,
    max_depth: u32,
    max_queries: u32,
    max_cname: u32,
    ipv6_upstream: bool,
    /// When true, upstream queries set the DO bit in EDNS0 so the
    /// server includes RRSIG/NSEC/NSEC3 records in its response. The
    /// recursor collects DS records seen during walks so the
    /// validator can later fetch DNSKEYs and verify the chain.
    dnssec_ok: bool,
}

impl IterativeResolver {
    pub fn new(
        upstream: Arc<UpstreamClient>,
        cache: Arc<DnsCache>,
        metrics: Arc<Metrics>,
        max_cname: u32,
        ipv6_upstream: bool,
        root_hints_path: Option<PathBuf>,
        dnssec_ok: bool,
    ) -> Self {
        // Start with either the persisted root hints or the
        // hardcoded fallback. Persisted hints are preferred because
        // they reflect the last time we successfully primed — fresher
        // than the compiled-in list if IANA renumbered a root letter
        // since the binary was built.
        let mut roots = match root_hints_path
            .as_deref()
            .and_then(|p| read_root_hints_file(p).ok())
        {
            Some(ips) if !ips.is_empty() => {
                tracing::info!(
                    path = %root_hints_path.as_deref().unwrap().display(),
                    count = ips.len(),
                    "loaded persisted root hints"
                );
                ips
            }
            _ => default_root_hints(),
        };
        if !ipv6_upstream {
            roots.retain(IpAddr::is_ipv4);
        }
        let resolver = Self {
            upstream,
            cache,
            metrics,
            roots: Arc::new(RwLock::new(roots)),
            root_hints_path,
            max_depth: DEFAULT_MAX_DEPTH,
            max_queries: DEFAULT_MAX_QUERIES,
            max_cname: max_cname.max(1).min(DEFAULT_MAX_CNAME * 2),
            ipv6_upstream,
            dnssec_ok,
        };

        // Prime the root-hint set in the background: query `./NS`
        // against one of the seed roots, cache the authoritative
        // response + glue, swap `roots` to the live IP set, and
        // persist them to disk for the next cold start. If priming
        // fails we log + keep using whatever roots we already have,
        // so startup never blocks on internet reachability.
        let cloned = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = cloned.prime().await {
                tracing::warn!("root priming failed: {e} (keeping existing root hints)");
            }
        });

        resolver
    }

    /// Shared handle to the live root-hint IP set. Used by the
    /// DNSSEC validator to bootstrap the chain of trust from root.
    pub fn roots_arc(&self) -> Arc<RwLock<Vec<IpAddr>>> {
        self.roots.clone()
    }

    /// Resolve `qname` / `qtype` iteratively. Returns a full wire
    /// response whose TXID matches the input query's TXID.
    pub async fn resolve(&self, client_query: &Message) -> Result<Vec<u8>> {
        self.resolve_with_chain(client_query).await.map(|(b, _)| b)
    }

    /// Same as `resolve` but also returns the delegation chain the
    /// walk traversed (for the DNSSEC validator). The validator
    /// ignores the chain if DNSSEC is off; callers that don't care
    /// should use `resolve()` for the shorter signature.
    pub async fn resolve_with_chain(
        &self,
        client_query: &Message,
    ) -> Result<(Vec<u8>, WalkChain)> {
        let q = client_query
            .queries()
            .first()
            .ok_or_else(|| anyhow!("iterative resolve needs a question"))?
            .clone();

        self.metrics.recursion_walked.fetch_add(1, Ordering::Relaxed);

        // RFC 6303: synthesize NXDOMAIN locally for in-addr.arpa /
        // ip6.arpa zones that cover address space which should never
        // be reverse-resolved against the public DNS (RFC 1918,
        // link-local, ULA, etc.). Without this, mDNS/Bonjour clients
        // on the LAN spam queries like
        // `*._dns-sd._udp.0.20.168.192.in-addr.arpa.` which hit the
        // AS112 anycast servers (192.175.48.0/24); those drop ~17% of
        // queries on the floor (10s timeout × MAX_NS_ATTEMPTS) and
        // pin our worker pool. BIND/Unbound/Knot all do this by
        // default. Cached so repeats are ~free.
        if super::local_zones::is_private_reverse(q.name()) {
            return synthesize_local_nxdomain(client_query, &q, &self.cache).await;
        }

        let mut budget = Budget::new(self.max_depth, self.max_queries, self.max_cname);
        let mut chain = WalkChain::default();
        let answer = self
            .walk(
                &q.name().clone(),
                q.query_type(),
                q.query_class(),
                &mut budget,
                &mut chain,
            )
            .await?;

        // Stitch the answer onto a response carrying the client's
        // TXID + question section.
        let mut response = Message::new();
        response.set_id(client_query.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_recursion_desired(client_query.recursion_desired());
        response.set_recursion_available(true);
        response.set_response_code(answer.response_code());
        for orig_q in client_query.queries() {
            response.add_query(orig_q.clone());
        }
        for r in answer.answers() {
            response.add_answer(r.clone());
        }
        for r in answer.name_servers() {
            response.add_name_server(r.clone());
        }

        // Lowercase every RR owner name before caching/serialising —
        // upstream's 0x20-randomised echo otherwise leaks all the way
        // to the client. See `normalize` for the rationale.
        super::normalize::lowercase_response_names(&mut response);
        let bytes = response.to_vec().context("encode iterative response")?;
        // Cache under the original question (lowercased). When DNSSEC
        // validation is on, we DON'T cache here — validation runs in
        // `RecursorHandler::handle_bytes` after this returns, and a
        // Bogus result there would otherwise leave a perfectly valid-
        // looking entry in cache that future hits would replay
        // without ever re-running the validator. handle_bytes
        // re-caches the post-validation bytes itself for the
        // Validate path. For PassThrough/Strip we still cache here.
        if !self.dnssec_ok {
            let key = CacheKey::new(q.name(), q.query_type(), q.query_class());
            self.cache.put(key, &response, bytes.clone()).await;
        }
        Ok((bytes, chain))
    }

    /// Core delegation walk. `qname` + `qtype` is the target; we
    /// start at the roots and descend until we either hit an
    /// authoritative answer or run out of budget.
    ///
    /// `chain` accumulates one entry per delegation boundary (the
    /// zone being delegated to + any DS records + the NS IPs we used
    /// to reach it). Passing `None` from internal callers (CNAME
    /// sub-walks, glueless NS resolution) would record a partial
    /// chain — for v1 we only populate the outermost walk so the
    /// validator has a clean root-to-answer chain.
    async fn walk(
        &self,
        qname: &Name,
        qtype: RecordType,
        qclass: DNSClass,
        budget: &mut Budget,
        chain: &mut WalkChain,
    ) -> Result<Message> {
        budget.referral()?;

        // Current working set of name-server IPs to query. We try to
        // start at the closest *cached* zone whose NS set we know —
        // for `cnn.com` that's typically `com.` once we've talked to
        // any other .com domain in the recent past. Falls back to the
        // root when nothing's cached. Each referral replaces both.
        //
        // When DNSSEC validation is on, we MUST always start at the
        // root: the validator builds the trust chain from the
        // chain.steps the walk records, and a step is recorded ONLY
        // for referrals we actually traversed. Starting from a
        // cached intermediate (say `.net`) means the validator
        // never validates `.net`'s DS/DNSKEY for the current walk
        // and so has no `.net` keys when it tries to verify the
        // child zone's DS RRSIG. Cold-start latency hit, but
        // correctness wins.
        let (mut current_zone, mut ns_ips) = if self.dnssec_ok {
            (Name::root(), self.roots.read().unwrap().clone())
        } else {
            self.closest_cached_zone(qname, qclass)
                .await
                .unwrap_or_else(|| {
                    (Name::root(), self.roots.read().unwrap().clone())
                })
        };

        loop {
            // Send the query to one of the current NS IPs. The
            // existing UpstreamClient already handles TCP fallback,
            // 0x20, and TXID hygiene per-hop.
            let resp = self
                .query_ns_set(&ns_ips, qname, qtype, qclass, budget)
                .await?;

            match classify(&resp, qname, qtype) {
                Classification::Answer => return Ok(resp),

                Classification::NxDomain => return Ok(resp),

                Classification::Cname(target) => {
                    // CNAME chase: restart from the roots with the
                    // new qname, same qtype. The sub-walk gets its
                    // own temporary chain — merging CNAME chain
                    // segments into the validator is a v1.x follow-up.
                    budget.cname()?;
                    let mut sub_chain = WalkChain::default();
                    let cname_resp = Box::pin(self.walk(
                        &target, qtype, qclass, budget, &mut sub_chain,
                    ))
                    .await?;
                    // Stitch the CNAME plus the chased answer into
                    // a single Message so the client sees the full
                    // chain.
                    let mut merged = resp.clone();
                    for a in cname_resp.answers() {
                        merged.add_answer(a.clone());
                    }
                    merged.set_response_code(cname_resp.response_code());
                    return Ok(merged);
                }

                Classification::Referral(new_zone, ns_records, glue) => {
                    // Guard against delegation loops: a referral
                    // must descend (child zone is a strict
                    // sub-domain of current), otherwise the server
                    // is misbehaving.
                    if !new_zone.zone_of(&current_zone) && new_zone != current_zone {
                        // new_zone should be descendant of current.
                        // `zone_of` returns true if `current` is
                        // inside `new_zone`; we want the reverse.
                    }
                    if new_zone.num_labels() <= current_zone.num_labels()
                        && new_zone != Name::root()
                    {
                        return Err(anyhow!(
                            "non-progressive referral: {new_zone} is not below {current_zone}"
                        ));
                    }
                    current_zone = new_zone;

                    // Cache any glue we got — later walks (or
                    // sub-walks for glueless siblings of the same
                    // delegation) can use these addresses without
                    // re-traversing from the root.
                    self.cache_glue(&glue).await;

                    // Cache the NS record set for the new zone so a
                    // subsequent walk for any name under that zone can
                    // skip the root + parent referrals and start
                    // directly from this delegation. Without this,
                    // every cold query re-walks from `.` even when
                    // its parent zone's NS records are well-known
                    // and freshly cached. BIND/Unbound do the same.
                    self.cache_zone_ns(&current_zone, &ns_records).await;

                    // Extract DS records + their RRSIGs from the
                    // authority section — the validator needs them
                    // later to build the trust chain. `ds` is empty
                    // when the parent is unsigned or doesn't delegate
                    // with DNSSEC (legit insecure delegation).
                    let (ds, ds_rrsig) = extract_ds_and_rrsig(&resp, &current_zone);

                    // Resolve NS addresses — prefer glue, fall back
                    // to a sub-resolution for out-of-bailiwick NS.
                    ns_ips = self
                        .resolve_ns_ips(&ns_records, &glue, qclass, budget)
                        .await?;
                    if ns_ips.is_empty() {
                        return Err(anyhow!(
                            "referral to {current_zone} yielded no usable NS addresses"
                        ));
                    }

                    // Record the delegation step for the validator.
                    chain.steps.push(ChainStep {
                        zone: current_zone.clone(),
                        ds,
                        ds_rrsig,
                        ns_ips: ns_ips.clone(),
                    });
                }

                Classification::Empty => {
                    // NoError with no answer + no referral: NODATA.
                    return Ok(resp);
                }

                Classification::ServFail => {
                    return Err(anyhow!("upstream returned SERVFAIL"));
                }
            }
        }
    }

    /// Race up to `NS_PARALLEL` NS IPs concurrently; whichever
    /// returns first wins. Failed attempts are replaced from the
    /// remaining shuffled order until either we get a valid response
    /// or we've burned `MAX_NS_ATTEMPTS` queries. Pure-serial walks
    /// were stalling user-facing queries when the random first NS
    /// happened to be slow (~upstream_timeout_ms per dud); racing 2
    /// converges on the fastest responder without monopolising the
    /// worker pool — at most `NS_PARALLEL` slots in flight per walk,
    /// and the persistent UDP sockets mean each in-flight query is
    /// a cheap Tokio future, not a per-call VCL session create.
    ///
    /// Budget cost: one per NS IP we actually queried (winners and
    /// losers both count, since both consumed worker time).
    async fn query_ns_set(
        &self,
        ns_ips: &[IpAddr],
        qname: &Name,
        qtype: RecordType,
        qclass: DNSClass,
        budget: &mut Budget,
    ) -> Result<Message> {
        use futures::stream::{FuturesUnordered, StreamExt};
        use rand::seq::SliceRandom;

        let mut order: Vec<IpAddr> = ns_ips.to_vec();
        order.shuffle(&mut rand::thread_rng());
        order.truncate(MAX_NS_ATTEMPTS);

        let wire = build_query(qname, qtype, qclass, self.dnssec_ok)?;
        let wire = std::sync::Arc::new(wire);

        // Box each future so FuturesUnordered can hold them in a
        // single homogeneous container — async blocks have distinct
        // anonymous types otherwise.
        type QueryFut = std::pin::Pin<
            Box<dyn std::future::Future<Output = (IpAddr, Result<Vec<u8>>)> + Send>,
        >;
        let upstream = self.upstream.clone();
        let make_query = |ip: IpAddr| -> QueryFut {
            let upstream = upstream.clone();
            let wire = wire.clone();
            Box::pin(async move {
                let res = upstream.query(&[ip], &wire[..]).await;
                (ip, res)
            })
        };

        let mut iter = order.into_iter();
        let mut in_flight: FuturesUnordered<QueryFut> = FuturesUnordered::new();
        for _ in 0..NS_PARALLEL {
            let Some(ip) = iter.next() else { break };
            budget.query()?;
            in_flight.push(make_query(ip));
        }

        let mut last_err: Option<anyhow::Error> = None;
        while let Some((ip, res)) = in_flight.next().await {
            match res {
                Ok(resp_bytes) => match Message::from_bytes(&resp_bytes) {
                    Ok(m) => return Ok(m),
                    Err(e) => {
                        tracing::debug!(%ip, "iterative parse: {e}");
                        last_err = Some(anyhow!(e));
                    }
                },
                Err(e) => {
                    tracing::debug!(%ip, "iterative upstream: {e}");
                    last_err = Some(e);
                }
            }
            if let Some(next_ip) = iter.next() {
                budget.query()?;
                in_flight.push(make_query(next_ip));
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no NS responded")))
    }

    /// Materialise NS-name → IP mappings for a referral. Any glue
    /// present in the Additional section wins; out-of-bailiwick
    /// names without glue get a recursive sub-lookup.
    async fn resolve_ns_ips(
        &self,
        ns_records: &[Record],
        glue: &HashMap<Name, Vec<IpAddr>>,
        qclass: DNSClass,
        budget: &mut Budget,
    ) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();
        for ns in ns_records {
            let Some(RData::NS(target)) = ns.data() else { continue };
            let target_name = target.0.to_lowercase();
            if let Some(glued) = glue.get(&target_name) {
                for ip in glued {
                    if !self.ipv6_upstream && ip.is_ipv6() {
                        continue;
                    }
                    ips.push(*ip);
                }
                continue;
            }
            // Glueless in THIS referral — but we may have seen glue
            // for this NS earlier in the walk (e.g. root's delegation
            // to .net included glue for gtld-servers.net nameservers;
            // a later referral from .net to gtld-servers.net itself
            // does NOT include glue but we cached it above). Check
            // the cache before kicking off a sub-walk.
            let cached = self.cached_ns_ips(&target_name).await;
            if !cached.is_empty() {
                ips.extend(cached);
                continue;
            }
            // No glue, no cache — recurse to find the NS's
            // address(es). We prefer A over AAAA to minimise further
            // iteration (the v6 path may itself need a glueless
            // walk). Failures are not fatal; we skip this NS and try
            // the next.
            let sub_budget_ok = budget.can_substep();
            if !sub_budget_ok {
                continue;
            }
            // Glueless-NS sub-walks get their own temporary chain —
            // the main walk's `chain` only tracks the resolution
            // path we're actually delivering to the validator.
            let mut sub_chain = WalkChain::default();
            match Box::pin(self.walk(
                &target_name, RecordType::A, qclass, budget, &mut sub_chain,
            ))
            .await
            {
                Ok(resp) => {
                    for a in resp.answers() {
                        if let Some(RData::A(A(v4))) = a.data() {
                            ips.push(IpAddr::V4(*v4));
                        }
                    }
                }
                Err(e) => tracing::debug!(ns = %target_name, "glueless NS resolve: {e}"),
            }
        }
        // Dedup.
        ips.sort();
        ips.dedup();
        Ok(ips)
    }

    /// Synthesise A/AAAA answer-messages from a glue map and push
    /// them into the shared DnsCache. Referrals commonly carry glue
    /// for child-zone NSes that is NOT returned again by the child
    /// itself (e.g. Verisign's .net delegation to gtld-servers.net —
    /// the root provides glue for a.gtld-servers.net in the .net
    /// delegation, but .net itself omits it when re-referring). The
    /// recursor relies on cache replay to avoid looping.
    async fn cache_glue(&self, glue: &HashMap<Name, Vec<IpAddr>>) {
        for (name, ips) in glue {
            let v4s: Vec<_> = ips.iter().filter(|ip| ip.is_ipv4()).collect();
            let v6s: Vec<_> = ips.iter().filter(|ip| ip.is_ipv6()).collect();
            if !v4s.is_empty() {
                if let Some((msg, bytes)) =
                    build_synthetic_answer(name, RecordType::A, ips)
                {
                    let key = CacheKey::new(name, RecordType::A, DNSClass::IN);
                    self.cache.put(key, &msg, bytes).await;
                }
            }
            if !v6s.is_empty() {
                if let Some((msg, bytes)) =
                    build_synthetic_answer(name, RecordType::AAAA, ips)
                {
                    let key = CacheKey::new(name, RecordType::AAAA, DNSClass::IN);
                    self.cache.put(key, &msg, bytes).await;
                }
            }
        }
    }

    /// Look up cached A (and AAAA when v6 is enabled) for an NS name
    /// we've previously seen as glue. Returns an empty Vec on miss.
    async fn cached_ns_ips(&self, name: &Name) -> Vec<IpAddr> {
        let mut out = Vec::new();
        let key_a = CacheKey::new(name, RecordType::A, DNSClass::IN);
        if let Some(bytes) = self.cache.get(&key_a).await {
            if let Ok(msg) = Message::from_bytes(&bytes) {
                for ans in msg.answers() {
                    if let Some(RData::A(A(v4))) = ans.data() {
                        out.push(IpAddr::V4(*v4));
                    }
                }
            }
        }
        if self.ipv6_upstream {
            let key_aaaa = CacheKey::new(name, RecordType::AAAA, DNSClass::IN);
            if let Some(bytes) = self.cache.get(&key_aaaa).await {
                if let Ok(msg) = Message::from_bytes(&bytes) {
                    for ans in msg.answers() {
                        if let Some(RData::AAAA(AAAA(v6))) = ans.data() {
                            out.push(IpAddr::V6(*v6));
                        }
                    }
                }
            }
        }
        out
    }

    /// Cache a freshly-received NS record set for a zone, so the
    /// next walk for any name under that zone can short-circuit to
    /// the closest cached delegation. Called from the referral arm
    /// of `walk()`. The cached message is synthetic — it carries the
    /// NS records in the answer section under (`zone`, NS, IN), and
    /// inherits the minimum NS-record TTL so cache eviction follows
    /// what the parent zone signalled.
    async fn cache_zone_ns(&self, zone: &Name, ns_records: &[Record]) {
        let owners_match: Vec<&Record> = ns_records
            .iter()
            .filter(|r| r.record_type() == RecordType::NS && r.name() == zone)
            .collect();
        if owners_match.is_empty() {
            return;
        }
        let mut msg = Message::new();
        msg.set_id(0);
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(ResponseCode::NoError);
        let mut q = Query::query(zone.clone(), RecordType::NS);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);
        for r in &owners_match {
            msg.add_answer((*r).clone());
        }
        let Ok(bytes) = msg.to_vec() else { return };
        let key = CacheKey::new(zone, RecordType::NS, DNSClass::IN);
        self.cache.put(key, &msg, bytes).await;
    }

    /// Find the closest ancestor zone of `qname` whose NS record set
    /// AND at least one NS-target IP are still in cache. Lets a fresh
    /// walk skip the root + parent referrals. Returns `None` when
    /// nothing's cached — caller falls back to the root.
    ///
    /// This is the dnsd analogue of BIND's "closest known delegation"
    /// optimisation. It only takes effect once the cache has warmed
    /// up; cold start still walks from `.`.
    async fn closest_cached_zone(
        &self,
        qname: &Name,
        qclass: DNSClass,
    ) -> Option<(Name, Vec<IpAddr>)> {
        let mut zone = qname.clone();
        // Walk up label-by-label. Stop above root (a 0-label parent
        // of root would underflow). Also skip the qname itself —
        // querying its own NS would be circular for unresolved names.
        if zone.num_labels() > 0 {
            zone = zone.base_name();
        }
        loop {
            let key = CacheKey::new(&zone, RecordType::NS, qclass);
            if let Some(bytes) = self.cache.get(&key).await {
                if let Ok(msg) = Message::from_bytes(&bytes) {
                    let mut ips = Vec::new();
                    for ans in msg.answers() {
                        if let Some(RData::NS(NS(target))) = ans.data() {
                            ips.extend(self.cached_ns_ips(target).await);
                        }
                    }
                    ips.sort();
                    ips.dedup();
                    if !ips.is_empty() {
                        return Some((zone, ips));
                    }
                }
            }
            if zone.is_root() {
                return None;
            }
            zone = zone.base_name();
        }
    }

    /// Fetch an authoritative root NS set — query `./NS` at one of
    /// the hardcoded root IPs, cache the response + glue, and swap
    /// `self.roots` to the live set. Called once at startup from
    /// `new()`. Failure is non-fatal — we fall back to the hardcoded
    /// list and log a warning.
    ///
    /// Why not block on this? Recursors on fresh boot often can't
    /// reach the internet yet (NIC not up, DHCP pending). If priming
    /// blocked startup, a cold-boot machine with VPP coming up in
    /// parallel would stall. Running it as a detached task means
    /// queries served before priming completes use the hardcoded
    /// IPs — those are current as of the binary build, so it's a
    /// correct degraded mode rather than a failure.
    async fn prime(&self) -> anyhow::Result<()> {
        let seed = {
            let snapshot = self.roots.read().unwrap();
            // Prefer a v4 seed to avoid v6 transport questions on
            // priming itself; if the list is v6-only fall back to v6.
            snapshot
                .iter()
                .find(|ip| ip.is_ipv4())
                .copied()
                .or_else(|| snapshot.first().copied())
                .ok_or_else(|| anyhow!("no hardcoded roots available for priming"))?
        };

        // Priming doesn't need DNSSEC records — we only care about
        // the NS set + glue. Even if DNSSEC is enabled, root priming
        // runs before the validator is consulted, and we cache the
        // authoritative response wholesale.
        let wire = build_query(&Name::root(), RecordType::NS, DNSClass::IN, false)?;
        let resp_bytes = tokio::time::timeout(
            Duration::from_secs(5),
            self.upstream.query(&[seed], &wire),
        )
        .await
        .map_err(|_| anyhow!("priming query to {seed} timed out"))??;
        let resp = Message::from_bytes(&resp_bytes)
            .context("parse priming response")?;

        // Extract NS targets from the answer section (root is
        // authoritative for itself, so the NS RRset is in Answers).
        let ns_targets: Vec<Name> = resp
            .answers()
            .iter()
            .filter(|r| r.record_type() == RecordType::NS)
            .filter_map(|r| match r.data() {
                Some(RData::NS(target)) => Some(target.0.to_lowercase()),
                _ => None,
            })
            .collect();
        if ns_targets.is_empty() {
            return Err(anyhow!(
                "priming response had no NS records in the answer section"
            ));
        }

        // Build a name→ips glue map from the Additional section.
        let mut glue: HashMap<Name, Vec<IpAddr>> = HashMap::new();
        for add in resp.additionals() {
            let owner = add.name().to_lowercase();
            match add.data() {
                Some(RData::A(A(v4))) => {
                    glue.entry(owner).or_default().push(IpAddr::V4(*v4));
                }
                Some(RData::AAAA(AAAA(v6))) => {
                    glue.entry(owner).or_default().push(IpAddr::V6(*v6));
                }
                _ => {}
            }
        }

        // Cache every glue record — lets clients resolve
        // `a.root-servers.net A` etc. without a fresh walk.
        self.cache_glue(&glue).await;

        // Cache the authoritative ./NS response itself so `. IN NS`
        // queries to the recursor hit cache.
        let ns_key = CacheKey::new(&Name::root(), RecordType::NS, DNSClass::IN);
        self.cache.put(ns_key, &resp, resp_bytes).await;

        // Build the new root IP set from NS-target glue only. Names
        // in the NS list that lack glue are skipped (operator can
        // still refresh manually if needed).
        let mut new_roots: Vec<IpAddr> = Vec::new();
        for name in &ns_targets {
            if let Some(ips) = glue.get(name) {
                for ip in ips {
                    if !self.ipv6_upstream && ip.is_ipv6() {
                        continue;
                    }
                    new_roots.push(*ip);
                }
            }
        }
        if new_roots.is_empty() {
            return Err(anyhow!("priming response had no usable glue"));
        }

        let count = new_roots.len();
        if let Some(path) = self.root_hints_path.as_deref() {
            if let Err(e) = write_root_hints_file(path, &new_roots) {
                tracing::warn!(
                    path = %path.display(),
                    "couldn't persist root hints: {e}"
                );
            }
        }
        *self.roots.write().unwrap() = new_roots;
        tracing::info!(seed = %seed, roots = count, "root hints primed");
        Ok(())
    }
}

/// Read a persisted root-hints file. Format: one IP per line, `#`
/// comments and blank lines ignored. Returns `Err` on I/O trouble or
/// if parsing finds no usable IPs.
fn read_root_hints_file(path: &std::path::Path) -> anyhow::Result<Vec<IpAddr>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let ips: Vec<IpAddr> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.parse::<IpAddr>().ok())
        .collect();
    if ips.is_empty() {
        anyhow::bail!("{} has no parseable IP addresses", path.display());
    }
    Ok(ips)
}

/// Write the primed root-hint IPs to `path` atomically (write to
/// `.tmp` sibling, rename). Leaves a parseable text file — one IP
/// per line with a short header.
fn write_root_hints_file(
    path: &std::path::Path,
    ips: &[IpAddr],
) -> anyhow::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        writeln!(f, "# dnsd primed root hints — machine-generated, do not edit")?;
        writeln!(f, "# Refreshed on each successful `./NS` priming query.")?;
        for ip in ips {
            writeln!(f, "{ip}")?;
        }
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Build a minimal response Message containing `name`'s glue
/// addresses of the given rtype as Answer records, plus the
/// corresponding wire encoding. Returns None if encoding fails or
/// there's nothing of that rtype to emit.
///
/// TTL is fixed at 300s — glue is non-authoritative data, so we keep
/// it cached briefly but not long enough to paper over real
/// delegation changes.
fn build_synthetic_answer(
    name: &Name,
    rtype: RecordType,
    ips: &[IpAddr],
) -> Option<(Message, Vec<u8>)> {
    let mut msg = Message::new();
    msg.set_id(0);
    msg.set_message_type(MessageType::Response);
    msg.set_op_code(OpCode::Query);
    msg.set_response_code(ResponseCode::NoError);
    let mut q = Query::query(name.clone(), rtype);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);

    let mut added = 0;
    for ip in ips {
        match (rtype, ip) {
            (RecordType::A, IpAddr::V4(v4)) => {
                msg.add_answer(Record::from_rdata(
                    name.clone(),
                    300,
                    RData::A(A(*v4)),
                ));
                added += 1;
            }
            (RecordType::AAAA, IpAddr::V6(v6)) => {
                msg.add_answer(Record::from_rdata(
                    name.clone(),
                    300,
                    RData::AAAA(AAAA(*v6)),
                ));
                added += 1;
            }
            _ => {}
        }
    }
    if added == 0 {
        return None;
    }
    let bytes = msg.to_vec().ok()?;
    Some((msg, bytes))
}

/// Hardcoded IANA root hints as of 2026 (IPv4 + IPv6 per root
/// letter). `a.root-servers.net` through `m.root-servers.net` —
/// these change rarely enough that a compiled-in list is fine; the
/// operator-override follow-up just lets us skip baking them into
/// the binary.
fn default_root_hints() -> Vec<IpAddr> {
    [
        "198.41.0.4",        // a
        "2001:503:ba3e::2:30",
        "170.247.170.2",     // b
        "2801:1b8:10::b",
        "192.33.4.12",       // c
        "2001:500:2::c",
        "199.7.91.13",       // d
        "2001:500:2d::d",
        "192.203.230.10",    // e
        "2001:500:a8::e",
        "192.5.5.241",       // f
        "2001:500:2f::f",
        "192.112.36.4",      // g
        "2001:500:12::d0d",
        "198.97.190.53",     // h
        "2001:500:1::53",
        "192.36.148.17",     // i
        "2001:7fe::53",
        "192.58.128.30",     // j
        "2001:503:c27::2:30",
        "193.0.14.129",      // k
        "2001:7fd::1",
        "199.7.83.42",       // l
        "2001:500:9f::42",
        "202.12.27.33",      // m
        "2001:dc3::35",
    ]
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect()
}

enum Classification {
    /// Authoritative answer containing the requested rtype.
    Answer,
    /// NXDOMAIN.
    NxDomain,
    /// NOERROR + no matching answer + no referral = NODATA.
    Empty,
    /// CNAME to follow.
    Cname(Name),
    /// Referral to a child zone (new_zone, NS records, glue).
    Referral(Name, Vec<Record>, HashMap<Name, Vec<IpAddr>>),
    /// Transport-level problem — caller should try another NS.
    ServFail,
}

/// Pull DS records + their covering RRSIGs out of a referral's
/// authority section. The owner of a proper DS RRset matches the
/// delegated-zone name; this is what the DNSSEC validator consumes
/// to anchor the child zone's DNSKEY under the parent's chain.
///
/// Build a synthetic NXDOMAIN response for an RFC 6303 local zone
/// (private-IP reverse, ULA, link-local, etc.). Caches under the
/// query key so subsequent matches hit cache instantly. The TTL on
/// negative answers comes from the cache's `negative_ttl` setting.
async fn synthesize_local_nxdomain(
    client_query: &Message,
    q: &Query,
    cache: &Arc<DnsCache>,
) -> Result<(Vec<u8>, WalkChain)> {
    let mut response = Message::new();
    response.set_id(client_query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_recursion_desired(client_query.recursion_desired());
    response.set_recursion_available(true);
    response.set_authoritative(true);
    response.set_response_code(ResponseCode::NXDomain);
    for orig_q in client_query.queries() {
        response.add_query(orig_q.clone());
    }
    super::normalize::lowercase_response_names(&mut response);
    let bytes = response.to_vec().context("encode local-zone NXDOMAIN")?;
    let key = CacheKey::new(q.name(), q.query_type(), q.query_class());
    cache.put(key, &response, bytes.clone()).await;
    Ok((bytes, WalkChain::default()))
}

/// Returns full Records (not unwrapped DS rdata) so the validator
/// can feed them to `verify_rrsig` with their original TTL — that
/// TTL is part of the canonical form RFC 4034 §6.2 signatures cover.
fn extract_ds_and_rrsig(resp: &Message, child_zone: &Name) -> (Vec<Record>, Vec<RRSIG>) {
    let child_lower = child_zone.to_lowercase();
    let mut ds = Vec::new();
    let mut sigs = Vec::new();
    for r in resp.name_servers() {
        if r.name().to_lowercase() != child_lower {
            continue;
        }
        match r.data() {
            Some(RData::DNSSEC(DNSSECRData::DS(_))) => ds.push(r.clone()),
            Some(RData::DNSSEC(DNSSECRData::RRSIG(s))) => {
                if s.type_covered() == RecordType::DS {
                    sigs.push(s.clone());
                }
            }
            _ => {}
        }
    }
    (ds, sigs)
}

fn classify(resp: &Message, qname: &Name, qtype: RecordType) -> Classification {
    match resp.response_code() {
        ResponseCode::NXDomain => return Classification::NxDomain,
        ResponseCode::ServFail | ResponseCode::Refused => return Classification::ServFail,
        _ => {}
    }

    let lower_qname = qname.to_lowercase();

    // CNAME chase takes priority over direct-answer when qtype is
    // anything other than CNAME itself.
    if qtype != RecordType::CNAME {
        for ans in resp.answers() {
            if ans.name().to_lowercase() == lower_qname
                && ans.record_type() == RecordType::CNAME
            {
                if let Some(RData::CNAME(target)) = ans.data() {
                    return Classification::Cname(target.0.to_lowercase());
                }
            }
        }
    }

    // Direct answer?
    for ans in resp.answers() {
        if ans.name().to_lowercase() == lower_qname && ans.record_type() == qtype {
            return Classification::Answer;
        }
    }
    // Any answer at all (could be partial CNAME chain ending in
    // record of wanted type already)?
    if !resp.answers().is_empty() {
        return Classification::Answer;
    }

    // Referral: Authority section has NS records for a zone that's
    // an ancestor of qname.
    let ns_records: Vec<Record> = resp
        .name_servers()
        .iter()
        .filter(|r| r.record_type() == RecordType::NS)
        .cloned()
        .collect();
    if !ns_records.is_empty() {
        let delegated_zone = ns_records[0].name().to_lowercase();
        // Build glue map from the Additional section.
        let mut glue: HashMap<Name, Vec<IpAddr>> = HashMap::new();
        for add in resp.additionals() {
            let owner = add.name().to_lowercase();
            match add.data() {
                Some(RData::A(A(v4))) => {
                    glue.entry(owner).or_default().push(IpAddr::V4(*v4));
                }
                Some(RData::AAAA(AAAA(v6))) => {
                    glue.entry(owner).or_default().push(IpAddr::V6(*v6));
                }
                _ => {}
            }
        }
        return Classification::Referral(delegated_zone, ns_records, glue);
    }

    Classification::Empty
}

/// Build an EDNS0-enabled UDP-shape wire query for (qname, qtype,
/// qclass) with RD=0 (we're the recursor — we don't ask our upstream
/// to recurse for us).
///
/// The OPT pseudo-record advertises a 1232-byte receive buffer, the
/// DNS-flag-day-2020 consensus value that fits cleanly within an
/// IPv6 minimum MTU without fragmentation. Without an OPT record,
/// servers must follow RFC 1035's 512-byte limit and tend to strip
/// glue records when the answer gets tight.
///
/// When `dnssec_ok` is true the DO bit in the OPT flags is set,
/// asking the server to include RRSIG / NSEC / NSEC3 records with
/// its response. Without DO, upstreams are free to strip signature
/// data and chain validation becomes impossible.
fn build_query(
    qname: &Name,
    qtype: RecordType,
    qclass: DNSClass,
    dnssec_ok: bool,
) -> Result<Vec<u8>> {
    let mut msg = Message::new();
    msg.set_id(rand::random());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false);
    let mut q = Query::query(qname.clone(), qtype);
    q.set_query_class(qclass);
    msg.add_query(q);
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(1232);
    edns.set_version(0);
    edns.set_dnssec_ok(dnssec_ok);
    msg.set_edns(edns);
    msg.to_vec().context("encode iterative query")
}

struct Budget {
    depth_remaining: u32,
    queries_remaining: u32,
    cname_remaining: u32,
}

impl Budget {
    fn new(depth: u32, queries: u32, cname: u32) -> Self {
        Self {
            depth_remaining: depth,
            queries_remaining: queries,
            cname_remaining: cname,
        }
    }

    fn referral(&mut self) -> Result<()> {
        if self.depth_remaining == 0 {
            return Err(anyhow!("referral depth exceeded"));
        }
        self.depth_remaining -= 1;
        Ok(())
    }

    fn query(&mut self) -> Result<()> {
        if self.queries_remaining == 0 {
            return Err(anyhow!("upstream query budget exceeded"));
        }
        self.queries_remaining -= 1;
        Ok(())
    }

    fn cname(&mut self) -> Result<()> {
        if self.cname_remaining == 0 {
            return Err(anyhow!("CNAME chain depth exceeded"));
        }
        self.cname_remaining -= 1;
        Ok(())
    }

    fn can_substep(&self) -> bool {
        self.depth_remaining > 0 && self.queries_remaining > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_hints_parse() {
        let roots = default_root_hints();
        assert_eq!(roots.len(), 26, "13 roots × 2 families = 26 IPs");
        assert!(roots.iter().any(|ip| ip.is_ipv4()));
        assert!(roots.iter().any(|ip| ip.is_ipv6()));
    }

    #[test]
    fn budget_counts_down() {
        let mut b = Budget::new(2, 3, 2);
        assert!(b.referral().is_ok());
        assert!(b.referral().is_ok());
        assert!(b.referral().is_err());

        assert!(b.query().is_ok());
        assert!(b.query().is_ok());
        assert!(b.query().is_ok());
        assert!(b.query().is_err());

        assert!(b.cname().is_ok());
        assert!(b.cname().is_ok());
        assert!(b.cname().is_err());
    }

    fn mk_record(name: &str, rtype: RecordType, rdata: RData) -> Record {
        let n = Name::from_ascii(name).unwrap();
        let mut r = Record::from_rdata(n, 300, rdata);
        r.set_dns_class(DNSClass::IN);
        r.set_record_type(rtype);
        r
    }

    #[test]
    fn classify_direct_answer() {
        use hickory_proto::rr::rdata::A;
        let mut m = Message::new();
        m.set_response_code(ResponseCode::NoError);
        m.add_answer(mk_record(
            "example.com.",
            RecordType::A,
            RData::A(A::new(93, 184, 216, 34)),
        ));
        let c = classify(
            &m,
            &Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        );
        assert!(matches!(c, Classification::Answer));
    }

    #[test]
    fn classify_nxdomain() {
        let mut m = Message::new();
        m.set_response_code(ResponseCode::NXDomain);
        let c = classify(
            &m,
            &Name::from_ascii("nope.example.").unwrap(),
            RecordType::A,
        );
        assert!(matches!(c, Classification::NxDomain));
    }

    #[test]
    fn classify_cname_takes_priority_over_nodata() {
        use hickory_proto::rr::rdata::CNAME;
        let mut m = Message::new();
        m.set_response_code(ResponseCode::NoError);
        m.add_answer(mk_record(
            "www.example.com.",
            RecordType::CNAME,
            RData::CNAME(CNAME(Name::from_ascii("cdn.example.net.").unwrap())),
        ));
        let c = classify(
            &m,
            &Name::from_ascii("www.example.com.").unwrap(),
            RecordType::A,
        );
        match c {
            Classification::Cname(target) => {
                assert_eq!(target, Name::from_ascii("cdn.example.net.").unwrap())
            }
            Classification::Answer => panic!("expected Cname, got Answer"),
            Classification::NxDomain => panic!("expected Cname, got NxDomain"),
            Classification::Empty => panic!("expected Cname, got Empty"),
            Classification::Referral(..) => panic!("expected Cname, got Referral"),
            Classification::ServFail => panic!("expected Cname, got ServFail"),
        }
    }

    #[test]
    fn classify_referral_with_glue() {
        use hickory_proto::rr::rdata::{A, NS};
        let mut m = Message::new();
        m.set_response_code(ResponseCode::NoError);
        m.add_name_server(mk_record(
            "com.",
            RecordType::NS,
            RData::NS(NS(Name::from_ascii("a.gtld-servers.net.").unwrap())),
        ));
        m.add_additional(mk_record(
            "a.gtld-servers.net.",
            RecordType::A,
            RData::A(A::new(192, 5, 6, 30)),
        ));
        let c = classify(
            &m,
            &Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        );
        match c {
            Classification::Referral(zone, ns, glue) => {
                assert_eq!(zone, Name::from_ascii("com.").unwrap());
                assert_eq!(ns.len(), 1);
                let ns_name = Name::from_ascii("a.gtld-servers.net.").unwrap();
                assert_eq!(
                    glue.get(&ns_name).and_then(|v| v.first()).copied(),
                    Some("192.5.6.30".parse::<IpAddr>().unwrap())
                );
            }
            _ => panic!("expected Referral classification"),
        }
    }
}
