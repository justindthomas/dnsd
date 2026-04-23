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
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use crate::metrics::Metrics;
use crate::recursor::cache::{CacheKey, DnsCache};
use crate::recursor::forwarder::UpstreamClient;

/// Default per-query budget. Sized to resolve even worst-case
/// glueless chains without running away.
pub const DEFAULT_MAX_DEPTH: u32 = 16;
pub const DEFAULT_MAX_QUERIES: u32 = 100;
pub const DEFAULT_MAX_CNAME: u32 = 8;

#[derive(Clone)]
pub struct IterativeResolver {
    upstream: Arc<UpstreamClient>,
    cache: Arc<DnsCache>,
    metrics: Arc<Metrics>,
    roots: Vec<IpAddr>,
    max_depth: u32,
    max_queries: u32,
    max_cname: u32,
}

impl IterativeResolver {
    pub fn new(
        upstream: Arc<UpstreamClient>,
        cache: Arc<DnsCache>,
        metrics: Arc<Metrics>,
        max_cname: u32,
    ) -> Self {
        Self {
            upstream,
            cache,
            metrics,
            roots: default_root_hints(),
            max_depth: DEFAULT_MAX_DEPTH,
            max_queries: DEFAULT_MAX_QUERIES,
            max_cname: max_cname.max(1).min(DEFAULT_MAX_CNAME * 2),
        }
    }

    /// Resolve `qname` / `qtype` iteratively. Returns a full wire
    /// response whose TXID matches the input query's TXID.
    pub async fn resolve(&self, client_query: &Message) -> Result<Vec<u8>> {
        let q = client_query
            .queries()
            .first()
            .ok_or_else(|| anyhow!("iterative resolve needs a question"))?
            .clone();

        self.metrics.recursion_walked.fetch_add(1, Ordering::Relaxed);

        let mut budget = Budget::new(self.max_depth, self.max_queries, self.max_cname);
        let answer = self
            .walk(&q.name().clone(), q.query_type(), q.query_class(), &mut budget)
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

        let bytes = response.to_vec().context("encode iterative response")?;
        // Cache under the original question (lowercased).
        let key = CacheKey::new(q.name(), q.query_type(), q.query_class());
        self.cache.put(key, &response, bytes.clone()).await;
        Ok(bytes)
    }

    /// Core delegation walk. `qname` + `qtype` is the target; we
    /// start at the roots and descend until we either hit an
    /// authoritative answer or run out of budget.
    async fn walk(
        &self,
        qname: &Name,
        qtype: RecordType,
        qclass: DNSClass,
        budget: &mut Budget,
    ) -> Result<Message> {
        budget.referral()?;

        // Current working set of name-server IPs to query. Start
        // at the roots; each referral replaces this.
        let mut ns_ips: Vec<IpAddr> = self.roots.clone();
        // Current zone we're talking to. Starts at the root ".".
        let mut current_zone = Name::root();

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
                    // new qname, same qtype.
                    budget.cname()?;
                    let cname_resp =
                        Box::pin(self.walk(&target, qtype, qclass, budget)).await?;
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

    /// Try each NS IP in `ns_ips` in a shuffled order until one
    /// responds. Increments budget per query; bails on exhaustion.
    async fn query_ns_set(
        &self,
        ns_ips: &[IpAddr],
        qname: &Name,
        qtype: RecordType,
        qclass: DNSClass,
        budget: &mut Budget,
    ) -> Result<Message> {
        use rand::seq::SliceRandom;
        let mut order: Vec<IpAddr> = ns_ips.to_vec();
        order.shuffle(&mut rand::thread_rng());

        let wire = build_query(qname, qtype, qclass)?;

        let mut last_err = None;
        for ip in order {
            budget.query()?;
            match self.upstream.query(&[ip], &wire).await {
                Ok(resp_bytes) => {
                    match Message::from_bytes(&resp_bytes) {
                        Ok(m) => return Ok(m),
                        Err(e) => {
                            tracing::debug!(%ip, "iterative parse: {e}");
                            last_err = Some(anyhow!(e));
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(%ip, "iterative upstream: {e}");
                    last_err = Some(e);
                }
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
                ips.extend_from_slice(glued);
                continue;
            }
            // No glue — recurse to find the NS's address(es). We
            // prefer A over AAAA to minimise further iteration (the
            // v6 path may itself need a glueless walk). Failures are
            // not fatal; we skip this NS and try the next.
            let sub_budget_ok = budget.can_substep();
            if !sub_budget_ok {
                continue;
            }
            match Box::pin(self.walk(&target_name, RecordType::A, qclass, budget)).await {
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

/// Build a plain UDP-shape wire query for (qname, qtype, qclass)
/// with RD=0 (we're the recursor — we don't ask our upstream to
/// recurse for us).
fn build_query(qname: &Name, qtype: RecordType, qclass: DNSClass) -> Result<Vec<u8>> {
    let mut msg = Message::new();
    msg.set_id(rand::random());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false);
    let mut q = Query::query(qname.clone(), qtype);
    q.set_query_class(qclass);
    msg.add_query(q);
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
