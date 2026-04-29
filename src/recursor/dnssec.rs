//! DNSSEC policy + primitives.
//!
//! **Landed in v1 (2026-04-23):**
//!
//! * `DnssecPolicy` enum and operator config wiring.
//! * Trust-anchor loader — reads root.key (BIND-style `trusted-keys`
//!   or IANA root-anchors.xml trust format) and materialises the
//!   root KSK as a DNSKEY record we can verify against.
//! * `verify_rrset` primitive: given an RRSIG, the RRset it covers,
//!   and a DNSKEY, run hickory-proto's Verifier. Handles algorithm
//!   selection (RSA/ECDSA/Ed25519) via the `dnssec-ring` feature.
//! * `validate_response` — walks a response's Answer section and
//!   verifies each RRSet against any DNSKEY we already hold (trust
//!   anchors + keys cached from a prior chain walk). Returns
//!   Secure / Insecure / Bogus.
//!
//! **Still outstanding:**
//!
//! * Chain-of-trust walking — fetching DS from parent + DNSKEY from
//!   child, stitching into a trust path back to the root KSK.
//!   Lands as part of the iterative recursor's DNSSEC mode (pass
//!   through an `Arc<Validator>` that the recursor calls after each
//!   referral). Until then `validate_response` only returns Secure
//!   for RRsets signed by a key we've pre-seeded (the root KSK) —
//!   typically NS records at the root zone — and Insecure for
//!   everything else. That's honest but limited.
//! * NSEC / NSEC3 denial-of-existence proofs.
//! * Wildcard proof validation.
//! * RRSIG validity-period checks with clock skew.
//! * Algorithm-downgrade protection.
//!
//! Operators choose behavior via `dns.recursion.dnssec:`:
//!   * `passthrough` (default) — honour the upstream's AD bit
//!   * `strip` — unconditionally clear AD
//!   * `validate` — chain-walk every iterative answer; AD=1 on
//!     Secure, SERVFAIL+EDE 6 on Bogus. Requires `trust_anchor:` to
//!     point at a root.key file.
//!
//! The legacy boolean `dnssec_validate: true` is still honoured (it
//! maps to `dnssec: validate`) for backward compat with pre-v1
//! router.yaml.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, Context as _, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::dnssec::rdata::{DNSSECRData, DNSKEY, DS, RRSIG};
use hickory_proto::rr::dnssec::Verifier as _;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use crate::config::Recursion;
use crate::recursor::forwarder::UpstreamClient;
use crate::recursor::iterative::WalkChain;

/// Clock-skew tolerance for RRSIG validity-window checks. Matches
/// common recursor defaults (BIND/Unbound both ~300 s).
const CLOCK_SKEW: Duration = Duration::from_secs(300);

/// State of a single delegation step's DNSKEYs after the parallel
/// pre-flight in `validate_walk`. Replaces the inline fetch the
/// loop used to do — the loop now just consumes one of these per
/// step.
#[derive(Clone)]
enum StepDnskeyState {
    /// Cache hit and one of the cached keys hashes to a DS in this
    /// query's referral. Loop pushes onto chain_keys and continues
    /// without a network round-trip or signature verification.
    Cached(Vec<DNSKEY>),
    /// Negative cache hit (a recent fetch failed). Loop returns
    /// ValidationStatus::Insecure.
    Insecure,
    /// Live fetch result. On success carries the records + keys +
    /// covering RRSIG; on failure carries a stringified error
    /// (anyhow::Error isn't Clone, so we render it once at fetch
    /// time). The negative cache is already populated on failure.
    Fetched(std::result::Result<(Vec<Record>, Vec<DNSKEY>, Option<RRSIG>), String>),
}

/// Per-zone DNSKEY cache. Validated keys are reused across queries
/// until min(DNSKEY TTL, MAX_POSITIVE_TTL) so a single .com query
/// doesn't re-fetch root + .com DNSKEYs each time. The negative
/// half marks zones whose DNSKEY fetch failed (timeout / transport
/// error) as "treat as Insecure for NEGATIVE_TTL", so a zone like
/// arin.net (whose NSes RRL→TC=1 + our VPP TCP fallback is broken)
/// stops eating a 5-second deadline on every single query.
const POSITIVE_CACHE_CAP: usize = 256;
const NEGATIVE_CACHE_CAP: usize = 256;
const NEGATIVE_TTL: Duration = Duration::from_secs(300);
const MIN_POSITIVE_TTL: Duration = Duration::from_secs(60);
const MAX_POSITIVE_TTL: Duration = Duration::from_secs(86_400);

#[derive(Clone)]
struct PositiveEntry {
    keys: Vec<DNSKEY>,
    expiry: Instant,
}

pub struct DnskeyCache {
    positive: RwLock<HashMap<Name, PositiveEntry>>,
    negative: RwLock<HashMap<Name, Instant>>,
}

impl DnskeyCache {
    pub fn new() -> Self {
        Self {
            positive: RwLock::new(HashMap::new()),
            negative: RwLock::new(HashMap::new()),
        }
    }

    fn get_positive(&self, zone: &Name) -> Option<Vec<DNSKEY>> {
        let map = self.positive.read().unwrap();
        let entry = map.get(zone)?;
        if entry.expiry > Instant::now() {
            Some(entry.keys.clone())
        } else {
            None
        }
    }

    fn put_positive(&self, zone: Name, keys: Vec<DNSKEY>, ttl: Duration) {
        let ttl = ttl.clamp(MIN_POSITIVE_TTL, MAX_POSITIVE_TTL);
        let expiry = Instant::now() + ttl;
        let mut map = self.positive.write().unwrap();
        if map.len() >= POSITIVE_CACHE_CAP && !map.contains_key(&zone) {
            evict(&mut *map, |e: &PositiveEntry| e.expiry);
        }
        map.insert(zone, PositiveEntry { keys, expiry });
    }

    fn invalidate_positive(&self, zone: &Name) {
        self.positive.write().unwrap().remove(zone);
    }

    fn has_negative(&self, zone: &Name) -> bool {
        let map = self.negative.read().unwrap();
        map.get(zone).map(|e| *e > Instant::now()).unwrap_or(false)
    }

    fn put_negative(&self, zone: Name) {
        let expiry = Instant::now() + NEGATIVE_TTL;
        let mut map = self.negative.write().unwrap();
        if map.len() >= NEGATIVE_CACHE_CAP && !map.contains_key(&zone) {
            evict(&mut *map, |e: &Instant| *e);
        }
        map.insert(zone, expiry);
    }
}

impl Default for DnskeyCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Drop expired entries first; if every entry is still live, drop
/// one arbitrary entry to make room. Tiny hot-path code so we
/// don't bother with LRU bookkeeping.
fn evict<V>(map: &mut HashMap<Name, V>, expiry_of: impl Fn(&V) -> Instant) {
    let now = Instant::now();
    let stale: Vec<Name> = map
        .iter()
        .filter_map(|(k, v)| if expiry_of(v) <= now { Some(k.clone()) } else { None })
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

/// EDNS Extended DNS Error codes relevant to DNSSEC responses.
pub const EDE_DNSSEC_BOGUS: u16 = 6;
pub const EDE_NO_REACHABLE_AUTHORITY: u16 = 22;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnssecPolicy {
    /// Leave the upstream's AD bit alone. Right when we trust the
    /// configured forwarder to validate for us.
    PassThrough,
    /// Clear AD unconditionally. Correct when we don't trust the
    /// upstream's validation and don't want to mislead downstream
    /// clients with a bogus AD=1.
    Strip,
    /// Operator requested validation. Validates what it can against
    /// trust anchors + pre-fetched DNSKEYs; falls back to Strip when
    /// there's no trust path (chain walk pending).
    Validate,
}

impl DnssecPolicy {
    pub fn from_recursion(r: Option<&Recursion>) -> Self {
        use crate::config::DnssecMode;
        match r.map(|r| r.effective_dnssec()).unwrap_or_default() {
            DnssecMode::PassThrough => DnssecPolicy::PassThrough,
            DnssecMode::Strip => DnssecPolicy::Strip,
            DnssecMode::Validate => DnssecPolicy::Validate,
        }
    }

    pub fn apply_to_response(&self, resp: &mut Message) {
        match self {
            DnssecPolicy::PassThrough => { /* leave AD as-is */ }
            DnssecPolicy::Strip => {
                resp.set_authentic_data(false);
            }
            DnssecPolicy::Validate => {
                // Without chain walking we can't safely confirm AD,
                // so strip. The validator API (below) is invoked
                // separately by callers that have prefetched
                // DNSKEYs — they set AD explicitly on success.
                resp.set_authentic_data(false);
            }
        }
    }
}

/// Authoritative outcome of validating a single RRset or response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationStatus {
    /// Chain of trust is complete and every signature verifies.
    Secure,
    /// No trust path available (e.g. unsigned zone, or no DNSKEY
    /// in our store for the signer name). This is not a failure —
    /// per RFC 4035 §5 the answer is still returned, just without AD.
    Insecure,
    /// There's a trust path but a signature fails or is missing
    /// when required. Caller returns SERVFAIL with EDE 6
    /// (DNSSEC Bogus).
    Bogus(String),
}

/// A loaded set of trust anchors — typically just the IANA root
/// KSK, but operators can ship additional islands (e.g. a private
/// DNSSEC-signed zone).
pub struct TrustAnchors {
    keys: Vec<(hickory_proto::rr::Name, DNSKEY)>,
}

impl TrustAnchors {
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Load trust anchors from a file. Supports two formats:
    ///
    /// * BIND-style `trusted-keys`/`trust-anchors { ... }` blocks
    ///   (what `dig +sigchase` and Unbound emit for root.key).
    /// * IANA's XML `root-anchors.xml` (detected by the XML prolog).
    ///
    /// For v1 we implement the simple presentation-format parser
    /// that's enough to load the root KSK from a hand-maintained
    /// file like Unbound's `root.key`. Full BIND trust-anchors.conf
    /// is a follow-up.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading trust anchor file {}", path.display()))?;
        parse_presentation_format(&raw)
            .with_context(|| format!("parsing trust anchor file {}", path.display()))
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Build a `TrustAnchors` from a slice of `ManagedKey`s,
    /// skipping anything not in the `Active` state. Used by the
    /// RFC 5011 refresh loop to publish a new active set after a
    /// transition (promote / revoke).
    pub fn from_managed_keys(
        keys: &[crate::recursor::anchor::ManagedKey],
    ) -> anyhow::Result<Self> {
        let mut out = Vec::new();
        for k in keys.iter().filter(|k| k.is_active()) {
            let dnskey = k.to_dnskey()?;
            let name = hickory_proto::rr::Name::from_ascii(&k.zone)
                .with_context(|| format!("bad zone name {:?}", k.zone))?;
            out.push((name, dnskey));
        }
        Ok(Self { keys: out })
    }

    /// Read-only access to all (zone, key) pairs. Used by the
    /// RFC 5011 refresh task to verify a fresh DNSKEY RRset against
    /// every active anchor.
    pub fn keys(&self) -> &[(hickory_proto::rr::Name, DNSKEY)] {
        &self.keys
    }

    pub fn dnskeys_for(&self, owner: &hickory_proto::rr::Name) -> Vec<&DNSKEY> {
        let lower = owner.to_lowercase();
        self.keys
            .iter()
            .filter(|(n, _)| n.to_lowercase() == lower)
            .map(|(_, k)| k)
            .collect()
    }
}

impl Default for TrustAnchors {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse Unbound / BIND style `trusted-keys` / `trust-anchors`
/// entries, one DNSKEY per line:
///
/// ```text
/// .  172800  IN  DNSKEY  257 3 8 AwEAAag...
/// ```
///
/// Lines starting with `;` or blank are skipped. Multi-line records
/// wrapped in `(` / `)` are flattened first.
/// Public re-exported wrapper used by `anchor::bootstrap_self_managed`
/// to parse the embedded root KSK string at startup. Same parser
/// the operator-supplied file path uses.
pub fn parse_presentation_format_str(raw: &str) -> Result<TrustAnchors> {
    parse_presentation_format(raw)
}

fn parse_presentation_format(raw: &str) -> Result<TrustAnchors> {
    // Flatten parenthesised multi-line rdata.
    let mut flat = String::with_capacity(raw.len());
    let mut depth = 0;
    for ch in raw.chars() {
        match ch {
            '(' => {
                depth += 1;
            }
            ')' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            '\n' if depth > 0 => flat.push(' '),
            c => flat.push(c),
        }
    }

    let mut keys = Vec::new();
    for raw_line in flat.lines() {
        let line = raw_line
            .split_once(';')
            .map(|(lhs, _comment)| lhs)
            .unwrap_or(raw_line)
            .trim();
        if line.is_empty() {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        // Expect: NAME TTL CLASS DNSKEY flags protocol algorithm base64..
        // TTL may be omitted (dnssec-keygen emits 'IN' immediately after NAME
        // in some cases), so be permissive.
        let (name_str, rest) = match toks.split_first() {
            Some(pair) => pair,
            None => continue,
        };
        // Skip optional TTL + CLASS + "DNSKEY" before the rdata.
        let mut cursor = 0usize;
        while cursor < rest.len() {
            let t = rest[cursor];
            if t.eq_ignore_ascii_case("DNSKEY") {
                cursor += 1;
                break;
            }
            cursor += 1;
        }
        if rest.len() - cursor < 4 {
            continue; // not a DNSKEY record
        }
        let flags: u16 = rest[cursor]
            .parse()
            .with_context(|| format!("bad DNSKEY flags {:?}", rest[cursor]))?;
        let protocol: u8 = rest[cursor + 1]
            .parse()
            .with_context(|| format!("bad DNSKEY protocol {:?}", rest[cursor + 1]))?;
        let algorithm: u8 = rest[cursor + 2]
            .parse()
            .with_context(|| format!("bad DNSKEY algorithm {:?}", rest[cursor + 2]))?;
        let b64: String = rest[cursor + 3..].concat();
        let public_key = base64_decode(&b64)
            .ok_or_else(|| anyhow!("invalid base64 in DNSKEY public key"))?;

        let zone_flag = flags & 0x0100 != 0;
        let secure_entry_point = flags & 0x0001 != 0;
        let revoked = flags & 0x0080 != 0;
        let algorithm = hickory_proto::rr::dnssec::Algorithm::from_u8(algorithm);
        let _ = protocol; // DNSKEY protocol field is always 3.
        let dnskey = DNSKEY::new(zone_flag, secure_entry_point, revoked, algorithm, public_key);
        let name = hickory_proto::rr::Name::from_ascii(name_str)
            .with_context(|| format!("bad trust-anchor owner name {name_str:?}"))?;
        keys.push((name, dnskey));
    }
    Ok(TrustAnchors { keys })
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::prelude::{Engine, BASE64_STANDARD};
    // Strip whitespace that may have leaked from the multi-line flatten.
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    BASE64_STANDARD.decode(clean.as_bytes()).ok()
}

/// Verify a single RRset (same owner/type/class) against an RRSIG
/// and a candidate DNSKEY. Returns Ok on valid signature.
pub fn verify_rrset(
    rrset: &[Record],
    rrsig: &hickory_proto::rr::dnssec::rdata::RRSIG,
    key: &DNSKEY,
) -> Result<()> {
    if rrset.is_empty() {
        return Err(anyhow!("empty RRset"));
    }
    let owner = rrset[0].name().clone();
    let class = rrset[0].dns_class();
    key.verify_rrsig(&owner, class, rrsig, rrset)
        .map_err(|e| anyhow!("RRSIG verify failed: {e}"))
}

/// Group answer records by (name, rtype, class) and verify each
/// group against the RRSIG covering it, using whichever DNSKEY in
/// the store has a matching key-tag. Returns the highest-severity
/// validation outcome across all RRsets.
pub fn validate_response(resp: &Message, anchors: &TrustAnchors) -> ValidationStatus {
    // Group answers by (name, rtype).
    let mut groups: std::collections::BTreeMap<
        (hickory_proto::rr::Name, RecordType, DNSClass),
        Vec<Record>,
    > = Default::default();
    let mut sigs: Vec<hickory_proto::rr::dnssec::rdata::RRSIG> = Vec::new();

    for r in resp.answers() {
        match r.data() {
            Some(RData::DNSSEC(hickory_proto::rr::dnssec::rdata::DNSSECRData::RRSIG(rrsig))) => {
                sigs.push(rrsig.clone());
            }
            Some(_) => {
                groups
                    .entry((r.name().clone(), r.record_type(), r.dns_class()))
                    .or_default()
                    .push(r.clone());
            }
            None => {}
        }
    }

    if groups.is_empty() {
        return ValidationStatus::Insecure;
    }

    let mut overall = ValidationStatus::Secure;
    let mut saw_secure = false;

    for ((name, rtype, class), rrset) in groups {
        // Find the covering RRSIG.
        let sig = match sigs.iter().find(|s| s.type_covered() == rtype) {
            Some(s) => s,
            None => {
                overall = ValidationStatus::Insecure;
                continue;
            }
        };
        let signer = sig.signer_name().clone();
        let candidates = anchors.dnskeys_for(&signer);
        if candidates.is_empty() {
            overall = ValidationStatus::Insecure;
            continue;
        }
        let mut verified = false;
        for key in candidates {
            if let Ok(()) = verify_rrset(&rrset, sig, key) {
                verified = true;
                break;
            }
        }
        if verified {
            saw_secure = true;
        } else {
            return ValidationStatus::Bogus(format!(
                "signature on {name}/{rtype:?} did not verify under signer {signer}"
            ));
        }
        let _ = (name, class); // silence unused-var warnings if unused in log
    }

    if saw_secure {
        ValidationStatus::Secure
    } else {
        overall
    }
}

/// Apply a validation status to a response — sets AD on Secure,
/// clears it on Insecure/Bogus. Caller handles SERVFAIL+EDE for
/// Bogus separately.
pub fn apply_validation(resp: &mut Message, status: &ValidationStatus) {
    match status {
        ValidationStatus::Secure => resp.set_authentic_data(true),
        ValidationStatus::Insecure | ValidationStatus::Bogus(_) => {
            resp.set_authentic_data(false)
        }
    };
}

/// Shared, swappable handle to the active trust-anchor set. The RFC
/// 5011 refresh task publishes a new set into this swap whenever a
/// hold-down completes or a key gets revoked; existing in-flight
/// validations keep using the snapshot they loaded.
pub type TrustAnchorSwap = Arc<arc_swap::ArcSwap<TrustAnchors>>;

/// Helper that glues a validator into the handler: `Arc<Validator>`
/// can be cheaply cloned across tasks.
pub struct Validator {
    /// Active trust anchors. Loaded via `arc-swap` so the RFC 5011
    /// rotation task can publish updates without restarting the
    /// validator. Each `validate*` call snapshots once; long-running
    /// chain walks don't see mid-walk changes.
    pub anchors: TrustAnchorSwap,
    /// Upstream client used to fetch per-zone DNSKEY RRsets during
    /// chain validation.
    pub upstream: Arc<UpstreamClient>,
    /// Shared handle to the live root-hint set — the validator uses
    /// these IPs to fetch the root DNSKEY RRset before descending
    /// into the per-delegation chain walk (the trust-anchor KSK
    /// only signs DNSKEY; the root ZSK that signs TLD DS records
    /// isn't in the anchor file).
    pub roots: Arc<std::sync::RwLock<Vec<std::net::IpAddr>>>,
    /// Validated DNSKEYs cached by zone — avoids re-fetching keys
    /// for hot zones (root, TLDs, popular SLDs) on every query, and
    /// short-circuits zones whose fetch keeps timing out.
    pub cache: Arc<DnskeyCache>,
}

impl Validator {
    pub fn new(
        anchors: TrustAnchorSwap,
        upstream: Arc<UpstreamClient>,
        roots: Arc<std::sync::RwLock<Vec<std::net::IpAddr>>>,
    ) -> Self {
        Self {
            anchors,
            upstream,
            roots,
            cache: Arc::new(DnskeyCache::new()),
        }
    }

    /// Quick-path validation against pre-loaded anchors only. Used
    /// for tests and for responses we don't have a WalkChain for.
    pub fn validate(&self, resp: &Message) -> ValidationStatus {
        validate_response(resp, &self.anchors.load())
    }

    /// Full chain validation for an iterative-resolve result:
    ///   1. Seed the trust chain with the loaded trust anchors
    ///      (typically the root KSK).
    ///   2. For each delegation step, fetch the child zone's DNSKEY
    ///      RRset, verify its self-signed RRSIG, and confirm at
    ///      least one DS hash from the parent's referral matches one
    ///      of the child's KSKs.
    ///   3. Verify the parent's DS RRset's own RRSIG using the
    ///      parent zone's DNSKEYs (already trusted).
    ///   4. Validate the answer RRsets' RRSIGs using the terminal
    ///      zone's DNSKEYs.
    ///
    /// Missing DS at any step → "insecure delegation": the remaining
    /// chain is treated as Insecure (AD=0). NSEC/NSEC3 denial-of-DS
    /// proofs that would promote this to Bogus-on-downgrade land in
    /// a v1.x follow-up — for v1 we optimise for not-breaking
    /// legitimately-unsigned zones.
    pub async fn validate_walk(
        &self,
        walk: &WalkChain,
        answer: &Message,
    ) -> ValidationStatus {
        let mut chain_keys: Vec<(Name, Vec<DNSKEY>)> = Vec::new();

        // Snapshot the active anchor set once for this whole walk so
        // a concurrent RFC 5011 refresh that publishes a new set
        // doesn't shift our trust mid-validation.
        let anchors = self.anchors.load_full();

        // Seed with trust anchors.
        for (name, key) in &anchors.keys {
            let entry = chain_keys
                .iter_mut()
                .find(|(n, _)| n == name);
            match entry {
                Some((_, v)) => v.push(key.clone()),
                None => chain_keys.push((name.clone(), vec![key.clone()])),
            }
        }
        if chain_keys.is_empty() {
            // No trust anchor loaded at all — we can't validate
            // anything. Call it Insecure so the handler doesn't set
            // AD but doesn't SERVFAIL either.
            return ValidationStatus::Insecure;
        }

        // Fetch root DNSKEY and splice the ZSK into the root entry.
        // The trust anchor only contains the KSK (which signs only
        // the DNSKEY RRset itself); the ZSK that signs every other
        // root RRset (including TLD DS records) has to be learned
        // from the root and anchored under the KSK.
        let root = Name::root();
        let root_ips: Vec<std::net::IpAddr> = self.roots.read().unwrap().clone();
        if let Err(e) = self
            .splice_in_zone_dnskey(&mut chain_keys, &root, &root_ips)
            .await
        {
            return ValidationStatus::Bogus(format!("root DNSKEY bootstrap: {e}"));
        }

        // Pre-flight: kick off all per-step DNSKEY fetches in
        // parallel. Cache hits + negative-cache hits are resolved
        // synchronously; everything else fires concurrently. The
        // sequential verify loop below then has each step's DNSKEYs
        // ready when it gets there — turning N serial RTTs into one
        // parallel batch (paid during the wall time of the slowest
        // fetch). For a 5-deep signed chain that's typically ~5x
        // less wall-clock cost on cold queries.
        let prefetched = self.prefetch_step_dnskeys(walk).await;

        // Walk each delegation step, promoting the chain as we go.
        let mut insecure_from: Option<Name> = None;
        for (idx, step) in walk.steps.iter().enumerate() {
            if insecure_from.is_some() {
                // Already entered insecure territory.
                break;
            }
            // Find the parent zone's keys — the closest already-
            // trusted ancestor of step.zone.
            let parent_keys = closest_trusted_keys(&chain_keys, &step.zone);
            if parent_keys.is_empty() {
                // No trust above this step — can't validate.
                insecure_from = Some(step.zone.clone());
                break;
            }

            // If the parent didn't hand us any DS records, this is a
            // legitimately insecure delegation (per our scope, absent
            // a denial-of-DS proof).
            if step.ds.is_empty() {
                insecure_from = Some(step.zone.clone());
                break;
            }

            // Verify the DS RRset's own signature with parent keys.
            // Pass the ORIGINAL records (not reconstructed) so their
            // TTL matches what the signer used.
            let ds_rrsig = match step.ds_rrsig.iter().find(|s| s.type_covered() == RecordType::DS) {
                Some(s) => s,
                None => {
                    return ValidationStatus::Bogus(format!(
                        "DS for {} came without an RRSIG",
                        step.zone
                    ));
                }
            };
            if let Err(e) = check_rrsig_validity(ds_rrsig) {
                return ValidationStatus::Bogus(format!(
                    "DS RRSIG for {} invalid: {e}",
                    step.zone
                ));
            }
            let mut ds_verified = false;
            tracing::debug!(
                zone = %step.zone,
                ds_records = step.ds.len(),
                rrsig_signer = %ds_rrsig.signer_name(),
                rrsig_key_tag = ds_rrsig.key_tag(),
                rrsig_algo = ?ds_rrsig.algorithm(),
                parent_key_count = parent_keys.len(),
                "DS RRSIG validation: about to verify"
            );
            for k in &parent_keys {
                let key_tag = k.calculate_key_tag().unwrap_or(0);
                match verify_rrset(&step.ds, ds_rrsig, k) {
                    Ok(()) => {
                        ds_verified = true;
                        tracing::debug!(zone = %step.zone, key_tag, "DS RRSIG verified");
                        break;
                    }
                    Err(e) => {
                        tracing::debug!(
                            zone = %step.zone,
                            key_tag,
                            algo = ?k.algorithm(),
                            "DS RRSIG verify attempt failed: {e}"
                        );
                    }
                }
            }
            if !ds_verified {
                return ValidationStatus::Bogus(format!(
                    "DS RRSIG for {} did not verify under parent keys (rrsig key_tag={}, parent key_tags={:?})",
                    step.zone,
                    ds_rrsig.key_tag(),
                    parent_keys.iter().filter_map(|k| k.calculate_key_tag().ok()).collect::<Vec<_>>(),
                ));
            }

            // Pull the prefetched DNSKEY state for this step. Three
            // outcomes from prefetch:
            //   * Cached: cache had keys whose DS covered one of the
            //     parent's DS records. Reuse and skip the rest of
            //     this step's verify (already validated last time).
            //   * Insecure: negative-cached zone (the prefetch saw
            //     it; or the prefetch itself failed and put it in
            //     the negative cache). Stop walking, return Insecure.
            //   * Fetched: the parallel fetch completed; downstream
            //     verification continues with the returned keys.
            let zone_key = step.zone.to_lowercase();
            let (dnskey_records, dnskeys, dnskey_rrsig) =
                match prefetched.get(idx).cloned() {
                    Some(StepDnskeyState::Cached(cached_keys)) => {
                        tracing::debug!(zone = %step.zone, "DNSKEY cache hit (positive)");
                        chain_keys.push((step.zone.clone(), cached_keys));
                        continue;
                    }
                    Some(StepDnskeyState::Insecure) => {
                        tracing::debug!(zone = %step.zone, "DNSKEY cache hit (negative) — Insecure");
                        return ValidationStatus::Insecure;
                    }
                    Some(StepDnskeyState::Fetched(Ok(tuple))) => tuple,
                    Some(StepDnskeyState::Fetched(Err(msg))) => {
                        tracing::warn!(
                            zone = %step.zone,
                            "DNSKEY fetch failed, treating as Insecure: {msg}"
                        );
                        return ValidationStatus::Insecure;
                    }
                    None => {
                        // Shouldn't happen: prefetched is sized to
                        // walk.steps. Treat as Insecure rather than
                        // panicking.
                        tracing::error!(zone = %step.zone, "prefetch state missing for step");
                        return ValidationStatus::Insecure;
                    }
                };
            if dnskeys.is_empty() {
                return ValidationStatus::Bogus(format!(
                    "no DNSKEY records returned for {}",
                    step.zone
                ));
            }
            let dnskey_rrsig = match dnskey_rrsig {
                Some(s) => s,
                None => {
                    return ValidationStatus::Bogus(format!(
                        "DNSKEY RRset for {} unsigned",
                        step.zone
                    ));
                }
            };
            if let Err(e) = check_rrsig_validity(&dnskey_rrsig) {
                return ValidationStatus::Bogus(format!(
                    "DNSKEY RRSIG for {} invalid: {e}",
                    step.zone
                ));
            }

            // The DNSKEY RRset is self-signed: verify with one of
            // its own keys.
            let self_signed = dnskeys
                .iter()
                .any(|k| verify_rrset(&dnskey_records, &dnskey_rrsig, k).is_ok());
            if !self_signed {
                return ValidationStatus::Bogus(format!(
                    "DNSKEY RRset for {} is not self-signed",
                    step.zone
                ));
            }

            // Confirm at least one DNSKEY hashes to a DS we saw.
            let ds_values: Vec<&DS> = step
                .ds
                .iter()
                .filter_map(|r| match r.data() {
                    Some(RData::DNSSEC(DNSSECRData::DS(d))) => Some(d),
                    _ => None,
                })
                .collect();
            let ds_match = dnskeys.iter().any(|k| {
                ds_values
                    .iter()
                    .any(|d| d.covers(&step.zone, k).unwrap_or(false))
            });
            if !ds_match {
                return ValidationStatus::Bogus(format!(
                    "no DNSKEY for {} matches any DS from parent",
                    step.zone
                ));
            }

            let ttl = Duration::from_secs(
                dnskey_records
                    .iter()
                    .map(|r| r.ttl() as u64)
                    .min()
                    .unwrap_or(MIN_POSITIVE_TTL.as_secs()),
            );
            self.cache.put_positive(zone_key, dnskeys.clone(), ttl);
            chain_keys.push((step.zone.clone(), dnskeys));
        }

        if insecure_from.is_some() {
            return ValidationStatus::Insecure;
        }

        // Validate the answer RRSIGs against the terminal zone's
        // DNSKEYs (or the closest trusted ancestor if we can't
        // identify a terminal zone). For empty-answer responses
        // (NXDOMAIN / NODATA) fall through to denial-of-existence
        // proof validation using the NSEC or NSEC3 records in the
        // authority section.
        let (qname, qtype) = answer
            .queries()
            .first()
            .map(|q| (q.name().clone(), q.query_type()))
            .unwrap_or_else(|| (Name::root(), RecordType::A));
        validate_answer_against_chain(answer, &chain_keys, &qname, qtype)
    }

    /// Fetch `zone DNSKEY`, self-verify the RRset (the KSK signs
    /// the RRset using its own key), and splice the ZSK(s) into
    /// `chain_keys` alongside any existing entry for `zone`. Used
    /// for (a) the root bootstrap — the trust anchor only holds
    /// the KSK but we need the root ZSK to verify TLD DS records —
    /// and (b) every delegation step's child-zone DNSKEY fetch.
    ///
    /// Requires the zone already has at least one trusted key in
    /// `chain_keys` (either from the trust anchor, for root, or
    /// via the DS-covers check against the child's KSK, for
    /// deeper zones).
    async fn splice_in_zone_dnskey(
        &self,
        chain_keys: &mut Vec<(Name, Vec<DNSKEY>)>,
        zone: &Name,
        ns_ips: &[std::net::IpAddr],
    ) -> Result<()> {
        let zone_key = zone.to_lowercase();
        if let Some(cached_keys) = self.cache.get_positive(&zone_key) {
            tracing::debug!(zone = %zone, "DNSKEY cache hit for splice");
            chain_keys.retain(|(n, _)| n != zone);
            chain_keys.push((zone.clone(), cached_keys));
            return Ok(());
        }

        let (records, keys, sig) = self
            .fetch_dnskey_rrset(zone, ns_ips)
            .await
            .with_context(|| format!("fetching {zone} DNSKEY"))?;
        let sig = sig
            .ok_or_else(|| anyhow!("{zone} DNSKEY RRset came without an RRSIG"))?;
        check_rrsig_validity(&sig).with_context(|| format!("{zone} DNSKEY RRSIG"))?;

        // Verify using any trusted key for this zone (KSK from
        // trust anchor for root; previously-validated keys
        // otherwise).
        let existing = chain_keys
            .iter()
            .find(|(n, _)| n == zone)
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let verified = existing
            .iter()
            .any(|k| verify_rrset(&records, &sig, k).is_ok());
        if !verified {
            anyhow::bail!(
                "{zone} DNSKEY RRSIG did not verify under any existing trusted key"
            );
        }

        let ttl = Duration::from_secs(
            records
                .iter()
                .map(|r| r.ttl() as u64)
                .min()
                .unwrap_or(MIN_POSITIVE_TTL.as_secs()),
        );
        self.cache.put_positive(zone_key, keys.clone(), ttl);

        // Replace the chain entry for `zone` with the full set of
        // DNSKEYs — keeps both KSK and ZSK so subsequent RRSIGs
        // (signed by ZSK) validate.
        chain_keys.retain(|(n, _)| n != zone);
        chain_keys.push((zone.clone(), keys));
        Ok(())
    }

    /// Query `zone DNSKEY` at one of the given NS IPs. Returns
    /// `(full_records, dnskey_rdata, rrsig)` — the records carry
    /// their signed TTLs so `verify_rrsig` can reconstruct the
    /// canonical form; the rdata vec is a convenience for hash
    /// comparisons against the parent's DS.
    /// Pre-flight per-step DNSKEY fetches: cache+neg-cache lookups
    /// run synchronously, fetches fan out concurrently. The result
    /// vector is indexed by walk step. Failed fetches put the zone
    /// in the negative cache here (so a re-entry while these are
    /// still in flight short-circuits immediately).
    async fn prefetch_step_dnskeys(&self, walk: &WalkChain) -> Vec<StepDnskeyState> {
        let pending = walk.steps.iter().map(|step| {
            let zone = step.zone.clone();
            let zone_lower = zone.to_lowercase();
            let ns_ips = step.ns_ips.clone();
            let ds = step.ds.clone();
            async move {
                if let Some(cached_keys) = self.cache.get_positive(&zone_lower) {
                    let ds_values: Vec<&DS> = ds
                        .iter()
                        .filter_map(|r| match r.data() {
                            Some(RData::DNSSEC(DNSSECRData::DS(d))) => Some(d),
                            _ => None,
                        })
                        .collect();
                    let ds_match = cached_keys.iter().any(|k| {
                        ds_values
                            .iter()
                            .any(|d| d.covers(&zone, k).unwrap_or(false))
                    });
                    if ds_match {
                        return StepDnskeyState::Cached(cached_keys);
                    }
                    self.cache.invalidate_positive(&zone_lower);
                }
                if self.cache.has_negative(&zone_lower) {
                    return StepDnskeyState::Insecure;
                }
                // Fan out — every uncached step's fetch starts here
                // and runs concurrently with all the others (they
                // share the worker pool, but each is just waiting on
                // a UDP/TCP round-trip).
                let fetch = self.fetch_dnskey_rrset(&zone, &ns_ips);
                let fetch_deadline = Duration::from_secs(5);
                match tokio::time::timeout(fetch_deadline, fetch).await {
                    Ok(Ok(tuple)) => StepDnskeyState::Fetched(Ok(tuple)),
                    Ok(Err(e)) => {
                        tracing::warn!(
                            zone = %zone,
                            "DNSKEY fetch failed: {e:#}"
                        );
                        self.cache.put_negative(zone_lower);
                        StepDnskeyState::Fetched(Err(format!("{e:#}")))
                    }
                    Err(_) => {
                        tracing::warn!(
                            zone = %zone,
                            ?fetch_deadline,
                            "DNSKEY fetch timed out"
                        );
                        self.cache.put_negative(zone_lower);
                        StepDnskeyState::Fetched(Err(format!(
                            "DNSKEY fetch timed out ({:?})",
                            fetch_deadline
                        )))
                    }
                }
            }
        });
        futures::future::join_all(pending).await
    }

    async fn fetch_dnskey_rrset(
        &self,
        zone: &Name,
        ns_ips: &[std::net::IpAddr],
    ) -> Result<(Vec<Record>, Vec<DNSKEY>, Option<RRSIG>)> {
        if ns_ips.is_empty() {
            return Err(anyhow!("no NS addresses to query for {zone} DNSKEY"));
        }
        let wire = build_dnskey_query(zone)?;
        // Iterate NSes ourselves rather than calling upstream.query
        // wholesale, so we can log per-NS timing and the actual
        // failure mode. Otherwise a generic timeout is all we see,
        // which made diagnosing the persistent arin.net DNSKEY
        // timeout require redeploys.
        let mut last_err: Option<anyhow::Error> = None;
        for ip in ns_ips {
            let ns_t0 = std::time::Instant::now();
            match self.upstream.query(&[*ip], &wire).await {
                Ok(bytes) => {
                    tracing::info!(
                        zone = %zone,
                        ns = %ip,
                        elapsed_ms = ns_t0.elapsed().as_millis() as u64,
                        size = bytes.len(),
                        "DNSKEY fetch ok"
                    );
                    let resp = Message::from_bytes(&bytes)
                        .with_context(|| format!("parsing DNSKEY response for {zone}"))?;
                    let mut records = Vec::new();
                    let mut keys = Vec::new();
                    let mut sig: Option<RRSIG> = None;
                    let zone_lower = zone.to_lowercase();
                    for r in resp.answers() {
                        if r.name().to_lowercase() != zone_lower {
                            continue;
                        }
                        match r.data() {
                            Some(RData::DNSSEC(DNSSECRData::DNSKEY(k))) => {
                                records.push(r.clone());
                                keys.push(k.clone());
                            }
                            Some(RData::DNSSEC(DNSSECRData::RRSIG(s)))
                                if s.type_covered() == RecordType::DNSKEY =>
                            {
                                sig = Some(s.clone());
                            }
                            _ => {}
                        }
                    }
                    return Ok((records, keys, sig));
                }
                Err(e) => {
                    tracing::info!(
                        zone = %zone,
                        ns = %ip,
                        elapsed_ms = ns_t0.elapsed().as_millis() as u64,
                        "DNSKEY fetch attempt failed: {e:#}"
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("all NSes failed for {zone} DNSKEY")))
    }
}

fn closest_trusted_keys<'a>(
    chain: &'a [(Name, Vec<DNSKEY>)],
    zone: &Name,
) -> Vec<&'a DNSKEY> {
    // Pick the entry whose name is the LONGEST ancestor of `zone`
    // (equivalent to "deepest zone cut above or at `zone`"). Uses
    // hickory's `zone_of`: `self.zone_of(other)` is true when
    // `other` is a subzone of `self`.
    let zone_lower = zone.to_lowercase();
    let mut best: Option<&(Name, Vec<DNSKEY>)> = None;
    for entry in chain {
        if entry.0.to_lowercase() == zone_lower || entry.0.zone_of(&zone_lower) {
            match best {
                None => best = Some(entry),
                Some(b) if entry.0.num_labels() > b.0.num_labels() => best = Some(entry),
                _ => {}
            }
        }
    }
    best.map(|(_, keys)| keys.iter().collect()).unwrap_or_default()
}

fn validate_answer_against_chain(
    resp: &Message,
    chain: &[(Name, Vec<DNSKEY>)],
    qname: &Name,
    qtype: RecordType,
) -> ValidationStatus {
    let mut groups: std::collections::BTreeMap<(Name, RecordType, DNSClass), Vec<Record>> =
        Default::default();
    let mut sigs: Vec<(RRSIG, Record)> = Vec::new();
    for r in resp.answers() {
        match r.data() {
            Some(RData::DNSSEC(DNSSECRData::RRSIG(s))) => sigs.push((s.clone(), r.clone())),
            Some(_) => {
                groups
                    .entry((r.name().clone(), r.record_type(), r.dns_class()))
                    .or_default()
                    .push(r.clone());
            }
            None => {}
        }
    }

    if groups.is_empty() {
        // NXDOMAIN / NODATA — the authoritative denial proof lives
        // in the authority section as NSEC or NSEC3 records. If the
        // chain walk actually reached a signed zone and the denial
        // verifies, promote to Secure; otherwise Insecure.
        return match validate_denial(resp, chain, qname, qtype) {
            DenialOutcome::Secure => ValidationStatus::Secure,
            DenialOutcome::Insecure => ValidationStatus::Insecure,
            DenialOutcome::Bogus(msg) => ValidationStatus::Bogus(msg),
        };
    }

    let mut saw_secure = false;
    for ((name, rtype, _class), rrset) in &groups {
        let (sig, _sig_rec) = match sigs.iter().find(|(s, _)| s.type_covered() == *rtype) {
            Some(s) => s,
            None => return ValidationStatus::Insecure, // unsigned RRset
        };
        if let Err(e) = check_rrsig_validity(sig) {
            return ValidationStatus::Bogus(format!(
                "answer RRSIG for {name}/{rtype:?} invalid: {e}"
            ));
        }
        let signer = sig.signer_name().clone();
        let keys = closest_trusted_keys(chain, &signer);
        if keys.is_empty() {
            return ValidationStatus::Insecure;
        }
        let verified = keys
            .iter()
            .any(|k| verify_rrset(rrset, sig, k).is_ok());
        if !verified {
            return ValidationStatus::Bogus(format!(
                "answer RRSIG for {name}/{rtype:?} did not verify under {signer}"
            ));
        }

        // Wildcard-expansion detection: RFC 4034 §6.2.1 — if the
        // RRSIG's labels field is FEWER than the owner name's label
        // count, the answer was synthesised from a wildcard. Full
        // RFC-compliance requires an NSEC/NSEC3 proof that no exact
        // match for qname exists under the closest encloser (so an
        // attacker can't replay a wildcard answer for a name that
        // DOES have an exact match at the auth server). We accept
        // wildcard answers whose RRSIG validates (the wildcard is
        // signed) as Secure — confirming the nonexistence proof is
        // a v1.x follow-up.
        let owner_labels = name.num_labels();
        if sig.num_labels() < owner_labels {
            tracing::debug!(
                qname = %qname,
                owner = %name,
                sig_labels = sig.num_labels(),
                "wildcard-expanded answer accepted without nonexistence proof (v1 scope)"
            );
        }

        saw_secure = true;
    }

    if saw_secure {
        ValidationStatus::Secure
    } else {
        ValidationStatus::Insecure
    }
}

// --- NSEC / NSEC3 denial-of-existence proofs (RFC 4035 §5,
// --- RFC 5155 §8) ---------------------------------------------

/// Outcome of denial validation. Insecure is the "unsigned zone"
/// case; Secure means a valid NSEC/NSEC3 proof was found AND all
/// its RRSIGs verified.
#[derive(Debug)]
enum DenialOutcome {
    Secure,
    Insecure,
    Bogus(String),
}

/// Walk the authority section looking for NSEC or NSEC3 records
/// that prove either NXDOMAIN or NODATA for (qname, qtype).
fn validate_denial(
    resp: &Message,
    chain: &[(Name, Vec<DNSKEY>)],
    qname: &Name,
    qtype: RecordType,
) -> DenialOutcome {
    // Collect authority records grouped by owner + rtype, plus the
    // RRSIGs covering them. We need the RRSIGs so the verifier can
    // confirm the denial records aren't forgeries.
    let mut nsec_sets: std::collections::BTreeMap<Name, Vec<Record>> = Default::default();
    let mut nsec3_sets: std::collections::BTreeMap<Name, Vec<Record>> = Default::default();
    let mut nsec_rrsigs: std::collections::BTreeMap<Name, Vec<RRSIG>> = Default::default();
    let mut nsec3_rrsigs: std::collections::BTreeMap<Name, Vec<RRSIG>> = Default::default();
    for r in resp.name_servers() {
        match r.data() {
            Some(RData::DNSSEC(DNSSECRData::NSEC(_))) => {
                nsec_sets.entry(r.name().clone()).or_default().push(r.clone());
            }
            Some(RData::DNSSEC(DNSSECRData::NSEC3(_))) => {
                nsec3_sets.entry(r.name().clone()).or_default().push(r.clone());
            }
            Some(RData::DNSSEC(DNSSECRData::RRSIG(s))) => match s.type_covered() {
                RecordType::NSEC => {
                    nsec_rrsigs
                        .entry(r.name().clone())
                        .or_default()
                        .push(s.clone());
                }
                RecordType::NSEC3 => {
                    nsec3_rrsigs
                        .entry(r.name().clone())
                        .or_default()
                        .push(s.clone());
                }
                _ => {}
            },
            _ => {}
        }
    }

    if nsec_sets.is_empty() && nsec3_sets.is_empty() {
        return DenialOutcome::Insecure;
    }

    // Verify every NSEC and NSEC3 RRset with the chain keys.
    // If any fails, the whole denial is Bogus — a partial-forgery
    // attacker can't remove RRSIGs from real denials without being
    // caught.
    if !nsec_sets.is_empty() {
        if let Err(e) = verify_authority_rrsets(&nsec_sets, &nsec_rrsigs, chain) {
            return DenialOutcome::Bogus(e);
        }
    }
    if !nsec3_sets.is_empty() {
        if let Err(e) = verify_authority_rrsets(&nsec3_sets, &nsec3_rrsigs, chain) {
            return DenialOutcome::Bogus(e);
        }
    }

    // Now the proof logic. NSEC3 takes precedence if present (zones
    // don't mix them in a response).
    if !nsec3_sets.is_empty() {
        return prove_denial_nsec3(&nsec3_sets, qname, qtype, resp.response_code());
    }
    prove_denial_nsec(&nsec_sets, qname, qtype, resp.response_code())
}

/// Verify every RRset in `sets` against its covering RRSIG using
/// keys from the validated chain.
fn verify_authority_rrsets(
    sets: &std::collections::BTreeMap<Name, Vec<Record>>,
    rrsigs_by_owner: &std::collections::BTreeMap<Name, Vec<RRSIG>>,
    chain: &[(Name, Vec<DNSKEY>)],
) -> std::result::Result<(), String> {
    for (owner, rrset) in sets {
        let rtype = rrset[0].record_type();
        let sigs = rrsigs_by_owner.get(owner).map(|v| v.as_slice()).unwrap_or(&[]);
        let sig = match sigs.iter().find(|s| s.type_covered() == rtype) {
            Some(s) => s,
            None => return Err(format!("denial RRset at {owner} has no RRSIG")),
        };
        if let Err(e) = check_rrsig_validity(sig) {
            return Err(format!("denial RRSIG at {owner} invalid: {e}"));
        }
        let keys = closest_trusted_keys(chain, sig.signer_name());
        if keys.is_empty() {
            return Err(format!(
                "no trusted keys under {} to verify denial at {owner}",
                sig.signer_name()
            ));
        }
        let verified = keys.iter().any(|k| verify_rrset(rrset, sig, k).is_ok());
        if !verified {
            return Err(format!(
                "denial RRSIG at {owner} did not verify under {}",
                sig.signer_name()
            ));
        }
    }
    Ok(())
}

/// NSEC denial logic (RFC 4035 §5):
///
/// * NODATA: the zone returns an NSEC record with owner = qname
///   whose type-bit-map doesn't contain qtype.
/// * NXDOMAIN: two NSECs (possibly the same in small zones):
///     1. one covering a name range that includes qname
///     2. one covering a name range that includes a synthesised
///        wildcard at the closest encloser (proves no `*.enc`).
fn prove_denial_nsec(
    sets: &std::collections::BTreeMap<Name, Vec<Record>>,
    qname: &Name,
    qtype: RecordType,
    rcode: hickory_proto::op::ResponseCode,
) -> DenialOutcome {
    use hickory_proto::op::ResponseCode;
    let qname_lower = qname.to_lowercase();

    // NODATA?  rcode == NoError AND an NSEC with owner == qname
    // exists whose type-bit-map omits qtype.
    if rcode == ResponseCode::NoError {
        for (owner, records) in sets {
            if owner.to_lowercase() != qname_lower {
                continue;
            }
            let nsec = match records[0].data() {
                Some(RData::DNSSEC(DNSSECRData::NSEC(n))) => n,
                _ => continue,
            };
            if !nsec.type_bit_maps().contains(&qtype) {
                return DenialOutcome::Secure;
            }
            return DenialOutcome::Bogus(format!(
                "NODATA claimed for {qname}/{qtype:?} but NSEC shows type present"
            ));
        }
    }

    // NXDOMAIN: need two NSEC covers.
    if rcode == ResponseCode::NXDomain {
        let mut saw_name_cover = false;
        let mut saw_wildcard_cover = false;
        for (owner, records) in sets {
            let nsec = match records[0].data() {
                Some(RData::DNSSEC(DNSSECRData::NSEC(n))) => n,
                _ => continue,
            };
            let next = nsec.next_domain_name();
            // Name range cover: owner < qname < next (canonical).
            if canonical_lt(owner, &qname_lower) && canonical_lt(&qname_lower, next) {
                saw_name_cover = true;
            }
            // Wildcard cover: find the closest encloser (the longest
            // ancestor of qname that's ALSO an ancestor of owner or
            // next). Then check a synthetic "*.encloser" falls in a
            // gap.
            let encloser = closest_encloser(&qname_lower, &[owner.clone(), next.clone()]);
            let wildcard = match synthetic_wildcard(&encloser) {
                Some(w) => w,
                None => continue,
            };
            if canonical_lt(owner, &wildcard) && canonical_lt(&wildcard, next) {
                saw_wildcard_cover = true;
            }
            // Edge case: the NSEC at the wildcard itself proves
            // *.encloser doesn't have the requested type — but we're
            // here on NXDOMAIN so the wildcard shouldn't exist at
            // all. Accept if owner == wildcard & type bitmap omits
            // qtype (strict wildcard NoData on an NXDOMAIN-style
            // response is an edge case most zones don't hit).
            if owner.to_lowercase() == wildcard {
                if !nsec.type_bit_maps().contains(&qtype) {
                    saw_wildcard_cover = true;
                }
            }
        }
        if saw_name_cover && saw_wildcard_cover {
            return DenialOutcome::Secure;
        }
        return DenialOutcome::Bogus(format!(
            "NSEC NXDOMAIN proof incomplete for {qname}: name_cover={saw_name_cover} wildcard_cover={saw_wildcard_cover}"
        ));
    }

    DenialOutcome::Insecure
}

/// NSEC3 denial logic (RFC 5155 §8). NSEC3 hashes the owner names
/// so proofs operate on hash intervals instead of name intervals.
/// Uses hickory's built-in SHA1 hasher — the only hash algorithm
/// defined for NSEC3 at time of writing.
fn prove_denial_nsec3(
    sets: &std::collections::BTreeMap<Name, Vec<Record>>,
    qname: &Name,
    qtype: RecordType,
    rcode: hickory_proto::op::ResponseCode,
) -> DenialOutcome {
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::dnssec::Nsec3HashAlgorithm;

    // Pull salt + iterations from the first NSEC3 — all NSEC3s in a
    // zone share parameters.
    let mut first_nsec3: Option<&hickory_proto::rr::dnssec::rdata::NSEC3> = None;
    for records in sets.values() {
        if let Some(RData::DNSSEC(DNSSECRData::NSEC3(n))) = records[0].data() {
            first_nsec3 = Some(n);
            break;
        }
    }
    let params = match first_nsec3 {
        Some(n) => n,
        None => return DenialOutcome::Insecure,
    };
    let salt = params.salt().to_vec();
    let iter = params.iterations();
    let hash_algo = params.hash_algorithm();
    if hash_algo != Nsec3HashAlgorithm::SHA1 {
        return DenialOutcome::Bogus(format!("unsupported NSEC3 hash algo {hash_algo:?}"));
    }

    // Parse each NSEC3 into (hash_of_owner, next_hashed, type_bits).
    let mut intervals: Vec<(Vec<u8>, Vec<u8>, Vec<RecordType>, bool)> = Vec::new();
    for (owner, records) in sets {
        let nsec3 = match records[0].data() {
            Some(RData::DNSSEC(DNSSECRData::NSEC3(n))) => n,
            _ => continue,
        };
        // The NSEC3 owner name's leftmost label IS the base32-hex-
        // encoded hash of some zone owner. Decode it.
        let leftmost = match owner.iter().next() {
            Some(l) => l,
            None => continue,
        };
        let owner_hash = match base32_hex_decode(leftmost) {
            Some(h) => h,
            None => continue,
        };
        let next_hash = nsec3.next_hashed_owner_name().to_vec();
        intervals.push((
            owner_hash,
            next_hash,
            nsec3.type_bit_maps().to_vec(),
            nsec3.opt_out(),
        ));
    }

    // Helper: hash a name with the zone's NSEC3 params.
    let hash_of = |name: &Name| -> Option<Vec<u8>> {
        Nsec3HashAlgorithm::SHA1
            .hash(&salt, name, iter)
            .ok()
            .map(|d| d.as_ref().to_vec())
    };

    // NODATA: NSEC3 at H(qname) with type bitmap lacking qtype.
    if rcode == ResponseCode::NoError {
        let target = match hash_of(qname) {
            Some(h) => h,
            None => return DenialOutcome::Insecure,
        };
        for (owner_hash, _, types, _) in &intervals {
            if owner_hash == &target {
                if !types.contains(&qtype) {
                    return DenialOutcome::Secure;
                }
                return DenialOutcome::Bogus(format!(
                    "NSEC3 NODATA claim contradicted by type bitmap for {qname}/{qtype:?}"
                ));
            }
        }
        // No exact-match NSEC3 for NODATA. This could still be an
        // opt-out NODATA, but for simplicity we treat it as Insecure.
        return DenialOutcome::Insecure;
    }

    // NXDOMAIN: need (a) closest-encloser proof + (b) next-closer
    // name coverage + (c) wildcard-at-encloser coverage.
    if rcode == ResponseCode::NXDomain {
        // Closest encloser: longest ancestor of qname whose hash
        // matches an NSEC3 owner.
        let mut closest_encloser: Option<Name> = None;
        let mut current = qname.clone();
        while current.num_labels() > 0 {
            current = match current.trim_to(current.num_labels() as usize - 1) {
                n => n,
            };
            let h = match hash_of(&current) {
                Some(h) => h,
                None => break,
            };
            if intervals.iter().any(|(o, _, _, _)| o == &h) {
                closest_encloser = Some(current.clone());
                break;
            }
            if current.is_root() {
                break;
            }
        }
        let encloser = match closest_encloser {
            Some(e) => e,
            None => {
                return DenialOutcome::Bogus(format!(
                    "NSEC3 NXDOMAIN: no closest-encloser found for {qname}"
                ));
            }
        };

        // Next-closer name: qname truncated to encloser.num_labels()+1.
        let nc_labels = encloser.num_labels() as usize + 1;
        if nc_labels > qname.num_labels() as usize {
            return DenialOutcome::Bogus(format!(
                "NSEC3 NXDOMAIN: {qname} same as closest encloser {encloser}"
            ));
        }
        let next_closer = qname.trim_to(nc_labels);
        let nc_hash = match hash_of(&next_closer) {
            Some(h) => h,
            None => return DenialOutcome::Insecure,
        };
        let nc_covered = intervals
            .iter()
            .any(|(o, n, _, _)| hash_in_range(&nc_hash, o, n));
        if !nc_covered {
            return DenialOutcome::Bogus(format!(
                "NSEC3 NXDOMAIN: no NSEC3 covers next-closer {next_closer}"
            ));
        }

        // Wildcard at encloser.
        let wildcard = match prepend_wildcard(&encloser) {
            Some(w) => w,
            None => return DenialOutcome::Insecure,
        };
        let wc_hash = match hash_of(&wildcard) {
            Some(h) => h,
            None => return DenialOutcome::Insecure,
        };
        let wc_covered = intervals
            .iter()
            .any(|(o, n, _, _)| hash_in_range(&wc_hash, o, n) || o == &wc_hash);
        if !wc_covered {
            return DenialOutcome::Bogus(format!(
                "NSEC3 NXDOMAIN: no NSEC3 covers wildcard {wildcard}"
            ));
        }

        return DenialOutcome::Secure;
    }

    DenialOutcome::Insecure
}

/// Canonical DNS name ordering per RFC 4034 §6.1. Compare labels
/// right-to-left, lowercase byte-wise. hickory's `Name::cmp` does
/// this already — this is just a thin predicate wrapper.
fn canonical_lt(a: &Name, b: &Name) -> bool {
    a.to_lowercase().cmp(&b.to_lowercase()) == std::cmp::Ordering::Less
}

/// Compute the closest encloser of `qname` given the owner and next
/// names of an NSEC. For our purposes "closest encloser" is the
/// longest suffix of qname that is also a suffix of either bound —
/// the NSEC ownership interval necessarily contains qname's
/// ancestors up to some point.
fn closest_encloser(qname: &Name, candidates: &[Name]) -> Name {
    let mut best = Name::root();
    for cand in candidates {
        let cand_lower = cand.to_lowercase();
        // Walk qname's ancestors; pick the longest one that's an
        // ancestor of the candidate too.
        let mut anc = qname.clone();
        while anc.num_labels() > 0 {
            if anc.zone_of(&cand_lower) || anc == cand_lower {
                if anc.num_labels() > best.num_labels() {
                    best = anc.clone();
                }
                break;
            }
            anc = anc.trim_to(anc.num_labels() as usize - 1);
        }
    }
    best
}

/// Synthesise `*.owner` — used for NSEC wildcard-cover proofs.
fn synthetic_wildcard(owner: &Name) -> Option<Name> {
    prepend_wildcard(owner)
}

fn prepend_wildcard(owner: &Name) -> Option<Name> {
    Name::from_ascii("*")
        .ok()?
        .append_domain(owner)
        .ok()
        .map(|n| n.to_lowercase())
}

fn hash_in_range(target: &[u8], owner_hash: &[u8], next_hash: &[u8]) -> bool {
    // NSEC3 intervals are ORDERED ranges on the hash axis. A hash h
    // is "covered" when owner_hash < h < next_hash, with wrap-around
    // at the end of the zone.
    use std::cmp::Ordering;
    match (owner_hash.cmp(target), target.cmp(next_hash)) {
        (Ordering::Less, Ordering::Less) => true,
        _ => {
            // Wrap case: owner_hash > next_hash means the range
            // spans the zero boundary. Target is covered if it's
            // greater than owner or less than next.
            if owner_hash.cmp(next_hash) == Ordering::Greater {
                owner_hash.cmp(target) == Ordering::Less
                    || target.cmp(next_hash) == Ordering::Less
            } else {
                false
            }
        }
    }
}

/// Decode a base32-hex (RFC 4648 §7) octet sequence from a leftmost-
/// label byte slice. NSEC3 owner names use this encoding.
fn base32_hex_decode(label: &[u8]) -> Option<Vec<u8>> {
    // Uppercase the label first — the spec says base32hex is
    // case-insensitive and hickory sometimes delivers lowercase.
    let upper: String = std::str::from_utf8(label).ok()?.to_ascii_uppercase();
    data_encoding::BASE32HEX_NOPAD.decode(upper.as_bytes()).ok()
}

/// Build a DNSKEY query for `zone`. Always sets DO=1 — otherwise
/// the server omits the covering RRSIG which is what we actually
/// need.
pub(crate) fn build_dnskey_query(zone: &Name) -> Result<Vec<u8>> {
    let mut msg = Message::new();
    msg.set_id(rand::random());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false);
    let mut q = Query::query(zone.clone(), RecordType::DNSKEY);
    q.set_query_class(DNSClass::IN);
    msg.add_query(q);
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(1232);
    edns.set_version(0);
    edns.set_dnssec_ok(true);
    msg.set_edns(edns);
    msg.to_vec().context("encode DNSKEY query")
}

/// Validity-window + sanity check on an RRSIG. Catches expired
/// signatures (RFC 4034 §3.1.5) and garbage inception/expiry.
fn check_rrsig_validity(sig: &RRSIG) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let inception = sig.sig_inception();
    let expiration = sig.sig_expiration();
    if expiration < inception {
        return Err(anyhow!(
            "RRSIG expiration {expiration} precedes inception {inception}"
        ));
    }
    let skew = CLOCK_SKEW.as_secs() as u32;
    if now + skew < inception {
        return Err(anyhow!(
            "RRSIG inception {inception} is > clock+skew {}",
            now + skew
        ));
    }
    if now > expiration + skew {
        return Err(anyhow!(
            "RRSIG expired at {expiration} (now={now}, skew={skew})"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};

    fn make_response(ad: bool) -> Message {
        let mut m = Message::new();
        m.set_message_type(MessageType::Response);
        m.set_op_code(OpCode::Query);
        m.set_response_code(ResponseCode::NoError);
        m.set_authentic_data(ad);
        m
    }

    #[test]
    fn pass_through_preserves_ad() {
        let mut m = make_response(true);
        DnssecPolicy::PassThrough.apply_to_response(&mut m);
        assert!(m.authentic_data());
    }

    #[test]
    fn strip_clears_ad() {
        let mut m = make_response(true);
        DnssecPolicy::Strip.apply_to_response(&mut m);
        assert!(!m.authentic_data());
    }

    #[test]
    fn validate_strips_until_chain_walk_lands() {
        let mut m = make_response(true);
        DnssecPolicy::Validate.apply_to_response(&mut m);
        assert!(
            !m.authentic_data(),
            "without a real chain walker we must never leak AD=1"
        );
    }

    #[test]
    fn policy_from_config_defaults_to_pass_through() {
        assert_eq!(
            DnssecPolicy::from_recursion(None),
            DnssecPolicy::PassThrough
        );
    }

    #[test]
    fn policy_validate_when_mode_is_validate() {
        use crate::config::DnssecMode;
        let r = Recursion {
            enabled: true,
            dnssec: DnssecMode::Validate,
            ..Default::default()
        };
        assert_eq!(
            DnssecPolicy::from_recursion(Some(&r)),
            DnssecPolicy::Validate
        );
    }

    #[test]
    fn policy_validate_honours_legacy_boolean() {
        // Pre-v1 configs that wrote `dnssec_validate: true` without
        // the new `dnssec:` enum still promote to Validate. Exercises
        // `Recursion::effective_dnssec`.
        let r = Recursion {
            enabled: true,
            dnssec_validate: true,
            ..Default::default()
        };
        assert_eq!(
            DnssecPolicy::from_recursion(Some(&r)),
            DnssecPolicy::Validate
        );
    }

    #[test]
    fn policy_strip_when_mode_is_strip() {
        use crate::config::DnssecMode;
        let r = Recursion {
            enabled: true,
            dnssec: DnssecMode::Strip,
            ..Default::default()
        };
        assert_eq!(
            DnssecPolicy::from_recursion(Some(&r)),
            DnssecPolicy::Strip
        );
    }

    #[test]
    fn explicit_dnssec_overrides_legacy_boolean() {
        // If operator wrote both (unlikely in practice), the
        // explicit `dnssec:` enum wins.
        use crate::config::DnssecMode;
        let r = Recursion {
            enabled: true,
            dnssec: DnssecMode::Strip,
            dnssec_validate: true,
            ..Default::default()
        };
        assert_eq!(
            DnssecPolicy::from_recursion(Some(&r)),
            DnssecPolicy::Strip
        );
    }

    #[test]
    fn trust_anchor_parses_unbound_root_key() {
        // A real-shape .  DNSKEY record (root KSK-2017-ish; the
        // base64 here is intentionally a placeholder that has valid
        // base64 but not a real key — parsing is what's under test,
        // not cryptographic correctness).
        let raw = r#"
; the root KSK
.       172800  IN      DNSKEY  257 3 8 AwEAAcoGlCP1+vrZMw/baseline=
.       172800  IN      DNSKEY  256 3 8 AwEAAfakeZSKeyMaterial=
"#;
        let ta = parse_presentation_format(raw).expect("parse");
        assert_eq!(ta.len(), 2, "expected KSK + ZSK");
        assert_eq!(
            ta.dnskeys_for(&hickory_proto::rr::Name::from_ascii(".").unwrap())
                .len(),
            2
        );
    }

    #[test]
    fn empty_trust_anchor_file_parses_cleanly() {
        let ta = parse_presentation_format("; just a comment\n\n\n").unwrap();
        assert!(ta.is_empty());
    }

    #[test]
    fn validate_empty_answers_is_insecure() {
        let m = make_response(false);
        let ta = TrustAnchors::new();
        assert!(matches!(
            validate_response(&m, &ta),
            ValidationStatus::Insecure
        ));
    }
}
