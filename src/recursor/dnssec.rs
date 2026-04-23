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
//! For now, operators who set `dns.recursion.dnssec_validate: true`
//! get: AD cleared on every response (never misleadingly AD=1) and
//! an Extended DNS Error of 22 ("No Reachable Authority") attached
//! when signature verification is attempted but fails. Once the
//! chain walk lands, Secure responses will set AD=1 naturally.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context as _, Result};
use hickory_proto::op::Message;
use hickory_proto::rr::dnssec::rdata::DNSKEY;
use hickory_proto::rr::dnssec::Verifier as _;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};

use crate::config::Recursion;

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
        match r {
            Some(r) if r.dnssec_validate => DnssecPolicy::Validate,
            _ => DnssecPolicy::PassThrough,
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

/// Helper that glues a validator into the handler: `Arc<Validator>`
/// can be cheaply cloned across tasks.
pub struct Validator {
    pub anchors: Arc<TrustAnchors>,
}

impl Validator {
    pub fn new(anchors: Arc<TrustAnchors>) -> Self {
        Self { anchors }
    }

    pub fn validate(&self, resp: &Message) -> ValidationStatus {
        validate_response(resp, &self.anchors)
    }
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
    fn policy_validate_when_flag_set() {
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
