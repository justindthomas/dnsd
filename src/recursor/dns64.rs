//! DNS64 synthesis (RFC 6147).
//!
//! Behaviours:
//!
//! * **AAAA synthesis.** When an AAAA query returns NODATA or
//!   NXDOMAIN (and the listener has DNS64 enabled, and the name is
//!   not excluded), fire the corresponding A query and synthesise
//!   AAAA responses by embedding each A into the operator-configured
//!   NAT64 prefix.
//!
//! * **PTR synthesis.** An `ip6.arpa` PTR that lands inside the NAT64
//!   prefix is rewritten as the equivalent `in-addr.arpa` query.
//!   (Per RFC 6147 §5.3.1, the resolver then forwards the v4 PTR
//!   upstream; we just return the decoded v4 and let the dispatcher
//!   issue the follow-up.)
//!
//! * **AD bit suppression.** Synthesised AAAA MUST NOT carry AD=1
//!   (RFC 6147 §5.5) because the RRSIG on the A doesn't cover the
//!   synthesised AAAA.
//!
//! Exclusions:
//!
//! * `ipv4only.arpa` — a DNS64 client uses this to discover whether
//!   it's sitting behind a synthesiser; we must return the real AAAA
//!   (RFC 7050) which upstream handles naturally.
//! * Operator-configured FQDN suffixes.
//!
//! Prefix format: RFC 6052 defines embeddings for /32, /40, /48,
//! /56, /64, /96 NAT64 prefixes. /96 (the WKP `64:ff9b::/96` default)
//! is the simple case where the last 32 bits of the v6 address are
//! the v4. The others skip the `u` byte at position 64/71. We
//! support them all because the parser is trivial once the pattern
//! is in place.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{AAAA, PTR};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use ipnet::Ipv6Net;

use crate::config::Dns64 as Dns64Cfg;

pub const DEFAULT_PREFIX: &str = "64:ff9b::/96";
pub const DEFAULT_EXCLUSIONS: &[&str] = &["ipv4only.arpa."];

#[derive(Clone, Debug)]
pub struct Dns64Policy {
    pub prefix: Ipv6Net,
    pub exclusions: Vec<Name>,
}

impl Dns64Policy {
    pub fn from_config(cfg: &Dns64Cfg) -> anyhow::Result<Self> {
        let prefix_str = cfg.prefix.clone().unwrap_or_else(|| DEFAULT_PREFIX.into());
        let prefix: Ipv6Net = prefix_str.parse()
            .map_err(|e| anyhow::anyhow!("invalid dns64 prefix {prefix_str:?}: {e}"))?;
        if !valid_prefix_length(prefix.prefix_len()) {
            anyhow::bail!(
                "dns64 prefix length {} not valid per RFC 6052 (must be 32/40/48/56/64/96)",
                prefix.prefix_len()
            );
        }
        let mut exclusions = Vec::with_capacity(cfg.exclusions.len() + DEFAULT_EXCLUSIONS.len());
        for default in DEFAULT_EXCLUSIONS {
            exclusions.push(Name::from_ascii(default).unwrap().to_lowercase());
        }
        for e in &cfg.exclusions {
            exclusions.push(
                Name::from_ascii(e)
                    .map_err(|err| anyhow::anyhow!("bad dns64 exclusion {e:?}: {err}"))?
                    .to_lowercase(),
            );
        }
        Ok(Self { prefix, exclusions })
    }

    /// Default policy (WKP /96 prefix, only the ipv4only.arpa
    /// exclusion). Used when the operator enables `dns64: true` on
    /// a listener without any global `dns.dns64:` block.
    pub fn default_wkp() -> Self {
        Self {
            prefix: DEFAULT_PREFIX.parse().expect("WKP prefix parses"),
            exclusions: DEFAULT_EXCLUSIONS
                .iter()
                .map(|s| Name::from_ascii(s).unwrap().to_lowercase())
                .collect(),
        }
    }

    pub fn is_excluded(&self, qname: &Name) -> bool {
        let lq = qname.to_lowercase();
        self.exclusions.iter().any(|ex| lq.zone_of(ex) || &lq == ex)
    }
}

fn valid_prefix_length(len: u8) -> bool {
    matches!(len, 32 | 40 | 48 | 56 | 64 | 96)
}

/// Embed an IPv4 address into the given NAT64 prefix per RFC 6052 §2.2.
///
/// Positions:
///   /32  → v4 at bits 32..64
///   /40  → v4 at 40..72, skip the suffix byte at 64..72 (u bits MUST be 0)
///   /48  → v4 at 48..80, skip u at 64..72
///   /56  → v4 at 56..88, skip u at 64..72
///   /64  → v4 at 72..104 (skip u at 64..72)
///   /96  → v4 at 96..128
pub fn embed_v4(prefix: &Ipv6Net, v4: Ipv4Addr) -> Ipv6Addr {
    let mut addr = prefix.addr().octets();
    let v4_bytes = v4.octets();
    match prefix.prefix_len() {
        32 => addr[4..8].copy_from_slice(&v4_bytes),
        40 => {
            addr[5..8].copy_from_slice(&v4_bytes[0..3]);
            addr[8] = 0; // u bits
            addr[9] = v4_bytes[3];
        }
        48 => {
            addr[6..8].copy_from_slice(&v4_bytes[0..2]);
            addr[8] = 0;
            addr[9..11].copy_from_slice(&v4_bytes[2..4]);
        }
        56 => {
            addr[7] = v4_bytes[0];
            addr[8] = 0;
            addr[9..12].copy_from_slice(&v4_bytes[1..4]);
        }
        64 => {
            addr[8] = 0;
            addr[9..13].copy_from_slice(&v4_bytes);
        }
        96 => addr[12..16].copy_from_slice(&v4_bytes),
        _ => unreachable!("valid_prefix_length should have caught this"),
    }
    Ipv6Addr::from(addr)
}

/// Reverse of `embed_v4`. Returns `Some(v4)` if `addr` is inside
/// `prefix` and the embedded v4 decodes cleanly; `None` otherwise.
pub fn extract_v4(prefix: &Ipv6Net, addr: Ipv6Addr) -> Option<Ipv4Addr> {
    if !prefix.contains(&addr) {
        return None;
    }
    let o = addr.octets();
    let v4 = match prefix.prefix_len() {
        32 => Ipv4Addr::new(o[4], o[5], o[6], o[7]),
        40 => Ipv4Addr::new(o[5], o[6], o[7], o[9]),
        48 => Ipv4Addr::new(o[6], o[7], o[9], o[10]),
        56 => Ipv4Addr::new(o[7], o[9], o[10], o[11]),
        64 => Ipv4Addr::new(o[9], o[10], o[11], o[12]),
        96 => Ipv4Addr::new(o[12], o[13], o[14], o[15]),
        _ => return None,
    };
    Some(v4)
}

/// Decode an `ip6.arpa` question name into the underlying IPv6
/// address. Returns `None` if the label structure is wrong.
pub fn ip6_arpa_to_addr(name: &Name) -> Option<Ipv6Addr> {
    // ip6.arpa has 32 single-nibble labels before the "ip6.arpa."
    // literal; iterate and concatenate high-first.
    let lower = name.to_lowercase();
    if lower.num_labels() != 32 + 2 {
        return None;
    }
    let labels: Vec<_> = lower.iter().collect();
    if labels.len() < 34 {
        return None;
    }
    // Last two labels MUST be "ip6" and "arpa".
    if labels[32] != b"ip6".as_slice() || labels[33] != b"arpa".as_slice() {
        return None;
    }
    let mut nibbles = [0u8; 32];
    for (i, lbl) in labels[..32].iter().enumerate() {
        if lbl.len() != 1 {
            return None;
        }
        let c = lbl[0] as char;
        let n = c.to_digit(16)? as u8;
        // Label order is little-end-first: "0.0.0.0.0.0.0.0....6.f.f.4.6.0.arpa".
        // So label[0] is nibble 0 (low). Flip.
        nibbles[31 - i] = n;
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = (nibbles[i * 2] << 4) | nibbles[i * 2 + 1];
    }
    Some(Ipv6Addr::from(bytes))
}

/// Decide whether an AAAA query with an empty/NXDOMAIN answer should
/// trigger DNS64 synthesis. Checks listener-opt-in, exclusion list,
/// and the response shape.
pub fn should_synthesise(
    policy: Option<&Dns64Policy>,
    listener_enabled: bool,
    qname: &Name,
    qtype: RecordType,
    response: &Message,
) -> bool {
    if !listener_enabled {
        return false;
    }
    let Some(policy) = policy else { return false };
    if qtype != RecordType::AAAA {
        return false;
    }
    if policy.is_excluded(qname) {
        return false;
    }
    // Two triggers: NODATA (NoError + empty answers) or NXDOMAIN.
    match response.response_code() {
        ResponseCode::NoError => response.answers().is_empty(),
        ResponseCode::NXDomain => true,
        _ => false,
    }
}

/// Rewrite an A response into a DNS64-synthesised AAAA response.
/// The original query section is preserved, TTLs come from the A
/// records, AD bit is cleared per RFC 6147 §5.5.
pub fn synthesise_from_a(
    policy: &Dns64Policy,
    original_query: &Message,
    a_response: &Message,
) -> Message {
    let mut resp = Message::new();
    resp.set_id(original_query.id());
    resp.set_message_type(hickory_proto::op::MessageType::Response);
    resp.set_op_code(hickory_proto::op::OpCode::Query);
    resp.set_recursion_desired(original_query.recursion_desired());
    resp.set_recursion_available(true);
    resp.set_response_code(ResponseCode::NoError);
    // AD MUST be 0 for synthesised responses (RFC 6147 §5.5).
    resp.set_authentic_data(false);
    for q in original_query.queries() {
        resp.add_query(q.clone());
    }
    for rec in a_response.answers() {
        if rec.record_type() != RecordType::A {
            continue;
        }
        let Some(RData::A(a)) = rec.data() else { continue };
        let v6 = embed_v4(&policy.prefix, a.0);
        let mut new_rec = Record::from_rdata(rec.name().clone(), rec.ttl(), RData::AAAA(AAAA(v6)));
        new_rec.set_dns_class(rec.dns_class());
        resp.add_answer(new_rec);
    }
    resp
}

/// Rewrite an `ip6.arpa` PTR question into the equivalent
/// `in-addr.arpa` question when the address falls under our NAT64
/// prefix. Returns the synthesised v4 query or `None` if this PTR
/// isn't a DNS64 candidate.
pub fn rewrite_ptr_question(policy: &Dns64Policy, qname: &Name) -> Option<Name> {
    let addr = ip6_arpa_to_addr(qname)?;
    let v4 = extract_v4(&policy.prefix, addr)?;
    let o = v4.octets();
    let ascii = format!(
        "{}.{}.{}.{}.in-addr.arpa.",
        o[3], o[2], o[1], o[0]
    );
    Name::from_ascii(&ascii).ok()
}

/// Rewrap a PTR response sourced from an in-addr.arpa lookup so that
/// it answers an ip6.arpa question. Preserves RDATA (the PTR target
/// name) but swaps the owner name.
pub fn rewrap_ptr_response(
    original_query: &Message,
    v4_response: &Message,
) -> Message {
    let original_qname = match original_query.queries().first() {
        Some(q) => q.name().clone(),
        None => return v4_response.clone(),
    };
    let mut resp = Message::new();
    resp.set_id(original_query.id());
    resp.set_message_type(hickory_proto::op::MessageType::Response);
    resp.set_op_code(hickory_proto::op::OpCode::Query);
    resp.set_recursion_desired(original_query.recursion_desired());
    resp.set_recursion_available(true);
    resp.set_response_code(v4_response.response_code());
    resp.set_authentic_data(false); // AD cleared for synthesised
    for q in original_query.queries() {
        resp.add_query(q.clone());
    }
    for rec in v4_response.answers() {
        if rec.record_type() != RecordType::PTR {
            continue;
        }
        let Some(RData::PTR(ptr)) = rec.data() else { continue };
        let mut new_rec = Record::from_rdata(
            original_qname.clone(),
            rec.ttl(),
            RData::PTR(PTR(ptr.0.clone())),
        );
        new_rec.set_dns_class(DNSClass::IN);
        resp.add_answer(new_rec);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wkp() -> Dns64Policy {
        Dns64Policy::default_wkp()
    }

    #[test]
    fn embed_and_extract_wkp() {
        let policy = wkp();
        let v4: Ipv4Addr = "192.0.2.33".parse().unwrap();
        let v6 = embed_v4(&policy.prefix, v4);
        assert_eq!(v6, "64:ff9b::c000:221".parse::<Ipv6Addr>().unwrap());
        assert_eq!(extract_v4(&policy.prefix, v6), Some(v4));
    }

    #[test]
    fn embed_and_extract_all_lengths() {
        let cases = [
            ("2001:db8::/32", "203.0.113.5"),
            ("2001:db8:1234::/48", "203.0.113.5"),
            ("2001:db8:aaaa:bbbb::/64", "203.0.113.5"),
            ("64:ff9b::/96", "203.0.113.5"),
        ];
        for (prefix, v4) in cases {
            let p: Ipv6Net = prefix.parse().unwrap();
            let v4a: Ipv4Addr = v4.parse().unwrap();
            let v6 = embed_v4(&p, v4a);
            assert_eq!(
                extract_v4(&p, v6),
                Some(v4a),
                "round-trip failed for prefix {prefix}"
            );
        }
    }

    #[test]
    fn ip6_arpa_decodes_to_address() {
        let n = Name::from_ascii(
            "1.2.2.0.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa.",
        )
        .unwrap();
        let addr = ip6_arpa_to_addr(&n).unwrap();
        assert_eq!(addr, "64:ff9b::c000:221".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn ptr_question_rewrite_only_under_prefix() {
        let policy = wkp();
        // ip6.arpa PTR for 64:ff9b::c000:221 → 33.2.0.192.in-addr.arpa.
        let ip6_ptr = Name::from_ascii(
            "1.2.2.0.0.0.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa.",
        )
        .unwrap();
        let rewritten = rewrite_ptr_question(&policy, &ip6_ptr).unwrap();
        assert_eq!(
            rewritten,
            Name::from_ascii("33.2.0.192.in-addr.arpa.").unwrap()
        );

        // Outside the prefix: no rewrite.
        let outside = Name::from_ascii(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.ip6.arpa.",
        )
        .unwrap();
        assert!(rewrite_ptr_question(&policy, &outside).is_none());
    }

    #[test]
    fn exclusions_cover_ipv4only_arpa() {
        let policy = wkp();
        assert!(policy.is_excluded(&Name::from_ascii("ipv4only.arpa.").unwrap()));
        assert!(policy.is_excluded(&Name::from_ascii("sub.ipv4only.arpa.").unwrap()));
        assert!(!policy.is_excluded(&Name::from_ascii("example.com.").unwrap()));
    }

    #[test]
    fn should_synthesise_triggers() {
        use hickory_proto::op::{MessageType, Query};
        let policy = wkp();
        let mut resp = Message::new();
        resp.set_message_type(MessageType::Response);
        resp.set_response_code(ResponseCode::NoError);
        // NODATA: NoError with no answers.
        assert!(should_synthesise(
            Some(&policy),
            true,
            &Name::from_ascii("example.com.").unwrap(),
            RecordType::AAAA,
            &resp
        ));

        // NXDOMAIN also triggers.
        resp.set_response_code(ResponseCode::NXDomain);
        assert!(should_synthesise(
            Some(&policy),
            true,
            &Name::from_ascii("example.com.").unwrap(),
            RecordType::AAAA,
            &resp
        ));

        // SERVFAIL does not.
        resp.set_response_code(ResponseCode::ServFail);
        assert!(!should_synthesise(
            Some(&policy),
            true,
            &Name::from_ascii("example.com.").unwrap(),
            RecordType::AAAA,
            &resp
        ));

        // A query never triggers.
        resp.set_response_code(ResponseCode::NoError);
        assert!(!should_synthesise(
            Some(&policy),
            true,
            &Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            &resp
        ));

        // Listener off → never triggers.
        assert!(!should_synthesise(
            Some(&policy),
            false,
            &Name::from_ascii("example.com.").unwrap(),
            RecordType::AAAA,
            &resp
        ));

        // Excluded name → never triggers.
        assert!(!should_synthesise(
            Some(&policy),
            true,
            &Name::from_ascii("ipv4only.arpa.").unwrap(),
            RecordType::AAAA,
            &resp
        ));

        // No policy → never triggers.
        assert!(!should_synthesise(
            None,
            true,
            &Name::from_ascii("example.com.").unwrap(),
            RecordType::AAAA,
            &resp
        ));

        let _ = Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::AAAA);
    }

    #[test]
    fn synthesise_preserves_ttl_and_clears_ad() {
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::A;
        let policy = wkp();
        let mut original = Message::new();
        original.set_id(0xbeef);
        original.set_message_type(MessageType::Query);
        original.set_op_code(OpCode::Query);
        original.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::AAAA,
        ));

        let mut a_resp = Message::new();
        a_resp.set_id(0xbeef);
        a_resp.set_message_type(MessageType::Response);
        a_resp.set_response_code(ResponseCode::NoError);
        a_resp.set_authentic_data(true);
        let mut rec = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            123,
            RData::A(A::new(192, 0, 2, 33)),
        );
        rec.set_dns_class(DNSClass::IN);
        a_resp.add_answer(rec);

        let synth = synthesise_from_a(&policy, &original, &a_resp);
        assert_eq!(synth.id(), 0xbeef);
        assert_eq!(synth.queries().len(), 1);
        assert_eq!(synth.answers().len(), 1);
        let ans = &synth.answers()[0];
        assert_eq!(ans.ttl(), 123);
        assert_eq!(ans.record_type(), RecordType::AAAA);
        assert!(!synth.authentic_data(), "AD must be cleared for synthesised AAAA");
        if let Some(RData::AAAA(aaaa)) = ans.data() {
            assert_eq!(aaaa.0, "64:ff9b::c000:221".parse::<Ipv6Addr>().unwrap());
        } else {
            panic!("expected AAAA answer");
        }
    }

    #[test]
    fn reject_bad_prefix_lengths() {
        for bad in [24u8, 50, 72, 100, 128] {
            let cfg = Dns64Cfg {
                prefix: Some(format!("2001:db8::/{bad}")),
                exclusions: vec![],
            };
            assert!(
                Dns64Policy::from_config(&cfg).is_err(),
                "prefix /{bad} should be rejected"
            );
        }
    }
}
