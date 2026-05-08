//! RFC 8880 §7.2 local-answer treatment for `ipv4only.arpa`.
//!
//! `ipv4only.arpa` is the IETF-blessed probe a DNS64 client uses to
//! discover whether it sits behind a synthesiser. The IANA-registered
//! A records are static (192.0.0.170 and 192.0.0.171) and the PTR
//! records under `170.0.0.192.in-addr.arpa` / `171.0.0.192.in-addr.arpa`
//! point back at `ipv4only.arpa`. RFC 8880 says a recursor SHOULD
//! answer all of these locally — acting as if it were authoritative
//! for the zone — rather than forwarding upstream.
//!
//! Behaviours:
//!
//! * **A query for `ipv4only.arpa`** → both A records.
//! * **AAAA query for `ipv4only.arpa`, listener has DNS64**
//!   → synthesised AAAA pair under the configured NAT64 prefix.
//! * **AAAA query for `ipv4only.arpa`, listener has no DNS64**
//!   → NODATA (NoError with no answers).
//! * **PTR query for `170.0.0.192.in-addr.arpa.` /
//!   `171.0.0.192.in-addr.arpa.`** → `ipv4only.arpa.`
//!
//! AD bit is always cleared on these synthesised answers — there's
//! no upstream RRSIG covering them.

use std::net::Ipv4Addr;

use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, PTR};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use super::dns64::{embed_v4, Dns64Policy};

/// TTL for our synthesised answers. RFC 8880 doesn't pin a value; the
/// records are static so any reasonable TTL works. 1h matches what
/// the IANA-operated nameservers serve.
const LOCAL_TTL: u32 = 3_600;

const A_170: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 170);
const A_171: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 171);

/// Names whose PTR queries map back to `ipv4only.arpa.` per RFC 8880.
const PTR_NAMES: &[&str] = &[
    "170.0.0.192.in-addr.arpa.",
    "171.0.0.192.in-addr.arpa.",
];

/// True when (qname, qtype) is one of the names we should answer
/// locally per RFC 8880 §7.2.
pub fn is_local_question(qname: &Name, qtype: RecordType) -> bool {
    let lower_name = qname.to_lowercase();
    let lower = lower_name.to_ascii();
    let s = lower.as_str();
    match qtype {
        RecordType::A | RecordType::AAAA => s == "ipv4only.arpa.",
        RecordType::PTR => PTR_NAMES.iter().any(|n| s == *n),
        _ => false,
    }
}

/// Build the synthesised response. `dns64_policy` is consulted only
/// for AAAA queries and only when `dns64_enabled` is true; for A and
/// PTR queries the answer is identical regardless.
pub fn synth_response(
    original_query: &Message,
    dns64_policy: Option<&Dns64Policy>,
    dns64_enabled: bool,
) -> Message {
    let q = original_query
        .queries
        .first()
        .expect("caller already extracted a question");
    let qname = q.name.clone();
    let qtype = q.query_type();

    let mut resp = Message::response(original_query.metadata.id, OpCode::Query);
    resp.metadata.recursion_desired = original_query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NoError;
    resp.metadata.authentic_data = false;
    for q in &original_query.queries {
        resp.add_query(q.clone());
    }

    match qtype {
        RecordType::A => {
            for v4 in [A_170, A_171] {
                let mut rec = Record::from_rdata(qname.clone(), LOCAL_TTL, RData::A(A(v4)));
                rec.dns_class = DNSClass::IN;
                resp.add_answer(rec);
            }
        }
        RecordType::AAAA => {
            // No DNS64 → NODATA. RFC 8880 §7.2: client uses the empty
            // AAAA answer as evidence that no synthesiser is in path.
            if let (true, Some(policy)) = (dns64_enabled, dns64_policy) {
                for v4 in [A_170, A_171] {
                    let v6 = embed_v4(&policy.prefix, v4);
                    let mut rec = Record::from_rdata(
                        qname.clone(),
                        LOCAL_TTL,
                        RData::AAAA(AAAA(v6)),
                    );
                    rec.dns_class = DNSClass::IN;
                    resp.add_answer(rec);
                }
            }
        }
        RecordType::PTR => {
            let target = Name::from_ascii("ipv4only.arpa.")
                .expect("static literal parses");
            let mut rec = Record::from_rdata(
                qname.clone(),
                LOCAL_TTL,
                RData::PTR(PTR(target)),
            );
            rec.dns_class = DNSClass::IN;
            resp.add_answer(rec);
        }
        _ => {}
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, Query};
    use std::net::Ipv6Addr;

    fn build_query(name: &str, qtype: RecordType) -> Message {
        let mut m = Message::new(0xabcd, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
        m
    }

    #[test]
    fn recognises_ipv4only_a_and_aaaa() {
        let n = Name::from_ascii("ipv4only.arpa.").unwrap();
        assert!(is_local_question(&n, RecordType::A));
        assert!(is_local_question(&n, RecordType::AAAA));
        assert!(!is_local_question(&n, RecordType::MX));
        // Subdomain — RFC 8880 only covers the bare name.
        let sub = Name::from_ascii("foo.ipv4only.arpa.").unwrap();
        assert!(!is_local_question(&sub, RecordType::A));
    }

    #[test]
    fn recognises_ptr_names() {
        let n170 = Name::from_ascii("170.0.0.192.in-addr.arpa.").unwrap();
        let n171 = Name::from_ascii("171.0.0.192.in-addr.arpa.").unwrap();
        assert!(is_local_question(&n170, RecordType::PTR));
        assert!(is_local_question(&n171, RecordType::PTR));
        // Wrong qtype — fall through to the normal path.
        assert!(!is_local_question(&n170, RecordType::A));
        // Adjacent v4 — not us.
        let n172 = Name::from_ascii("172.0.0.192.in-addr.arpa.").unwrap();
        assert!(!is_local_question(&n172, RecordType::PTR));
    }

    #[test]
    fn case_insensitive() {
        let n = Name::from_ascii("IPv4Only.ARPA.").unwrap();
        assert!(is_local_question(&n, RecordType::A));
    }

    #[test]
    fn a_query_returns_both_records() {
        let q = build_query("ipv4only.arpa.", RecordType::A);
        let resp = synth_response(&q, None, false);
        assert_eq!(resp.metadata.id, 0xabcd);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 2);
        let mut got = resp
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect::<Vec<_>>();
        got.sort();
        assert_eq!(got, vec![A_170, A_171]);
        assert!(!resp.metadata.authentic_data);
    }

    #[test]
    fn aaaa_without_dns64_is_nodata() {
        let q = build_query("ipv4only.arpa.", RecordType::AAAA);
        let resp = synth_response(&q, None, false);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty());
    }

    #[test]
    fn aaaa_with_dns64_synthesises() {
        let policy = Dns64Policy::default_wkp();
        let q = build_query("ipv4only.arpa.", RecordType::AAAA);
        let resp = synth_response(&q, Some(&policy), true);
        assert_eq!(resp.answers.len(), 2);
        let want_170: Ipv6Addr = "64:ff9b::c000:aa".parse().unwrap();
        let want_171: Ipv6Addr = "64:ff9b::c000:ab".parse().unwrap();
        let got: Vec<_> = resp
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::AAAA(a) => Some(a.0),
                _ => None,
            })
            .collect();
        assert!(got.contains(&want_170));
        assert!(got.contains(&want_171));
        assert!(!resp.metadata.authentic_data);
    }

    #[test]
    fn ptr_returns_ipv4only_arpa() {
        let q = build_query("170.0.0.192.in-addr.arpa.", RecordType::PTR);
        let resp = synth_response(&q, None, false);
        assert_eq!(resp.answers.len(), 1);
        let target = Name::from_ascii("ipv4only.arpa.").unwrap();
        match &resp.answers[0].data {
            RData::PTR(p) => assert_eq!(p.0, target),
            other => panic!("expected PTR, got {other:?}"),
        }
        assert!(!resp.metadata.authentic_data);
    }
}
