//! RFC 9462 DDR (Discovery of Designated Resolvers) — answer
//! `_dns.resolver.arpa` SVCB queries locally.
//!
//! A client that only has a plaintext (Do53) resolver address can
//! upgrade to encrypted DNS by querying that resolver for the special
//! name `_dns.resolver.arpa` / SVCB: the resolver answers with an SVCB
//! record describing its own encrypted endpoint(s). The client then
//! connects there and — for an IP-configured resolver — verifies the
//! encrypted resolver's TLS certificate covers the original resolver
//! IP (RFC 9462 §4). This is the path Apple platforms use; they do
//! not consume the RFC 9463 DNR RA/DHCP option.
//!
//! dnsd answers this locally for any query under `_dns.resolver.arpa`:
//! SVCB gets the synthesized record, every other qtype gets NODATA, so
//! the name never escapes to the AS112-delegated public `resolver.arpa`.
//!
//! This build advertises DNS-over-TLS only (`alpn=dot`, port 853) —
//! consistent with the DNR RA option. The IP hints are the resolver's
//! own DoT listener addresses, restricted to global-scope addresses:
//! DDR verified discovery needs the encrypted resolver's certificate
//! to assert the resolver IP, and no public CA issues certificates for
//! RFC 1918 / ULA / link-local space.

use std::net::IpAddr;

use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::svcb::{Alpn, IpHint, SvcParamKey, SvcParamValue, SVCB};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

/// TTL for the synthesized SVCB answer. RFC 9462 uses 7200 in its
/// examples; the record only changes when the operator reconfigures
/// listeners, so a couple of hours is comfortable.
const DDR_TTL: u32 = 7_200;

/// The special name a DDR client queries. RFC 9462 §4.
const RESOLVER_ARPA: &str = "_dns.resolver.arpa.";

/// True when `qname` is exactly `_dns.resolver.arpa` (case-insensitive).
/// dnsd answers every qtype for this name — SVCB with the record,
/// everything else NODATA — so the query never recurses.
pub fn is_ddr_question(qname: &Name) -> bool {
    qname.to_lowercase().to_ascii().as_str() == RESOLVER_ARPA
}

/// True for global-scope addresses — the only ones for which a public
/// CA can issue the IP-SAN certificate DDR verified discovery needs.
fn is_global_scope(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_unspecified()
                && !v4.is_broadcast()
                && !v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return false;
            }
            let top = v6.segments()[0];
            // Exclude fc00::/7 unique-local and fe80::/10 link-local.
            (top & 0xfe00) != 0xfc00 && (top & 0xffc0) != 0xfe80
        }
    }
}

/// Build the DDR SVCB record from the resolver's DoT listener
/// addresses. `resolver_name` is the TargetName clients use for SNI +
/// certificate name validation (the DoT cert's domain). Returns `None`
/// — DDR disabled — when no global-scope DoT address exists: a DDR
/// answer pointing only at unroutable / uncertifiable addresses is
/// worse than no answer at all.
pub fn build_svcb(resolver_name: &Name, dot_addrs: &[IpAddr]) -> Option<SVCB> {
    let mut v4: Vec<A> = Vec::new();
    let mut v6: Vec<AAAA> = Vec::new();
    for ip in dot_addrs {
        if !is_global_scope(ip) {
            continue;
        }
        match ip {
            IpAddr::V4(a) => v4.push(A(*a)),
            IpAddr::V6(a) => v6.push(AAAA(*a)),
        }
    }
    if v4.is_empty() && v6.is_empty() {
        return None;
    }

    // SvcParams MUST be in ascending key order on the wire (RFC 9460
    // §2.2): alpn(1), port(3), ipv4hint(4), ipv6hint(6).
    let mut params: Vec<(SvcParamKey, SvcParamValue)> = vec![
        (
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec!["dot".to_string()])),
        ),
        (SvcParamKey::Port, SvcParamValue::Port(853)),
    ];
    if !v4.is_empty() {
        params.push((SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(IpHint(v4))));
    }
    if !v6.is_empty() {
        params.push((SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(IpHint(v6))));
    }
    Some(SVCB::new(1, resolver_name.clone(), params))
}

/// Synthesize the response. SVCB queries get the record; every other
/// qtype gets NODATA (NoError, no answers) so `_dns.resolver.arpa`
/// never recurses. AD is cleared — these answers carry no RRSIG.
pub fn synth_response(original_query: &Message, svcb: &SVCB) -> Message {
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

    if qtype == RecordType::SVCB {
        let mut rec = Record::from_rdata(qname, DDR_TTL, RData::SVCB(svcb.clone()));
        rec.dns_class = DNSClass::IN;
        resp.add_answer(rec);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    #[test]
    fn recognises_resolver_arpa() {
        assert!(is_ddr_question(&n("_dns.resolver.arpa.")));
        assert!(is_ddr_question(&n("_DNS.Resolver.ARPA.")));
        assert!(!is_ddr_question(&n("resolver.arpa.")));
        assert!(!is_ddr_question(&n("foo._dns.resolver.arpa.")));
        assert!(!is_ddr_question(&n("example.com.")));
    }

    #[test]
    fn build_svcb_keeps_only_global_scope() {
        let name = n("dns.example.net.");
        let addrs = vec![
            IpAddr::from_str("192.168.20.1").unwrap(), // RFC1918 — dropped
            IpAddr::from_str("23.177.24.9").unwrap(),  // public — kept
            IpAddr::from_str("fe80::1").unwrap(),      // link-local — dropped
            IpAddr::from_str("fd00::1").unwrap(),      // ULA — dropped
            IpAddr::from_str("2602:f90e:10::ffff:ffff:ffff:fffe").unwrap(), // GUA — kept
        ];
        let svcb = build_svcb(&name, &addrs).expect("has global addrs");
        assert_eq!(svcb.svc_priority, 1);
        let v4: Vec<_> = svcb
            .svc_params
            .iter()
            .filter_map(|(_, v)| match v {
                SvcParamValue::Ipv4Hint(h) => Some(h.0.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        let v6: Vec<_> = svcb
            .svc_params
            .iter()
            .filter_map(|(_, v)| match v {
                SvcParamValue::Ipv6Hint(h) => Some(h.0.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(v4, vec![A("23.177.24.9".parse().unwrap())]);
        assert_eq!(
            v6,
            vec![AAAA("2602:f90e:10::ffff:ffff:ffff:fffe".parse().unwrap())]
        );
    }

    #[test]
    fn build_svcb_none_when_no_global_addr() {
        let name = n("dns.example.net.");
        let addrs = vec![
            IpAddr::from_str("192.168.20.1").unwrap(),
            IpAddr::from_str("fd00::1").unwrap(),
        ];
        assert!(build_svcb(&name, &addrs).is_none());
    }
}
