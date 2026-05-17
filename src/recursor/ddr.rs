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
//! This build advertises both DNS-over-TLS (`alpn=dot`, port 853,
//! SvcPriority 1) and DNS-over-HTTPS (`alpn=h2`, dohpath
//! `/dns-query{?dns}`, SvcPriority 2) as two SVCB records. The IP
//! hints are the resolver's own DoT / DoH listener addresses,
//! restricted to global-scope addresses: DDR verified discovery
//! needs the encrypted resolver's certificate to assert the
//! resolver IP, and no public CA issues certificates for RFC 1918 /
//! ULA / link-local space.

use std::net::IpAddr;

use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::svcb::{
    Alpn, IpHint, SvcParamKey, SvcParamValue, Unknown, SVCB,
};
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

/// RFC 9461 §5 `dohpath` SvcParam value — the URI Template for
/// dnsd's DoH endpoint. dnsd serves DoH at the fixed path
/// `/dns-query` with a `dns=` query parameter on GET, so the
/// template is a constant.
const DOH_PATH: &str = "/dns-query{?dns}";

/// Partition a listener address list into global-scope A / AAAA
/// hints — the only addresses for which a public CA can issue the
/// IP-SAN certificate DDR verified discovery needs.
fn split_global_hints(addrs: &[IpAddr]) -> (Vec<A>, Vec<AAAA>) {
    let mut v4: Vec<A> = Vec::new();
    let mut v6: Vec<AAAA> = Vec::new();
    for ip in addrs {
        if !is_global_scope(ip) {
            continue;
        }
        match ip {
            IpAddr::V4(a) => v4.push(A(*a)),
            IpAddr::V6(a) => v6.push(AAAA(*a)),
        }
    }
    (v4, v6)
}

/// Build the DDR SVCB records. One record for DoT (`alpn=dot`,
/// port 853, SvcPriority 1) and one for DoH (`alpn=h2`, dohpath,
/// port 443 implied, SvcPriority 2) — each emitted only when its
/// listener set has a global-scope address. An empty result means
/// DDR is off: an answer pointing only at unroutable /
/// uncertifiable addresses is worse than no answer at all.
///
/// DoT keeps the lower SvcPriority: it carries no HTTP request
/// metadata, so DoT-capable clients should prefer it. DoH
/// (priority 2) is the path for DoH-only clients (Windows).
///
/// `resolver_name` is the TargetName clients use for SNI +
/// certificate name validation (the TLS cert's domain).
pub fn build_ddr_records(
    resolver_name: &Name,
    dot_addrs: &[IpAddr],
    doh_addrs: &[IpAddr],
) -> Vec<SVCB> {
    let mut records = Vec::new();

    // DoT — SvcParams in ascending key order (RFC 9460 §2.2):
    // alpn(1), port(3), ipv4hint(4), ipv6hint(6).
    let (v4, v6) = split_global_hints(dot_addrs);
    if !(v4.is_empty() && v6.is_empty()) {
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
        records.push(SVCB::new(1, resolver_name.clone(), params));
    }

    // DoH — ascending key order: alpn(1), ipv4hint(4), ipv6hint(6),
    // dohpath(7). The port is omitted: RFC 9461 §3 makes 443 the
    // DoH default. `dohpath` (key 7) is not modelled by hickory
    // 0.26, so it goes out as `SvcParamKey::Unknown(7)` carrying the
    // raw UTF-8 URI Template.
    let (v4, v6) = split_global_hints(doh_addrs);
    if !(v4.is_empty() && v6.is_empty()) {
        let mut params: Vec<(SvcParamKey, SvcParamValue)> = vec![(
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec!["h2".to_string()])),
        )];
        if !v4.is_empty() {
            params.push((SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(IpHint(v4))));
        }
        if !v6.is_empty() {
            params.push((SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(IpHint(v6))));
        }
        params.push((
            SvcParamKey::Unknown(7),
            SvcParamValue::Unknown(Unknown(DOH_PATH.as_bytes().to_vec())),
        ));
        records.push(SVCB::new(2, resolver_name.clone(), params));
    }

    records
}

/// Synthesize the response. SVCB queries get every DDR record (one
/// per encrypted transport); every other qtype gets NODATA
/// (NoError, no answers) so `_dns.resolver.arpa` never recurses. AD
/// is cleared — these answers carry no RRSIG.
pub fn synth_response(original_query: &Message, svcbs: &[SVCB]) -> Message {
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
        for svcb in svcbs {
            let mut rec = Record::from_rdata(
                qname.clone(),
                DDR_TTL,
                RData::SVCB(svcb.clone()),
            );
            rec.dns_class = DNSClass::IN;
            resp.add_answer(rec);
        }
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

    fn hints(svcb: &SVCB) -> (Vec<A>, Vec<AAAA>) {
        let v4 = svcb
            .svc_params
            .iter()
            .filter_map(|(_, v)| match v {
                SvcParamValue::Ipv4Hint(h) => Some(h.0.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        let v6 = svcb
            .svc_params
            .iter()
            .filter_map(|(_, v)| match v {
                SvcParamValue::Ipv6Hint(h) => Some(h.0.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        (v4, v6)
    }

    #[test]
    fn build_records_keeps_only_global_scope() {
        let name = n("dns.example.net.");
        let addrs = vec![
            IpAddr::from_str("192.168.20.1").unwrap(), // RFC1918 — dropped
            IpAddr::from_str("23.177.24.9").unwrap(),  // public — kept
            IpAddr::from_str("fe80::1").unwrap(),      // link-local — dropped
            IpAddr::from_str("fd00::1").unwrap(),      // ULA — dropped
            IpAddr::from_str("2602:f90e:10::ffff:ffff:ffff:fffe").unwrap(), // GUA — kept
        ];
        let recs = build_ddr_records(&name, &addrs, &addrs);
        assert_eq!(recs.len(), 2, "one DoT + one DoH record");

        let dot = &recs[0];
        assert_eq!(dot.svc_priority, 1);
        let (v4, v6) = hints(dot);
        assert_eq!(v4, vec![A("23.177.24.9".parse().unwrap())]);
        assert_eq!(
            v6,
            vec![AAAA("2602:f90e:10::ffff:ffff:ffff:fffe".parse().unwrap())]
        );

        let doh = &recs[1];
        assert_eq!(doh.svc_priority, 2);
        let (v4, v6) = hints(doh);
        assert_eq!(v4, vec![A("23.177.24.9".parse().unwrap())]);
        assert_eq!(
            v6,
            vec![AAAA("2602:f90e:10::ffff:ffff:ffff:fffe".parse().unwrap())]
        );
        // DoH carries alpn=h2 and the dohpath SvcParam (key 7).
        let alpn: Vec<String> = doh
            .svc_params
            .iter()
            .filter_map(|(_, v)| match v {
                SvcParamValue::Alpn(a) => Some(a.0.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(alpn, vec!["h2".to_string()]);
        let dohpath = doh.svc_params.iter().find_map(|(k, v)| match (k, v) {
            (SvcParamKey::Unknown(7), SvcParamValue::Unknown(u)) => Some(u.0.clone()),
            _ => None,
        });
        assert_eq!(dohpath, Some(b"/dns-query{?dns}".to_vec()));
        // SvcParam keys MUST be ascending on the wire (RFC 9460 §2.2).
        let keys: Vec<u16> =
            doh.svc_params.iter().map(|(k, _)| u16::from(*k)).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "DoH SvcParams not in ascending key order");
    }

    #[test]
    fn build_records_doh_only_when_doh_addrs_present() {
        let name = n("dns.example.net.");
        let dot = vec![IpAddr::from_str("23.177.24.9").unwrap()];
        // DoT has a global addr, DoH set is all private — only DoT.
        let doh_private = vec![IpAddr::from_str("192.168.20.1").unwrap()];
        let recs = build_ddr_records(&name, &dot, &doh_private);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].svc_priority, 1);
    }

    #[test]
    fn build_records_empty_when_no_global_addr() {
        let name = n("dns.example.net.");
        let addrs = vec![
            IpAddr::from_str("192.168.20.1").unwrap(),
            IpAddr::from_str("fd00::1").unwrap(),
        ];
        assert!(build_ddr_records(&name, &addrs, &addrs).is_empty());
    }
}
