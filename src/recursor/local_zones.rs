//! Local-zone short-circuits — RFC 6303 "empty zones".
//!
//! A modern recursor should answer authoritatively (with NXDOMAIN) for
//! reverse-DNS zones covering address space that has no business
//! resolving against the public DNS — RFC 1918, link-local, ULA, etc.
//! Otherwise mDNS/Bonjour service discovery on the LAN floods the
//! AS112 anycast cluster (192.175.48.0/24, the IANA blackhole servers
//! for unrouted reverse zones) with `_dns-sd._udp.X.X.in-addr.arpa`
//! queries, AS112 drops a large fraction silently, and each timed-out
//! walk pins a recursor worker for `MAX_NS_ATTEMPTS × upstream_timeout`
//! seconds. On a 4-worker pool this turns the recursor unusable inside
//! a few minutes of LAN traffic.
//!
//! BIND, Unbound, and Knot all carry equivalent built-in empty-zone
//! lists. We just check for suffix matches against this static list
//! before kicking off the iterative walk.

use hickory_proto::rr::Name;

/// IPv4 in-addr.arpa zones we synthesize NXDOMAIN for. From
/// IANA's "IPv4 Special-Purpose Address Registry" + RFC 6303 §4.2.
const PRIVATE_IPV4_ARPA: &[&str] = &[
    "10.in-addr.arpa.",                    // RFC 1918 /8
    "16.172.in-addr.arpa.",                // RFC 1918 /12 (172.16.0.0/12)
    "17.172.in-addr.arpa.",
    "18.172.in-addr.arpa.",
    "19.172.in-addr.arpa.",
    "20.172.in-addr.arpa.",
    "21.172.in-addr.arpa.",
    "22.172.in-addr.arpa.",
    "23.172.in-addr.arpa.",
    "24.172.in-addr.arpa.",
    "25.172.in-addr.arpa.",
    "26.172.in-addr.arpa.",
    "27.172.in-addr.arpa.",
    "28.172.in-addr.arpa.",
    "29.172.in-addr.arpa.",
    "30.172.in-addr.arpa.",
    "31.172.in-addr.arpa.",
    "168.192.in-addr.arpa.",               // RFC 1918 /16
    "254.169.in-addr.arpa.",               // RFC 3927 link-local
    "0.in-addr.arpa.",                     // 0.0.0.0/8 "this network"
    "127.in-addr.arpa.",                   // loopback
    "2.0.192.in-addr.arpa.",               // RFC 5736 documentation (192.0.2.0/24)
    "100.51.198.in-addr.arpa.",            // RFC 5737 documentation (198.51.100.0/24)
    "113.0.203.in-addr.arpa.",             // RFC 5737 documentation (203.0.113.0/24)
    "255.255.255.255.in-addr.arpa.",       // limited broadcast
];

/// IPv6 ip6.arpa zones we synthesize NXDOMAIN for. From RFC 6303 §4.3.
const PRIVATE_IPV6_ARPA: &[&str] = &[
    "d.f.ip6.arpa.",                       // ULA fc00::/7 (top nibble d or c)
    "c.f.ip6.arpa.",
    "8.e.f.ip6.arpa.",                     // link-local fe80::/10
    "9.e.f.ip6.arpa.",
    "a.e.f.ip6.arpa.",
    "b.e.f.ip6.arpa.",
    "8.b.d.0.1.0.0.2.ip6.arpa.",           // RFC 3849 documentation 2001:db8::/32
    // Loopback ::1 and unspecified :: don't need their own zones —
    // the all-zero qname covers both via the implicit catch.
];

/// Forward special-use TLDs that should NXDOMAIN locally — IANA
/// delegates them to AS112 anycast (which mostly drops queries) so
/// hitting them upstream just burns workers on timeouts.
const SPECIAL_USE_TLDS: &[&str] = &[
    "home.arpa.",                          // RFC 8375 residential local
    // mDNS spam (`*._dns-sd._udp.home.arpa.`) is the main offender on
    // jt-router. The other RFC 6761/6762 specials (`local.`,
    // `invalid.`, `test.`) are also "must not escape the LAN" but
    // we add them only as we observe demand — overly aggressive
    // local NX risks breaking developer setups that use those for
    // intentional local resolvers.
];

/// True when `qname` falls under one of the RFC 6303 private/reserved
/// reverse-DNS zones, or under an RFC 8375 / 6761 / 6762 special-use
/// forward TLD that should never escape the LAN. Suffix match on
/// label boundaries (case-insensitive via Name's lowercase form).
pub fn is_private_reverse(qname: &Name) -> bool {
    let lower = qname.to_lowercase();
    let lower_str = lower.to_ascii();
    let s = lower_str.as_str();
    for z in PRIVATE_IPV4_ARPA
        .iter()
        .chain(PRIVATE_IPV6_ARPA.iter())
        .chain(SPECIAL_USE_TLDS.iter())
    {
        // Exact match or qname ends in `.{z}` (treating both as FQDN).
        if s == *z {
            return true;
        }
        // `s` should end in z (which already has a trailing dot).
        if s.len() > z.len() && s.ends_with(z) {
            // Ensure we matched on a label boundary: char before
            // the suffix must be the label separator dot.
            let cut = s.len() - z.len();
            if cut > 0 && s.as_bytes()[cut - 1] == b'.' {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn n(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    fn rfc1918_class_a() {
        assert!(is_private_reverse(&n("1.2.10.in-addr.arpa.")));
        assert!(is_private_reverse(&n("1.2.3.10.in-addr.arpa.")));
        assert!(is_private_reverse(&n("10.in-addr.arpa.")));
    }

    #[test]
    fn rfc1918_class_c() {
        assert!(is_private_reverse(&n("1.20.168.192.in-addr.arpa.")));
        assert!(is_private_reverse(&n("168.192.in-addr.arpa.")));
        // The actual mDNS-spam shape from jt-router.
        assert!(is_private_reverse(&n("db._dns-sd._udp.0.20.168.192.in-addr.arpa.")));
    }

    #[test]
    fn rfc1918_class_b() {
        assert!(is_private_reverse(&n("1.16.172.in-addr.arpa.")));
        assert!(is_private_reverse(&n("1.31.172.in-addr.arpa.")));
        // 32.172 is NOT private.
        assert!(!is_private_reverse(&n("1.32.172.in-addr.arpa.")));
        assert!(!is_private_reverse(&n("1.15.172.in-addr.arpa.")));
    }

    #[test]
    fn ipv6_link_local() {
        assert!(is_private_reverse(&n(
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa."
        )));
    }

    #[test]
    fn public_addr_not_private() {
        assert!(!is_private_reverse(&n("8.8.8.8.in-addr.arpa.")));
        assert!(!is_private_reverse(&n("1.1.1.1.in-addr.arpa.")));
        // Make sure we don't false-positive on names that contain
        // "10.in-addr.arpa" as a substring but not as a suffix.
        assert!(!is_private_reverse(&n("notreally.10.in-addr.arpa.example.com.")));
    }

    #[test]
    fn forward_names_not_matched() {
        assert!(!is_private_reverse(&n("example.com.")));
        assert!(!is_private_reverse(&n("apple.com.")));
    }

    #[test]
    fn special_use_tlds() {
        assert!(is_private_reverse(&n("home.arpa.")));
        assert!(is_private_reverse(&n("b._dns-sd._udp.home.arpa.")));
        assert!(is_private_reverse(&n("anything.under.home.arpa.")));
    }
}
