//! Per-listener client ACL: accept a query only if the peer's IP
//! falls inside at least one of the configured CIDRs.

use std::net::IpAddr;

use ipnet::IpNet;

pub struct ClientAcl {
    allow: Vec<IpNet>,
}

impl ClientAcl {
    pub fn new(allow: Vec<IpNet>) -> Self {
        Self { allow }
    }

    /// Empty allow-list means "no clients allowed". That's the safe
    /// default for a resolver — forcing the operator to declare
    /// `allow_from` explicitly. Operators who want "anyone" set
    /// `["0.0.0.0/0", "::/0"]` (or `["::/0"]` for dual-stack).
    pub fn allows(&self, peer: IpAddr) -> bool {
        self.allow.iter().any(|cidr| cidr.contains(&peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_matches_v4_and_v6() {
        let acl = ClientAcl::new(vec![
            "10.0.0.0/8".parse().unwrap(),
            "2602:f90e::/48".parse().unwrap(),
        ]);
        assert!(acl.allows("10.1.2.3".parse().unwrap()));
        assert!(!acl.allows("192.168.1.1".parse().unwrap()));
        assert!(acl.allows("2602:f90e::1".parse().unwrap()));
        assert!(!acl.allows("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn empty_allow_denies_all() {
        let acl = ClientAcl::new(vec![]);
        assert!(!acl.allows("127.0.0.1".parse().unwrap()));
    }
}
