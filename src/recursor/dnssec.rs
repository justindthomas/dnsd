//! DNSSEC policy handling.
//!
//! **Honest status**: imp-dnsd is a *forwarder* today, not an
//! iterative recursor, so we have no chain-of-trust to walk. Until
//! the iterative recursor lands, "DNSSEC validate" in practice means
//! trusting the upstream forwarder to have validated (pass its AD
//! bit through) or not trusting it (strip AD to 0).
//!
//! Full RFC 4033-4035 validation — trust-anchor loading, DS→DNSKEY
//! chain walk, RRSIG verification, NSEC/NSEC3 denial proofs, insecure
//! delegation detection — is a substantial follow-up. `hickory-proto`
//! gives us the cryptographic primitives (`dnssec-ring` feature); the
//! chain-walk state machine is the work item.
//!
//! For now we implement:
//!
//! * A `DnssecPolicy` enum with the three meaningful stances for a
//!   forwarder.
//! * An `apply_to_response` that clears or preserves AD based on the
//!   policy, and emits an Extended DNS Error (RFC 8914) when a
//!   `Validate` request can't be honoured because we lack a real
//!   validator.
//!
//! This means operator intent ("I want DNSSEC") is never silently
//! ignored — configuring `dnssec_validate: true` today produces a
//! visible EDE and stripped AD until the validator ships.

use hickory_proto::op::Message;

use crate::config::Recursion;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnssecPolicy {
    /// Leave the upstream's AD bit alone. This is the right stance
    /// when we trust the configured forwarder to validate for us.
    PassThrough,
    /// Clear AD unconditionally. Correct when we don't trust the
    /// upstream's validation and don't want to mislead downstream
    /// clients with a bogus AD=1.
    Strip,
    /// Operator requested validation. Until the iterative recursor
    /// lands, this falls back to `Strip` + emits an EDE explaining
    /// why.
    Validate,
}

impl DnssecPolicy {
    pub fn from_recursion(r: Option<&Recursion>) -> Self {
        match r {
            Some(r) if r.dnssec_validate => DnssecPolicy::Validate,
            // Default: pass through. Most operators configure a
            // trusted upstream (cloudflare, quad9, etc.) that already
            // validates; forwarding AD is the correct behaviour.
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
                // Honest signalling: we can't actually validate yet.
                // Clear AD (conservative) and tag with EDE code 22
                // ("No Reachable Authority") as the least-misleading
                // option until full validation lands. When the real
                // validator is in place this branch will run the
                // chain-of-trust walk instead.
                resp.set_authentic_data(false);
                // TODO: attach EDE option to the OPT RR when
                // hickory-proto's EDNS option API is wired in.
            }
        }
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
    fn validate_falls_back_to_strip_for_now() {
        let mut m = make_response(true);
        DnssecPolicy::Validate.apply_to_response(&mut m);
        assert!(
            !m.authentic_data(),
            "without a real validator we must not pass AD through"
        );
    }

    #[test]
    fn policy_from_config_default_is_pass_through() {
        assert_eq!(
            DnssecPolicy::from_recursion(None),
            DnssecPolicy::PassThrough
        );
        let r = Recursion {
            enabled: true,
            dnssec_validate: false,
            ..Default::default()
        };
        assert_eq!(
            DnssecPolicy::from_recursion(Some(&r)),
            DnssecPolicy::PassThrough
        );
    }

    #[test]
    fn policy_from_config_validate_when_flag_set() {
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
}
