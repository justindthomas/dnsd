//! Response-name normalisation.
//!
//! 0x20 case randomisation (see `zeroxtwenty.rs`) is great for
//! defending against off-path cache poisoning, but the random case
//! the upstream echoed back leaks all the way to the client without
//! intervention — we'd hand `cnn.com` queries a `cNn.COm.` answer.
//! Every other modern recursor (BIND, Unbound, Knot, PowerDNS)
//! lowercases names in the response before serving the client; we
//! match that.
//!
//! Applied at two points:
//! - Just after a successful walk completes, before the bytes get
//!   cached + returned (`iterative::resolve_with_chain`).
//! - In the forwarder path after re-parsing the upstream response
//!   (`forwarder::query_one`).
//!
//! We don't recurse into RDATA (CNAME/NS/MX/SOA targets) for now —
//! those names rarely surface to the user verbatim, and rewriting
//! them in hickory requires re-encoding the typed RData variants.
//! Follow-up if it bites.

use hickory_proto::op::Message;

/// Lowercase every record's owner name in the message, in-place.
/// Touches QUESTION, ANSWER, AUTHORITY, and ADDITIONAL sections.
pub fn lowercase_response_names(msg: &mut Message) {
    for q in msg.queries.iter_mut() {
        q.set_name(q.name().to_lowercase());
    }
    for r in msg.answers.iter_mut() {
        r.name = r.name.to_lowercase();
    }
    for r in msg.authorities.iter_mut() {
        r.name = r.name.to_lowercase();
    }
    for r in msg.additionals.iter_mut() {
        r.name = r.name.to_lowercase();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{rdata::A, DNSClass, Name, RData, Record, RecordType};
    use std::str::FromStr;

    #[test]
    fn lowercases_question_and_answer() {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(
            Name::from_str("CnN.COm.").unwrap(),
            RecordType::A,
        ));
        let rec = Record::from_rdata(
            Name::from_str("CnN.COm.").unwrap(),
            60,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        );
        m.add_answer(rec);

        lowercase_response_names(&mut m);
        assert_eq!(
            m.queries[0].name().to_string(),
            "cnn.com."
        );
        assert_eq!(m.answers[0].name.to_string(), "cnn.com.");
        let _ = DNSClass::IN; // silence unused
    }
}
