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
    let new_queries: Vec<_> = msg
        .queries()
        .iter()
        .map(|q| {
            let mut nq = q.clone();
            nq.set_name(q.name().to_lowercase());
            nq
        })
        .collect();
    msg.take_queries();
    for q in new_queries {
        msg.add_query(q);
    }

    rewrite_section_names(
        msg.take_answers(),
        |r| r,
        |msg, r| {
            msg.add_answer(r);
        },
        msg,
    );
    rewrite_section_names(
        msg.take_name_servers(),
        |r| r,
        |msg, r| {
            msg.add_name_server(r);
        },
        msg,
    );
    rewrite_section_names(
        msg.take_additionals(),
        |r| r,
        |msg, r| {
            msg.add_additional(r);
        },
        msg,
    );
}

fn rewrite_section_names<R, F, A>(
    records: Vec<R>,
    _identity: F,
    add_back: A,
    msg: &mut Message,
) where
    R: NameOwned,
    F: Fn(R) -> R,
    A: Fn(&mut Message, R),
{
    for mut r in records {
        let lower = r.name().to_lowercase();
        r.set_name(lower);
        add_back(msg, r);
    }
}

/// Tiny shim so the same closure works for `Record` (answer/auth/
/// additional sections all hand back `Record`s in hickory 0.24).
pub trait NameOwned {
    fn name(&self) -> &hickory_proto::rr::Name;
    fn set_name(&mut self, name: hickory_proto::rr::Name);
}

impl NameOwned for hickory_proto::rr::Record {
    fn name(&self) -> &hickory_proto::rr::Name {
        hickory_proto::rr::Record::name(self)
    }
    fn set_name(&mut self, name: hickory_proto::rr::Name) {
        hickory_proto::rr::Record::set_name(self, name);
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
        let mut m = Message::new();
        m.set_id(1);
        m.set_message_type(MessageType::Response);
        m.set_op_code(OpCode::Query);
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
            m.queries()[0].name().to_string(),
            "cnn.com."
        );
        assert_eq!(m.answers()[0].name().to_string(), "cnn.com.");
        let _ = DNSClass::IN; // silence unused
    }
}
