#![no_main]

use dnsd::recursor::normalize::lowercase_response_names;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use libfuzzer_sys::fuzz_target;

// Fuzz the forwarder response-rewrite path: parse upstream wire, lowercase
// owner names, re-serialise. Catches panics on adversarial RDATA whose
// canonicalised form trips the encoder (e.g., compression-pointer corner
// cases, oversized labels after lowercasing).
fuzz_target!(|data: &[u8]| {
    let Ok(mut msg) = Message::from_bytes(data) else {
        return;
    };
    lowercase_response_names(&mut msg);
    let _ = msg.to_vec();
});
