#![no_main]

use dnsd::recursor::dnssec::{validate_response, TrustAnchors};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = Message::from_bytes(data) {
        let anchors = TrustAnchors::new();
        let _ = validate_response(&msg, &anchors);
    }
});
