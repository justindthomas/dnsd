//! 0x20 case randomisation for upstream queries.
//!
//! Draft `draft-vixie-dnsext-dns0x20-00` (widely deployed; not on the
//! standards track but adopted by BIND, Unbound, Knot, and most
//! modern open resolvers). For every ASCII letter in the question
//! name we flip to a random case before sending upstream. The
//! response echoes the same case back — any mismatch means the
//! packet didn't come from the server we queried.
//!
//! Adds ~1 bit of entropy per letter in the qname — a 10-letter name
//! gets ~1024× the spoofer's work on top of the TXID + source-port
//! defences already in place.
//!
//! We do NOT normalise the response back to lowercase before handing
//! it to the client. DNS name comparison is case-insensitive, and
//! every non-broken client handles the mixed case fine; re-writing
//! would require recomputing compression pointers which doesn't buy
//! us anything.

use anyhow::{anyhow, Result};
use rand::Rng;

/// In-place 0x20-encode the question name in a DNS wire query.
/// Returns the encoded question-name byte range as a vector so
/// `verify` can compare against the response.
pub fn encode(query: &mut [u8]) -> Result<Vec<u8>> {
    let range = qname_byte_range(query)?;
    let mut rng = rand::thread_rng();
    for i in range.clone() {
        let b = query[i];
        // Only flip letters, not label length bytes. We walk label
        // bodies below; skipping length bytes means walking the
        // length-prefix structure. qname_label_positions yields
        // exactly the data positions.
        if b.is_ascii_alphabetic() && rng.gen::<bool>() {
            query[i] = b ^ 0x20;
        }
    }
    Ok(query[range].to_vec())
}

/// Verify the question name in `response` echoes the `expected` case
/// pattern exactly. Returns Ok on match, Err otherwise.
pub fn verify(response: &[u8], expected: &[u8]) -> Result<()> {
    let range = qname_byte_range(response)?;
    let got = &response[range];
    if got == expected {
        Ok(())
    } else {
        Err(anyhow!(
            "0x20 case mismatch (possible spoof): sent {:?}, got {:?}",
            String::from_utf8_lossy(expected),
            String::from_utf8_lossy(got),
        ))
    }
}

/// Find the byte range `[start, end)` covering the letter bytes of
/// the question name — i.e. the label bodies, skipping the leading
/// length bytes but including them in the returned range since the
/// caller needs the full sequence to compare against the response.
///
/// A DNS wire message starts with a 12-byte header; immediately
/// after that the QNAME is a sequence of `<len> <label>…` until a
/// zero-length terminator, then QTYPE (2 bytes) + QCLASS (2 bytes).
/// We return [12, end_of_qname_terminator) — letters + length bytes
/// in order.
fn qname_byte_range(msg: &[u8]) -> Result<std::ops::Range<usize>> {
    if msg.len() < 12 {
        return Err(anyhow!("DNS message too short for header"));
    }
    let start = 12;
    let mut i = start;
    loop {
        if i >= msg.len() {
            return Err(anyhow!("unterminated QNAME"));
        }
        let len = msg[i] as usize;
        if len == 0 {
            // Include the terminator in the range.
            return Ok(start..i + 1);
        }
        if len & 0xc0 != 0 {
            // Compression pointer in the question section is malformed —
            // it shouldn't happen for the very first name in a query.
            return Err(anyhow!("compression pointer in question section"));
        }
        if i + 1 + len > msg.len() {
            return Err(anyhow!("QNAME label overruns message"));
        }
        i += 1 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    fn build_query(name: &str) -> Vec<u8> {
        let mut m = Message::new();
        m.set_id(0x1234);
        m.set_message_type(MessageType::Query);
        m.set_op_code(OpCode::Query);
        m.add_query(Query::query(
            Name::from_ascii(name).unwrap(),
            RecordType::A,
        ));
        m.to_vec().unwrap()
    }

    #[test]
    fn encode_randomises_case_roundtrip() {
        let mut q = build_query("example.com.");
        let sent = encode(&mut q).unwrap();
        // Same QNAME length (just case flipped).
        assert_eq!(sent.len(), "\x07example\x03com\x00".len());
        // Case-insensitive content equal to 'example.com.'.
        let lower: Vec<u8> = sent.iter().map(|b| b.to_ascii_lowercase()).collect();
        assert_eq!(lower, b"\x07example\x03com\x00");
    }

    #[test]
    fn verify_detects_case_mismatch() {
        let mut q = build_query("example.com.");
        let sent = encode(&mut q).unwrap();

        // Construct a "response" that just echoes the query
        // question section — identical bytes mean verify passes.
        assert!(verify(&q, &sent).is_ok());

        // Flip one letter's case in the "response" → verify fails.
        let mut tampered = q.clone();
        let letter_pos = 12 + 1; // first byte after the length 0x07
        tampered[letter_pos] ^= 0x20;
        assert!(verify(&tampered, &sent).is_err());
    }

    #[test]
    fn encode_on_all_labels() {
        // Walk enough letters that randomness hits both cases.
        let mut q = build_query("aaaaaaaaaaaaaaaaaa.example.com.");
        let sent = encode(&mut q).unwrap();
        // Should preserve label-length bytes (non-letter) exactly.
        assert_eq!(sent[0], 18); // "aaaaaaaaaaaaaaaaaa" len
        assert_eq!(sent[19], 7); // "example" len
        assert_eq!(sent[27], 3); // "com" len
    }
}
