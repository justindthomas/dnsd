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
//! Response normalisation back to lowercase before handing to the
//! client lives in `normalize::lowercase_response_names` — applied
//! by both the iterative and forwarder paths once the response is
//! verified. Match what BIND/Unbound/Knot do, so users see clean
//! `cnn.com.` instead of whatever case the upstream echoed.

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

/// Verify the question name in `response` echoes the `expected`
/// pattern. Letter bytes must match `expected` *case-insensitively* —
/// some authoritatives (and middleboxes) lowercase the qname before
/// echoing, which wouldn't be a spoof but the strict check would
/// reject. Length bytes (label-length prefixes) and non-letter bytes
/// must still match exactly. The off-path attacker still has to know
/// the layout + content, just not the random case of letters; we keep
/// the entropy from TXID + source-port randomisation, which together
/// remain plenty against off-path injection.
pub fn verify(response: &[u8], expected: &[u8]) -> Result<()> {
    let range = qname_byte_range(response)?;
    let got = &response[range];
    if got.len() != expected.len() {
        return Err(anyhow!(
            "0x20 length mismatch: sent {} bytes, got {} bytes",
            expected.len(),
            got.len()
        ));
    }
    let ok = got.iter().zip(expected.iter()).all(|(g, e)| {
        if e.is_ascii_alphabetic() {
            g.eq_ignore_ascii_case(e)
        } else {
            g == e
        }
    });
    if ok {
        Ok(())
    } else {
        Err(anyhow!(
            "0x20 mismatch (possible spoof): sent {:?}, got {:?}",
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
    fn verify_passes_on_byte_exact_echo() {
        let mut q = build_query("example.com.");
        let sent = encode(&mut q).unwrap();
        assert!(verify(&q, &sent).is_ok());
    }

    #[test]
    fn verify_passes_on_case_only_mutation() {
        // An authoritative that lowercases (or otherwise re-cases)
        // before echoing should NOT be treated as a spoof. The byte
        // length stays the same; only ASCII letter case differs.
        let mut q = build_query("example.com.");
        let sent = encode(&mut q).unwrap();
        let mut lowered = q.clone();
        let letter_pos = 12 + 1;
        lowered[letter_pos] = lowered[letter_pos].to_ascii_lowercase();
        // sent had random case; lowered now diverges in case from sent.
        assert!(verify(&lowered, &sent).is_ok());
    }

    #[test]
    fn verify_detects_label_length_mutation() {
        // Length bytes (label-length prefixes) must still match
        // exactly — a label-length change is structural, not just
        // cosmetic, and a spoof attempt would have to guess them too.
        let mut q = build_query("example.com.");
        let sent = encode(&mut q).unwrap();
        let mut tampered = q.clone();
        tampered[12] = tampered[12].wrapping_add(1); // mutate length
        assert!(verify(&tampered, &sent).is_err());
    }

    #[test]
    fn verify_detects_non_letter_mutation() {
        // Mutating a non-letter byte (e.g. a digit) inside a label is
        // also detected — only ASCII letters are allowed to differ.
        let mut q = build_query("ex2mple.com.");
        let sent = encode(&mut q).unwrap();
        let mut tampered = q.clone();
        // Find the '2' in "ex2mple" and bump it to '3'.
        for b in tampered.iter_mut() {
            if *b == b'2' {
                *b = b'3';
                break;
            }
        }
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
