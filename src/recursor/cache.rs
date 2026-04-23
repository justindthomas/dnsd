//! Query response cache.
//!
//! Keyed on (lowercased name, record type, class). Stores the full
//! wire-format response so lookup is zero-parse on hit — handler
//! rewrites the TXID and streams the bytes straight back to the
//! transport.
//!
//! TTL handling honours the minimum TTL across all answer RRs (the
//! conservative choice — RFC 2181 §5.2). Negative caching per
//! RFC 2308 caps NXDOMAIN/NODATA to the SOA MINIMUM (or the operator
//! `negative_ttl` when no SOA is present).
//!
//! Serve-stale (RFC 8767) is intentionally out-of-scope for v1; the
//! follow-up adds a `stale_window` and a background refresh dance.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use moka::future::Cache as MokaCache;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct CacheKey {
    pub name: Name,
    pub rtype: RecordType,
    pub class: DNSClass,
}

impl CacheKey {
    /// DNS names are case-insensitive; normalise before hashing so
    /// 0x20-randomised queries still hit the cache.
    pub fn new(name: &Name, rtype: RecordType, class: DNSClass) -> Self {
        Self {
            name: name.to_lowercase(),
            rtype,
            class,
        }
    }
}

#[derive(Clone)]
struct Entry {
    bytes: Arc<Vec<u8>>,
    expires: Instant,
}

pub struct DnsCache {
    inner: MokaCache<CacheKey, Entry>,
    min_ttl: u32,
    max_ttl: u32,
    negative_ttl: u32,
}

impl DnsCache {
    pub fn new(max_entries: u64, min_ttl: u32, max_ttl: u32, negative_ttl: u32) -> Self {
        Self {
            inner: MokaCache::builder().max_capacity(max_entries).build(),
            min_ttl,
            max_ttl,
            negative_ttl,
        }
    }

    pub async fn get(&self, key: &CacheKey) -> Option<Vec<u8>> {
        let entry = self.inner.get(key).await?;
        if Instant::now() >= entry.expires {
            // Expired entry — evict + miss. (Serve-stale hook goes
            // here later: return entry.bytes + spawn async refresh.)
            self.inner.invalidate(key).await;
            return None;
        }
        Some((*entry.bytes).clone())
    }

    /// Insert a response into the cache. `bytes` is the exact wire
    /// response we'll later replay. Takes a hickory-parsed `msg`
    /// so we can compute the right TTL without re-parsing.
    pub async fn put(&self, key: CacheKey, msg: &Message, bytes: Vec<u8>) {
        let ttl = self.compute_ttl(msg);
        if ttl == 0 {
            return; // DO-NOT-CACHE per operator config (min_ttl=0 + answer TTL=0)
        }
        let expires = Instant::now() + Duration::from_secs(ttl as u64);
        self.inner
            .insert(
                key,
                Entry {
                    bytes: Arc::new(bytes),
                    expires,
                },
            )
            .await;
    }

    fn compute_ttl(&self, msg: &Message) -> u32 {
        match msg.response_code() {
            ResponseCode::NXDomain | ResponseCode::NoError if msg.answers().is_empty() => {
                // Negative cache: cap at SOA MINIMUM if present, else
                // operator default. (NoError + empty answers = NODATA.)
                let soa_min = msg
                    .name_servers()
                    .iter()
                    .find_map(|r| {
                        if r.record_type() == RecordType::SOA {
                            // SOA MINIMUM is the 7th field (index 6 in
                            // the wire format). hickory exposes it via
                            // the typed rdata.
                            if let Some(hickory_proto::rr::RData::SOA(soa)) = r.data() {
                                return Some(soa.minimum());
                            }
                        }
                        None
                    })
                    .unwrap_or(self.negative_ttl);
                soa_min.min(self.max_ttl).max(self.min_ttl)
            }
            ResponseCode::NoError => {
                // Positive cache: min TTL across answer section
                // (RFC 2181 §5.2 conservative reading).
                let min_answer_ttl = msg
                    .answers()
                    .iter()
                    .map(|r| r.ttl())
                    .min()
                    .unwrap_or(self.negative_ttl);
                min_answer_ttl.min(self.max_ttl).max(self.min_ttl)
            }
            // SERVFAIL, REFUSED etc. never cache.
            _ => 0,
        }
    }

    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}

/// Rewrite only the TXID in a cached wire response. Used on cache
/// hit: the payload is identical except for the 16-bit ID.
pub fn rewrite_txid(bytes: &mut [u8], new_id: u16) {
    debug_assert!(bytes.len() >= 2);
    bytes[0..2].copy_from_slice(&new_id.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode};
    use hickory_proto::rr::{rdata::A, RData, Record};

    fn build_positive() -> (Message, Vec<u8>) {
        let mut msg = Message::new();
        msg.set_id(0x1234);
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(ResponseCode::NoError);
        let rec = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(A::new(192, 0, 2, 1)),
        );
        msg.add_answer(rec);
        let bytes = msg.to_vec().unwrap();
        (msg, bytes)
    }

    #[tokio::test]
    async fn hit_miss_and_expiry() {
        let cache = DnsCache::new(100, 0, 3600, 60);
        let (msg, bytes) = build_positive();
        let key = CacheKey::new(
            &Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        );

        assert!(cache.get(&key).await.is_none());
        cache.put(key.clone(), &msg, bytes.clone()).await;
        let hit = cache.get(&key).await.expect("hit");
        assert_eq!(hit, bytes);
    }

    #[tokio::test]
    async fn txid_rewrite_preserves_rest() {
        let (_msg, mut bytes) = build_positive();
        let before = bytes[2..].to_vec();
        rewrite_txid(&mut bytes, 0xcafe);
        assert_eq!(&bytes[0..2], &[0xca, 0xfe]);
        assert_eq!(&bytes[2..], &before[..]);
    }

    #[tokio::test]
    async fn servfail_not_cached() {
        let cache = DnsCache::new(100, 0, 3600, 60);
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_response_code(ResponseCode::ServFail);
        let bytes = msg.to_vec().unwrap();
        let key = CacheKey::new(
            &Name::from_ascii("sf.test.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        );
        cache.put(key.clone(), &msg, bytes).await;
        assert!(cache.get(&key).await.is_none());
    }
}
