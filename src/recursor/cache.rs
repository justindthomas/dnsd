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
    /// Used as the fallback negative TTL when the upstream NXDOMAIN /
    /// NoData response carries no SOA record to derive a MINIMUM from.
    negative_ttl: u32,
    /// Hard upper bound on cached negative-response lifetime, applied
    /// after the SOA MINIMUM is consulted. Distinct from `max_ttl`
    /// (the positive-cache cap) because operationally the cost of a
    /// stale negative is much higher than a stale positive: a stale
    /// positive resolves to a working IP (worst case: traffic to the
    /// wrong host briefly); a stale negative blackholes new clients
    /// (they get NXDOMAIN/NODATA and stop trying). Every mainstream
    /// resolver — Unbound, BIND, PowerDNS Recursor — caps this
    /// separately around the 1-hour mark by default.
    max_negative_ttl: u32,
}

impl DnsCache {
    pub fn new(
        max_entries: u64,
        min_ttl: u32,
        max_ttl: u32,
        negative_ttl: u32,
        max_negative_ttl: u32,
    ) -> Self {
        Self {
            inner: MokaCache::builder().max_capacity(max_entries).build(),
            min_ttl,
            max_ttl,
            negative_ttl,
            max_negative_ttl,
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
        match msg.metadata.response_code {
            ResponseCode::NXDomain | ResponseCode::NoError if msg.answers.is_empty() => {
                // Negative cache: cap at SOA MINIMUM if present, else
                // operator default. (NoError + empty answers = NODATA.)
                let soa_min = msg
                    .authorities
                    .iter()
                    .find_map(|r| {
                        if r.record_type() == RecordType::SOA {
                            // SOA MINIMUM is the 7th field (index 6 in
                            // the wire format). hickory exposes it via
                            // the typed rdata.
                            if let hickory_proto::rr::RData::SOA(soa) = &r.data {
                                return Some(soa.minimum);
                            }
                        }
                        None
                    })
                    .unwrap_or(self.negative_ttl);
                // Use `max_negative_ttl` (not the positive
                // `max_ttl`) for the upper bound — see the field
                // doc-comment on why those are different caps.
                soa_min.min(self.max_negative_ttl).max(self.min_ttl)
            }
            ResponseCode::NoError => {
                // Positive cache: min TTL across answer section
                // (RFC 2181 §5.2 conservative reading).
                let min_answer_ttl = msg
                    .answers
                    .iter()
                    .map(|r| r.ttl)
                    .min()
                    .unwrap_or(self.negative_ttl);
                min_answer_ttl.min(self.max_ttl).max(self.min_ttl)
            }
            // SERVFAIL, REFUSED etc. never cache.
            _ => 0,
        }
    }

    pub fn entry_count(&self) -> u64 {
        // moka's `entry_count` is eventually-consistent — fresh
        // inserts can lag behind the counter by a scheduler tick or
        // two, which makes test assertions flaky ("I just put an
        // entry in, why is count 0?"). Walk iter() for an accurate
        // live count. Fine for observability paths; not a hot path.
        self.inner.iter().count() as u64
    }

    /// Drop every cached entry. Used by the control socket's `cache
    /// flush` op.
    pub fn flush(&self) {
        self.inner.invalidate_all();
    }

    /// Materialise a lightweight summary of currently-cached entries.
    /// Walks the moka cache and collects key + remaining TTL for each
    /// live entry. Called at debug time from `cache dump` — not a
    /// hot path.
    pub fn dump(&self) -> Vec<CacheDumpEntry> {
        let now = Instant::now();
        self.inner
            .iter()
            .filter_map(|(k, v)| {
                let remaining = v.expires.saturating_duration_since(now).as_secs();
                if remaining == 0 {
                    return None;
                }
                Some(CacheDumpEntry {
                    name: k.name.to_string(),
                    rtype: k.rtype.to_string(),
                    class: k.class.to_string(),
                    ttl_remaining_secs: remaining,
                    size_bytes: v.bytes.len(),
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CacheDumpEntry {
    pub name: String,
    pub rtype: String,
    pub class: String,
    pub ttl_remaining_secs: u64,
    pub size_bytes: usize,
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
        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
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
        let cache = DnsCache::new(100, 0, 3600, 60, 600);
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

    /// SOA MINIMUM of 1 day must be capped by max_negative_ttl, not
    /// by max_ttl (the positive cache cap). Without this cap an
    /// upstream NODATA carrying a high SOA MINIMUM (common — many
    /// zones set MINIMUM to 1 day) would strand IPv6-only clients on
    /// stale AAAA "no record" answers far beyond any practical
    /// outage window.
    #[test]
    fn negative_ttl_capped_by_max_negative_ttl() {
        use hickory_proto::rr::{rdata::SOA, RData, Record};

        // max_ttl=604800 (7d), max_negative_ttl=600 (10min),
        // soa.minimum=86400 (1d). Expect the 10-min cap to win.
        let cache = DnsCache::new(100, 0, 604_800, 3_600, 600);

        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError; // NoData
        let soa = SOA::new(
            Name::from_ascii("example.com.").unwrap(),
            Name::from_ascii("hostmaster.example.com.").unwrap(),
            1,
            7200,
            3600,
            1_209_600,
            86_400,
        );
        let soa_rec = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            86_400,
            RData::SOA(soa),
        );
        msg.add_authority(soa_rec);

        let ttl = cache.compute_ttl(&msg);
        assert_eq!(
            ttl, 600,
            "SOA MINIMUM of 86400 must be capped to max_negative_ttl=600, not max_ttl=604800"
        );
    }

    #[tokio::test]
    async fn servfail_not_cached() {
        let cache = DnsCache::new(100, 0, 3600, 60, 600);
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::ServFail;
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
