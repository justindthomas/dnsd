//! Response Rate Limiting — per-client token bucket keyed on the
//! client's /24 (IPv4) or /64 (IPv6). RRL is an amplification-attack
//! defence: the resolver is the *source* of traffic an attacker
//! would spoof, so capping each putative /24 / /64 of *victims*
//! protects the wider internet more than it protects us.
//!
//! The buckets refill at `qps` requests per second with burst
//! capacity `burst`. When a bucket empties, further queries from
//! that subnet are dropped silently for the rest of the current
//! millisecond window — the client retries (or gives up) and neither
//! the attacker nor the legitimate spoofed victim sees a flood.
//!
//! Implementation uses `governor`'s keyed rate-limiter so buckets
//! age out on their own; we don't need a scrub thread.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

use crate::config::RateLimit;

pub type ClientKey = (u8, u64); // (tag, bucket-id). tag=4 for v4, 6 for v6.

pub struct Rrl {
    inner: Arc<RateLimiter<ClientKey, DefaultKeyedStateStore<ClientKey>, DefaultClock>>,
}

impl Rrl {
    pub fn from_config(cfg: Option<&RateLimit>) -> Option<Self> {
        let (qps, burst) = match cfg {
            Some(c) => (c.per_client_qps?, c.per_client_burst.unwrap_or_else(|| c.per_client_qps.unwrap_or(100))),
            None => return None,
        };
        let qps = NonZeroU32::new(qps).unwrap_or(NonZeroU32::new(1).unwrap());
        let burst = NonZeroU32::new(burst).unwrap_or(qps);
        let quota = Quota::per_second(qps).allow_burst(burst);
        Some(Self {
            inner: Arc::new(RateLimiter::keyed(quota)),
        })
    }

    /// Returns `true` if the query should be allowed. `false` means
    /// the bucket is empty and the caller should drop the query
    /// silently (no SERVFAIL — an RRL drop is supposed to be
    /// indistinguishable from a loss, reducing info leakage).
    pub fn check(&self, peer: IpAddr) -> bool {
        self.inner.check_key(&bucket_key(peer)).is_ok()
    }
}

fn bucket_key(peer: IpAddr) -> ClientKey {
    match peer {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (4, ((o[0] as u64) << 16) | ((o[1] as u64) << 8) | (o[2] as u64))
        }
        IpAddr::V6(v6) => {
            // /64: high 8 bytes as one u64.
            let segs = v6.segments();
            let mut hi: u64 = 0;
            for s in &segs[..4] {
                hi = (hi << 16) | (*s as u64);
            }
            (6, hi)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_bucket_is_slash_24() {
        assert_eq!(bucket_key("10.0.1.5".parse().unwrap()), (4, (10 << 16) | (0 << 8) | 1));
        // Same /24 → same key; different host octet → same key.
        assert_eq!(
            bucket_key("10.0.1.5".parse().unwrap()),
            bucket_key("10.0.1.250".parse().unwrap())
        );
        // Different /24 → different key.
        assert_ne!(
            bucket_key("10.0.1.5".parse().unwrap()),
            bucket_key("10.0.2.5".parse().unwrap())
        );
    }

    #[test]
    fn v6_bucket_is_slash_64() {
        // Within /64 → same key.
        assert_eq!(
            bucket_key("2001:db8::1".parse().unwrap()),
            bucket_key("2001:db8::dead:beef".parse().unwrap())
        );
        // Different /64 → different key.
        assert_ne!(
            bucket_key("2001:db8::1".parse().unwrap()),
            bucket_key("2001:db8:1::1".parse().unwrap())
        );
    }

    #[test]
    fn disabled_rrl_returns_none() {
        assert!(Rrl::from_config(None).is_none());
        let cfg = RateLimit {
            per_client_qps: None,
            per_client_burst: None,
        };
        assert!(Rrl::from_config(Some(&cfg)).is_none());
    }

    #[test]
    fn enabled_rrl_admits_then_blocks() {
        let cfg = RateLimit {
            per_client_qps: Some(2),
            per_client_burst: Some(2),
        };
        let rrl = Rrl::from_config(Some(&cfg)).expect("enabled");
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(rrl.check(peer));
        assert!(rrl.check(peer));
        // Third should be blocked.
        assert!(!rrl.check(peer));
        // Different /24 still allowed.
        assert!(rrl.check("10.0.1.1".parse().unwrap()));
    }
}
