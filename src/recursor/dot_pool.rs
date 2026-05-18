//! Per-worker pool of reusable DoT upstream connections — phase 5
//! workstream A of the `via: tor` forwarder feature.
//!
//! ## Why a pool
//!
//! The phase-4 DoT path opened a fresh connection per query: TCP
//! connect → SOCKS5 `CONNECT` (for `via: tor`) → TLS handshake → one
//! length-prefixed exchange → close. For `via: tor` that also burns a
//! fresh Tor circuit each time — ~1 s+ of setup before the query even
//! goes out. Under load that blows past the upstream timeout, clients
//! retry, and it storms. Keeping the TLS connection (and its Tor
//! circuit) alive and reusing it across queries removes that setup
//! cost from the steady state.
//!
//! ## Per-worker, by construction
//!
//! A `VclStream` is **thread-owned** — it can only be driven on the
//! vcl-io worker that created it (using it from another thread is an
//! `EBADFD`). So a connection cannot be shared across workers; the
//! pool is therefore *per worker*, exactly like `UpstreamUdpChannel`.
//! `UpstreamClient` holds one `DotPool` per vcl-io worker; a query
//! dispatched onto worker *i* only ever touches pool *i*. Within a
//! worker the pool is driven from a single-threaded tokio runtime, so
//! the interior mutability is a plain `Mutex` with no contention in
//! the common case (held only for the O(few) acquire/release book-
//! keeping, never across an await).
//!
//! ## One query at a time per connection
//!
//! No pipelining / TXID-demux on a shared stream — a `DotConn` is
//! handed out exclusively to one query and returned when it finishes.
//! Concurrency comes from the pool holding several connections per
//! key. This keeps the failure model trivial: a connection is either
//! idle-in-pool or checked-out, never both.
//!
//! ## Fail-closed
//!
//! The pool key includes `via`, the tor-SOCKS endpoint, and (for a
//! tor key) the SOCKS isolation username, so a `via: tor` connection
//! is *only ever* reused for a `via: tor` query to the same resolver
//! through the same tord *for the same forwarder*. There is no code
//! path that lets a tor query borrow a direct connection, and the
//! stale-connection rebuild re-runs the *same* builder (which still
//! goes SOCKS5→tord for a tor key) — the retry never widens the
//! fail-closed envelope.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::Via;

/// Drop a pooled connection that has been idle longer than this.
/// DoT keep-alive (RFC 7858 §3.4 leaves it implementation-defined,
/// resolvers typically time out idle connections in tens of seconds)
/// and Tor circuit aging both argue for a conservative cap.
const IDLE_CAP: Duration = Duration::from_secs(30);

/// Hard cap on the lifetime of a pooled connection regardless of how
/// busy it is. Bounds Tor-circuit reuse and forces periodic re-
/// handshakes so a connection can't be pinned forever.
const MAX_LIFETIME: Duration = Duration::from_secs(300);

/// Maximum idle connections kept per key. Beyond this, `release`
/// drops the connection instead of pooling it. Concurrency above
/// this just falls back to per-query connect, same as phase 4.
const MAX_PER_KEY: usize = 4;

/// Identifies one upstream DoT endpoint. Connections are reused only
/// within the same key — same resolver, same TLS identity, same
/// reachability (direct vs. which tord). Keying on `via` + the tor
/// SOCKS endpoint is what makes fail-closed structural: a tor key
/// and a direct key are distinct, so a tor query can never be handed
/// a direct connection.
///
/// For a `via: tor` key the forwarder domain is also part of the key
/// (`iso_user`): tord's `PerUpstream` isolation gives each SOCKS
/// username its own Tor circuit family, so a connection built for
/// forwarder X's traffic rides X's circuits. Reusing it for forwarder
/// Y — even when Y resolves to the same server IP — would carry Y's
/// queries over X's circuits and defeat the isolation. Keying on the
/// domain keeps pooled reuse honest: a connection is reused only for
/// the forwarder it was isolated for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DotConnKey {
    /// Resolver address (the DoT server itself, port 853).
    pub resolver: SocketAddr,
    /// TLS server name verified on the handshake.
    pub tls_name: String,
    /// Direct vs. tor.
    pub via: Via,
    /// tord's SOCKS5 endpoint for `via: tor` keys; `None` for direct.
    /// Part of the key so connections through two different tords
    /// are never confused.
    pub tor_socks: Option<SocketAddr>,
    /// SOCKS5 isolation username — the matched forwarder domain — for
    /// `via: tor` keys; `None` for direct (no Tor circuit, nothing to
    /// isolate). Part of the key so a pooled tor connection is reused
    /// only for the forwarder whose circuit family it belongs to.
    pub iso_user: Option<String>,
}

/// One pooled, established DoT connection: a TLS stream already
/// handshaken (and, for a tor key, SOCKS-tunnelled through tord),
/// ready for `exchange_dot`-style length-prefixed exchanges.
pub struct DotConn<S> {
    stream: S,
    created_at: Instant,
    last_used: Instant,
}

impl<S> DotConn<S> {
    /// Wrap a freshly-built stream as a pooled connection.
    pub fn new(stream: S) -> Self {
        let now = Instant::now();
        Self {
            stream,
            created_at: now,
            last_used: now,
        }
    }

    /// Mutable access to the underlying TLS stream for the exchange.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// True when this connection is too old / too long idle to trust
    /// for reuse. Checked on acquire (before handing it out) and on
    /// release (before pooling it).
    fn is_stale(&self, now: Instant) -> bool {
        now.duration_since(self.last_used) >= IDLE_CAP
            || now.duration_since(self.created_at) >= MAX_LIFETIME
    }
}

/// A per-worker pool of reusable DoT connections, keyed by upstream
/// endpoint. Lives on (and is only ever touched from) a single
/// vcl-io worker — see the module docs.
pub struct DotPool<S> {
    idle: Mutex<HashMap<DotConnKey, Vec<DotConn<S>>>>,
}

impl<S> Default for DotPool<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> DotPool<S> {
    pub fn new() -> Self {
        Self {
            idle: Mutex::new(HashMap::new()),
        }
    }
}

impl<S> DotPool<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{

    /// Take an idle, non-stale connection for `key` if one exists.
    /// Stale connections encountered along the way are evicted (and
    /// dropped, closing the underlying socket / Tor circuit). Returns
    /// `None` when the caller must build a fresh connection.
    pub fn take(&self, key: &DotConnKey) -> Option<DotConn<S>> {
        let now = Instant::now();
        let mut idle = self.idle.lock().unwrap();
        let bucket = idle.get_mut(key)?;
        // Pop from the back (LIFO) — the most-recently-released
        // connection is the warmest and least likely to have been
        // closed by the far end.
        while let Some(conn) = bucket.pop() {
            if !conn.is_stale(now) {
                return Some(conn);
            }
            // stale → drop it (socket / circuit closes)
        }
        if bucket.is_empty() {
            idle.remove(key);
        }
        None
    }

    /// Return a healthy connection to the pool for future reuse.
    /// Drops it instead when it is stale or the per-key bucket is
    /// already full. `last_used` is stamped here so idle-eviction
    /// measures from the end of the last exchange.
    pub fn release(&self, key: &DotConnKey, mut conn: DotConn<S>) {
        let now = Instant::now();
        conn.last_used = now;
        if conn.is_stale(now) {
            return; // too old to be worth keeping
        }
        let mut idle = self.idle.lock().unwrap();
        let bucket = idle.entry(key.clone()).or_default();
        if bucket.len() >= MAX_PER_KEY {
            return; // bucket full — drop, fall back to per-query connect
        }
        bucket.push(conn);
    }

    /// Light periodic sweep: drop every stale connection across all
    /// keys. Eviction also happens lazily in `take`; this just keeps
    /// idle connections from lingering when a key goes quiet.
    pub fn sweep(&self) {
        let now = Instant::now();
        let mut idle = self.idle.lock().unwrap();
        idle.retain(|_, bucket| {
            bucket.retain(|c| !c.is_stale(now));
            !bucket.is_empty()
        });
    }

    /// Total idle connections currently pooled — test/diagnostic.
    #[cfg(test)]
    pub fn idle_count(&self) -> usize {
        self.idle.lock().unwrap().values().map(|b| b.len()).sum()
    }
}

/// Run one DoT exchange for `key`, reusing a pooled connection when
/// one is available and building a fresh one otherwise.
///
/// `build` is the connection factory: it must establish a stream that
/// honours `key` exactly — for a `via: tor` key it MUST go
/// `connect_stream → SOCKS5 CONNECT → TLS handshake`, never direct.
/// The pool calls it on a cache miss and again for the one rebuild
/// retry; because it is the same closure both times, a rebuilt
/// connection for a tor key still goes through tor. Fail-closed is
/// preserved by construction.
///
/// `exchange` runs the length-prefixed query/response over a stream.
/// It takes the stream **by value** and hands it back alongside the
/// result — `(stream, Result<response>)` — so the pool can return a
/// still-healthy stream for reuse without any borrow-lifetime gymna-
/// stics across the rebuild path. In production the closure body is
/// the *unchanged* phase-4 framing (`dot_client::exchange_dot`) plus
/// TXID/0x20 verification.
///
/// ## Stale-connection detection + one-retry rebuild
///
/// A pooled connection can be silently dead: the resolver (or tord, or
/// a Tor relay) may have closed it while it sat idle. There is no
/// cheap liveness probe for a TLS-over-SOCKS stream, so staleness is
/// detected *by trying*: if the exchange on a reused connection fails
/// (write error, read error, EOF — or a TXID/0x20 mismatch, which on
/// a reused stream means stale buffered data), that connection is
/// discarded and a **fresh** one is built and the exchange retried —
/// exactly once. A reused-connection failure is therefore transparent
/// to the caller. The retry budget is one: a freshly-built connection
/// that also fails propagates the error (it is a real upstream
/// problem, not a stale-pool artefact). A connection that was *built
/// fresh* on the first attempt (pool miss) is not retried — there is
/// nothing stale to blame.
///
/// On success the connection is returned to the pool via `release`.
pub async fn exchange_pooled<S, B, BFut, X, XFut>(
    pool: &DotPool<S>,
    key: &DotConnKey,
    build: B,
    exchange: X,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    B: Fn() -> BFut,
    BFut: std::future::Future<Output = Result<S>>,
    X: Fn(S) -> XFut,
    XFut: std::future::Future<Output = (S, Result<Vec<u8>>)>,
{
    // First attempt: reuse a pooled connection if there is one.
    if let Some(conn) = pool.take(key) {
        let (stream, result) = exchange(conn.stream).await;
        match result {
            Ok(resp) => {
                // Healthy — re-pool the stream (release stamps
                // last_used).
                pool.release(key, DotConn::new(stream));
                return Ok(resp);
            }
            Err(reuse_err) => {
                // Stale pooled connection. The stream is dropped here
                // (closing the socket / Tor circuit); rebuild fresh —
                // once.
                tracing::debug!(
                    resolver = %key.resolver,
                    via = ?key.via,
                    "dot-pool: reused connection failed ({reuse_err:#}); rebuilding",
                );
                drop(stream);
                let fresh = build()
                    .await
                    .map_err(|e| anyhow!("dot-pool rebuild after stale conn: {e:#}"))?;
                let (stream, result) = exchange(fresh).await;
                let resp = result
                    .map_err(|e| anyhow!("dot-pool: rebuilt connection also failed: {e:#}"))?;
                pool.release(key, DotConn::new(stream));
                return Ok(resp);
            }
        }
    }

    // Pool miss: build a fresh connection. No retry here — a
    // brand-new connection that fails is a genuine upstream error,
    // not a stale-pool artefact, and must surface to the caller.
    let fresh = build().await?;
    let (stream, result) = exchange(fresh).await;
    let resp = result?;
    pool.release(key, DotConn::new(stream));
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn key(via: Via) -> DotConnKey {
        DotConnKey {
            resolver: "9.9.9.9:853".parse().unwrap(),
            tls_name: "dns.quad9.net".into(),
            via,
            tor_socks: match via {
                Via::Tor => Some("127.0.0.1:9050".parse().unwrap()),
                Via::Direct => None,
            },
            iso_user: match via {
                Via::Tor => Some("example.com".into()),
                Via::Direct => None,
            },
        }
    }

    /// A `DotConn` backed by a duplex stream, with `created_at` /
    /// `last_used` rewound by `age` so staleness can be tested
    /// without sleeping.
    fn aged_conn(age: Duration) -> DotConn<DuplexStream> {
        let (a, _b) = duplex(64);
        let mut c = DotConn::new(a);
        let then = Instant::now() - age;
        c.created_at = then;
        c.last_used = then;
        c
    }

    #[test]
    fn release_then_take_reuses_same_connection() {
        let pool: DotPool<DuplexStream> = DotPool::new();
        let k = key(Via::Direct);
        assert!(pool.take(&k).is_none(), "empty pool has nothing");
        let (a, _b) = duplex(64);
        pool.release(&k, DotConn::new(a));
        assert_eq!(pool.idle_count(), 1);
        let got = pool.take(&k);
        assert!(got.is_some(), "released connection is taken back");
        assert_eq!(pool.idle_count(), 0, "take removes it from the pool");
    }

    /// Push a connection straight into a key's bucket, bypassing
    /// `release` (which re-stamps `last_used`). Used to seed an
    /// already-stale connection for the eviction tests.
    fn seed(pool: &DotPool<DuplexStream>, k: &DotConnKey, conn: DotConn<DuplexStream>) {
        pool.idle.lock().unwrap().entry(k.clone()).or_default().push(conn);
    }

    #[test]
    fn release_refreshes_last_used() {
        // `release` measures idle from end-of-exchange: a connection
        // that sat idle before being released is re-stamped fresh,
        // so it IS pooled and IS taken back. (Idle eviction only
        // bites a connection that sits in the pool too long — see
        // `take_evicts_idle_expired_connection` / `sweep_*`.)
        let pool: DotPool<DuplexStream> = DotPool::new();
        let k = key(Via::Direct);
        pool.release(&k, aged_conn(IDLE_CAP + Duration::from_secs(1)));
        assert_eq!(pool.idle_count(), 1, "release re-stamps last_used → not stale");
        assert!(pool.take(&k).is_some());
    }

    #[test]
    fn take_evicts_idle_expired_connection() {
        // A connection that has sat IN the pool past the 30s idle
        // cap is evicted on `take` and never handed out.
        let pool: DotPool<DuplexStream> = DotPool::new();
        let k = key(Via::Direct);
        seed(&pool, &k, aged_conn(IDLE_CAP + Duration::from_secs(1)));
        assert_eq!(pool.idle_count(), 1, "seeded directly, no re-stamp");
        assert!(pool.take(&k).is_none(), "stale conn is not handed out");
        assert_eq!(pool.idle_count(), 0, "and it was evicted");
    }

    #[test]
    fn take_evicts_lifetime_expired_connection() {
        // A connection past MAX_LIFETIME is stale even if it was
        // used recently. Construct one with an old `created_at` but
        // a fresh `last_used`.
        let pool: DotPool<DuplexStream> = DotPool::new();
        let k = key(Via::Direct);
        let (a, _b) = duplex(64);
        let mut c = DotConn::new(a);
        c.created_at = Instant::now() - (MAX_LIFETIME + Duration::from_secs(1));
        // last_used stays ~now → only the lifetime cap makes it stale
        seed(&pool, &k, c);
        assert!(pool.take(&k).is_none(), "past MAX_LIFETIME → evicted");
    }

    #[test]
    fn take_pops_past_stale_to_reach_fresh() {
        // Bucket with a FRESH conn under a STALE one: take() pops the
        // stale (LIFO, top), evicts it, and keeps going to hand back
        // the fresh one underneath. Lazy eviction only drops what it
        // walks past — a stale conn *under* a fresh one survives the
        // take (and is reaped by a later take / sweep instead).
        let pool: DotPool<DuplexStream> = DotPool::new();
        let k = key(Via::Direct);
        let (a, _b) = duplex(64);
        seed(&pool, &k, DotConn::new(a)); // fresh, bottom
        seed(&pool, &k, aged_conn(IDLE_CAP + Duration::from_secs(5))); // stale, top
        assert!(
            pool.take(&k).is_some(),
            "take pops past the stale top conn and returns the fresh one",
        );
        assert_eq!(pool.idle_count(), 0, "the stale conn it walked past was evicted");
    }

    #[test]
    fn release_drops_when_bucket_full() {
        let pool: DotPool<DuplexStream> = DotPool::new();
        let k = key(Via::Direct);
        for _ in 0..MAX_PER_KEY + 3 {
            let (a, _b) = duplex(64);
            pool.release(&k, DotConn::new(a));
        }
        assert_eq!(
            pool.idle_count(),
            MAX_PER_KEY,
            "bucket is capped at MAX_PER_KEY"
        );
    }

    #[test]
    fn sweep_drops_stale_keeps_fresh() {
        let pool: DotPool<DuplexStream> = DotPool::new();
        let k = key(Via::Direct);
        let (a, _b) = duplex(64);
        seed(&pool, &k, DotConn::new(a)); // fresh
        seed(&pool, &k, aged_conn(IDLE_CAP * 2)); // stale
        pool.sweep();
        assert_eq!(pool.idle_count(), 1, "sweep keeps the fresh conn only");
    }

    #[test]
    fn tor_and_direct_keys_are_distinct() {
        // The fail-closed guarantee at the type level: a connection
        // released under a direct key is NOT reachable via the tor
        // key and vice versa.
        let pool: DotPool<DuplexStream> = DotPool::new();
        let (a, _b) = duplex(64);
        pool.release(&key(Via::Direct), DotConn::new(a));
        assert!(
            pool.take(&key(Via::Tor)).is_none(),
            "a direct connection must never satisfy a tor acquire",
        );
        assert!(
            pool.take(&key(Via::Direct)).is_some(),
            "the direct connection is still there for a direct acquire",
        );
    }

    // --- exchange_pooled: reuse, miss, stale-rebuild ---

    /// Owned-stream exchange stub matching `exchange_pooled`'s `X`
    /// contract: takes the stream by value, runs a ping/pong, hands
    /// the stream back with the result. A write/read failure (the
    /// far end was dropped) surfaces as `Err` — exactly the stale-
    /// connection signal the pool retries on.
    async fn exchange_ok(mut stream: DuplexStream) -> (DuplexStream, Result<Vec<u8>>) {
        let mut buf = [0u8; 4];
        let r = async {
            stream.write_all(b"ping").await?;
            stream.read_exact(&mut buf).await?;
            Ok::<Vec<u8>, anyhow::Error>(buf.to_vec())
        }
        .await;
        (stream, r)
    }

    #[tokio::test]
    async fn exchange_pooled_miss_builds_and_pools() {
        let pool: DotPool<DuplexStream> = DotPool::new();
        let k = key(Via::Direct);
        let builds = AtomicUsize::new(0);
        let build = || {
            builds.fetch_add(1, Ordering::SeqCst);
            async {
                // duplex pair: we drive the far end inline.
                let (near, mut far) = duplex(64);
                tokio::spawn(async move {
                    let mut b = [0u8; 4];
                    let _ = far.read_exact(&mut b).await;
                    let _ = far.write_all(b"pong").await;
                });
                Ok(near)
            }
        };
        let resp = exchange_pooled(&pool, &k, build, |s| exchange_ok(s))
            .await
            .unwrap();
        assert_eq!(resp, b"pong");
        assert_eq!(builds.load(Ordering::SeqCst), 1, "one build on a miss");
        assert_eq!(pool.idle_count(), 1, "connection returned to pool");
    }

    #[tokio::test]
    async fn exchange_pooled_reuses_without_building() {
        let pool: DotPool<DuplexStream> = DotPool::new();
        let k = key(Via::Direct);
        let builds = AtomicUsize::new(0);
        let build = || {
            builds.fetch_add(1, Ordering::SeqCst);
            async {
                let (near, mut far) = duplex(64);
                tokio::spawn(async move {
                    loop {
                        let mut b = [0u8; 4];
                        if far.read_exact(&mut b).await.is_err() {
                            break;
                        }
                        if far.write_all(b"pong").await.is_err() {
                            break;
                        }
                    }
                });
                Ok(near)
            }
        };
        // First call: miss → build.
        exchange_pooled(&pool, &k, &build, |s| exchange_ok(s))
            .await
            .unwrap();
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        // Second call: hit → no new build.
        let resp = exchange_pooled(&pool, &k, &build, |s| exchange_ok(s))
            .await
            .unwrap();
        assert_eq!(resp, b"pong");
        assert_eq!(
            builds.load(Ordering::SeqCst),
            1,
            "second call reused the pooled connection — no rebuild",
        );
    }

    #[tokio::test]
    async fn exchange_pooled_rebuilds_once_on_stale_connection() {
        let pool: DotPool<DuplexStream> = DotPool::new();
        let k = key(Via::Direct);
        // Pre-seed the pool with a dead connection: its far end is
        // dropped immediately, so an exchange on it fails.
        {
            let (near, far) = duplex(64);
            drop(far);
            pool.release(&k, DotConn::new(near));
        }
        let builds = AtomicUsize::new(0);
        let build = || {
            builds.fetch_add(1, Ordering::SeqCst);
            async {
                let (near, mut far) = duplex(64);
                tokio::spawn(async move {
                    let mut b = [0u8; 4];
                    let _ = far.read_exact(&mut b).await;
                    let _ = far.write_all(b"pong").await;
                });
                Ok(near)
            }
        };
        let resp = exchange_pooled(&pool, &k, build, |s| exchange_ok(s))
            .await
            .unwrap();
        assert_eq!(resp, b"pong", "rebuilt connection answered");
        assert_eq!(
            builds.load(Ordering::SeqCst),
            1,
            "exactly one rebuild after the stale connection",
        );
        assert_eq!(pool.idle_count(), 1, "rebuilt connection pooled");
    }

    #[tokio::test]
    async fn exchange_pooled_propagates_second_failure() {
        // Stale pooled connection AND the rebuild also fails — the
        // retry budget is one, so the second failure propagates.
        let pool: DotPool<DuplexStream> = DotPool::new();
        let k = key(Via::Direct);
        {
            let (near, far) = duplex(64);
            drop(far);
            pool.release(&k, DotConn::new(near));
        }
        let builds = AtomicUsize::new(0);
        let build = || {
            builds.fetch_add(1, Ordering::SeqCst);
            async {
                // Rebuilt connection is also dead.
                let (near, far) = duplex(64);
                drop(far);
                Ok(near)
            }
        };
        let err = exchange_pooled(&pool, &k, build, |s| exchange_ok(s))
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("rebuilt connection also failed"),
            "got: {err:#}",
        );
        assert_eq!(
            builds.load(Ordering::SeqCst),
            1,
            "only one rebuild attempt — retry budget is one",
        );
    }

    #[tokio::test]
    async fn exchange_pooled_miss_failure_is_not_retried() {
        // A pool miss that fails to build/exchange is a genuine
        // upstream error — no retry, the error surfaces immediately.
        let pool: DotPool<DuplexStream> = DotPool::new();
        let k = key(Via::Direct);
        let builds = AtomicUsize::new(0);
        let build = || {
            builds.fetch_add(1, Ordering::SeqCst);
            async {
                let (near, far) = duplex(64);
                drop(far);
                Ok(near)
            }
        };
        let err = exchange_pooled(&pool, &k, build, |s| exchange_ok(s))
            .await
            .unwrap_err();
        // The error is the raw exchange failure, not a "rebuilt" one.
        assert!(
            !format!("{err:#}").contains("rebuilt connection"),
            "a fresh-build miss must not be reported as a rebuild: {err:#}",
        );
        assert_eq!(
            builds.load(Ordering::SeqCst),
            1,
            "miss builds exactly once — no retry",
        );
    }
}
