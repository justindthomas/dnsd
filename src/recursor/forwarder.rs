//! Per-domain forwarder routing + upstream client.
//!
//! Longest-suffix match on the question name picks the forwarder;
//! servers within a forwarder are tried in the configured order with
//! a per-attempt timeout.
//!
//! Upstream transport picks: UDP first via a fresh ephemeral
//! VclDgramSocket (independent source port per query — baseline
//! Kaminsky defence). If the UDP response has TC=1 (truncated), we
//! transparently retry the same server over TCP via a VclStream. If
//! the operator wants to skip UDP entirely, `force_tcp` bypasses the
//! first leg (useful for DoT-upstream configurations we'll add later).
//!
//! TXID randomisation is via `rand`; 0x20 case randomisation is
//! applied to the question name before send and verified on recv
//! (and silently reverted on the response so cached entries use the
//! canonical owner name).

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hickory_proto::op::Message;
use hickory_proto::rr::Name;
use hickory_proto::serialize::binary::BinDecodable;
use rand::Rng;
use tokio::sync::oneshot;
use vcl_rs::{query_tcp_dns_sync, query_udp_sync, VclReactor};

use crate::config::Forwarder as ForwarderCfg;

const DEFAULT_UPSTREAM_TIMEOUT_MS: u64 = 2500;
const MAX_TCP_MESSAGE: usize = 65535;

/// Size of the dedicated VCL worker thread pool. Each worker is a
/// long-lived `std::thread` that calls `vppcom_worker_register` once
/// at start, then loops on the command channel. libvppcom 25.10's
/// session/worker model requires every session op (create, bind,
/// sendto, recvfrom, close) to run on the OS thread that owns the
/// worker context. Tokio's blocking pool reuses threads across tasks
/// in a way that violates that — `vppcom_session_create` GP-faults on
/// `__vcl_worker_index` arithmetic when threads aren't registered
/// against a live worker. We bypass tokio's pool entirely for upstream
/// queries.
///
/// Sized to fit under libvppcom's per-app worker cap (defaults to 16
/// in 25.10, with worker-0 already taken by `VclApp::init` on the
/// main thread). 12 here leaves headroom for the listener side's
/// reactor + a couple of TLS handshake workers if/when we add a DoT/
/// DoH server-side path that uses VCL transport. The worker that
/// can't register simply exits; the effective pool shrinks but the
/// process keeps running.
const UPSTREAM_WORKERS: usize = 12;

/// Bound on the in-flight command queue. Each command is small (a few
/// hundred bytes for the wire query plus addresses); 256 is plenty
/// for a home-router workload and caps memory in pathological cases.
const UPSTREAM_QUEUE_DEPTH: usize = 256;

#[derive(Clone)]
pub struct Forwarders {
    // Sorted longest-first so iter().find() returns the most specific
    // suffix match in O(n). For imp-sized operator configs (tens of
    // domains) this is faster than a trie and far simpler.
    entries: Vec<ForwarderEntry>,
}

#[derive(Clone, Debug)]
struct ForwarderEntry {
    domain: Name,
    servers: Vec<std::net::IpAddr>,
}

impl Forwarders {
    /// Snapshot of the current forwarder table for control-socket
    /// inspection. Returns (domain, server list) in longest-suffix-
    /// first order — the same order `lookup()` walks.
    pub fn snapshot(&self) -> Vec<(String, Vec<std::net::IpAddr>)> {
        self.entries
            .iter()
            .map(|e| (e.domain.to_string(), e.servers.clone()))
            .collect()
    }

    pub fn new(configs: &[ForwarderCfg]) -> Result<Self> {
        let mut entries = Vec::with_capacity(configs.len());
        for c in configs {
            // Query names off the wire are FQDNs; `zone_of` only
            // matches when both names are FQDNs. Operator configs
            // typically omit the trailing dot (`iana.org`, not
            // `iana.org.`), so normalise here.
            let mut domain = Name::from_ascii(&c.domain)
                .with_context(|| format!("bad forwarder domain {:?}", c.domain))?;
            domain.set_fqdn(true);
            entries.push(ForwarderEntry {
                domain: domain.to_lowercase(),
                servers: c.servers.clone(),
            });
        }
        // Longest-suffix wins → sort by label count descending.
        entries.sort_by_key(|e| std::cmp::Reverse(e.domain.num_labels()));
        Ok(Self { entries })
    }

    /// Return the forwarder whose configured domain is a proper
    /// suffix of `qname`, preferring the most specific match. A
    /// domain of "." (the root) would match everything; operators
    /// who want a global forwarder should configure it explicitly.
    pub fn lookup(&self, qname: &Name) -> Option<&[std::net::IpAddr]> {
        let lq = qname.to_lowercase();
        self.entries
            .iter()
            .find(|e| is_suffix(&lq, &e.domain))
            .map(|e| e.servers.as_slice())
    }
}

/// True when `suffix` is an ancestor (or equal) of `name` —
/// i.e. `name` ends in `suffix`. Note hickory's `zone.zone_of(name)`
/// reads as "is `name` a subzone of `zone`", so the call order is
/// `suffix.zone_of(name)`, not the reverse.
fn is_suffix(name: &Name, suffix: &Name) -> bool {
    if name.num_labels() < suffix.num_labels() {
        return false;
    }
    suffix.zone_of(name)
}

/// One unit of work for a worker thread. The worker calls
/// `query_udp_sync` / `query_tcp_dns_sync` from vcl-rs and sends the
/// result back via `reply`. The query bytes / source / timeout are
/// owned values so the worker thread doesn't need to borrow from the
/// async caller.
enum UpstreamCmd {
    Udp {
        peer: SocketAddr,
        source: Option<std::net::IpAddr>,
        query: Vec<u8>,
        timeout: Duration,
        reply: oneshot::Sender<vcl_rs::error::Result<(Vec<u8>, SocketAddr)>>,
    },
    Tcp {
        peer: SocketAddr,
        source: Option<std::net::IpAddr>,
        query: Vec<u8>,
        timeout: Duration,
        reply: oneshot::Sender<vcl_rs::error::Result<Vec<u8>>>,
    },
}

pub struct UpstreamClient {
    /// Sender side of the work queue. Cheap to clone (Arc internally
    /// in async-channel); we keep one and pass it around. Workers
    /// hold the matching Receiver clones.
    cmd_tx: async_channel::Sender<UpstreamCmd>,
    timeout: Duration,
    /// Explicit source IP for outgoing v4 upstream queries. When
    /// None, vcl-rs binds 0.0.0.0:<random> and relies on VPP's
    /// FIB-based source selection — which works on most setups
    /// but emits src=0.0.0.0 on some (multi-interface, no
    /// default-route-to-peer, etc.). Setting this from the v4
    /// listener address makes upstream queries always carry a
    /// real source IP that real upstreams will accept.
    source_v4: Option<std::net::Ipv4Addr>,
    /// Same idea for v6 upstream queries.
    source_v6: Option<std::net::Ipv6Addr>,
    /// Held to keep the type API stable (callers still construct
    /// with a reactor) and to keep VPP's session layer alive for the
    /// listener side via reference counting; the upstream path
    /// itself doesn't go through this reactor.
    #[allow(dead_code)]
    reactor: VclReactor,
}

/// Long-lived worker thread body. Registers as a VCL worker once at
/// startup, then loops on the command channel until the channel is
/// closed (i.e. UpstreamClient is dropped on shutdown). All VCL
/// session ops for upstream queries happen here; the thread is
/// dedicated and never migrates work to another OS thread, so
/// libvppcom's worker-per-thread invariant holds.
fn upstream_worker(rx: async_channel::Receiver<UpstreamCmd>, worker_no: usize) {
    vcl_rs::register_worker_thread();
    // libvppcom 25.10 caps workers per app — past that,
    // vppcom_worker_register returns -17 and leaves __vcl_worker_index
    // at -1. A thread in that state would GP-fault inside
    // vppcom_session_create on the very first command, taking down
    // the whole process. Bail this thread out instead — the effective
    // pool is just smaller. The remaining workers still drain the
    // queue.
    let vcl_idx = unsafe { vcl_rs::ffi::vppcom_worker_index() };
    if vcl_idx < 0 {
        tracing::warn!(
            worker_no,
            "upstream worker registration failed — exiting (effective pool shrinks by one)"
        );
        return;
    }
    tracing::debug!(worker_no, vcl_idx, "upstream worker thread started");
    while let Ok(cmd) = rx.recv_blocking() {
        match cmd {
            UpstreamCmd::Udp { peer, source, query, timeout, reply } => {
                let res = query_udp_sync(peer, source, &query, timeout);
                let _ = reply.send(res);
            }
            UpstreamCmd::Tcp { peer, source, query, timeout, reply } => {
                let res = query_tcp_dns_sync(peer, source, &query, timeout);
                let _ = reply.send(res);
            }
        }
    }
    tracing::debug!(worker_no, "upstream worker thread exiting");
    unsafe {
        vcl_rs::ffi::vppcom_worker_unregister();
    }
}

impl UpstreamClient {
    pub fn new(reactor: VclReactor, timeout_ms: Option<u32>) -> Self {
        let timeout = Duration::from_millis(
            timeout_ms.map(|t| t as u64).unwrap_or(DEFAULT_UPSTREAM_TIMEOUT_MS),
        );
        let (cmd_tx, cmd_rx) =
            async_channel::bounded::<UpstreamCmd>(UPSTREAM_QUEUE_DEPTH);
        for i in 0..UPSTREAM_WORKERS {
            let rx = cmd_rx.clone();
            std::thread::Builder::new()
                .name(format!("dnsd-up-{i:02}"))
                .spawn(move || upstream_worker(rx, i))
                .expect("spawn upstream worker thread");
        }
        // Drop our local Receiver so the worker clones are the only
        // consumers. Channel will close cleanly when cmd_tx is dropped
        // (i.e. when UpstreamClient drops at shutdown).
        drop(cmd_rx);
        Self {
            cmd_tx,
            reactor,
            timeout,
            source_v4: None,
            source_v6: None,
        }
    }

    /// Set the source IPs used for upstream queries. Called by
    /// `RecursorHandler::from_parts` after listener config is parsed
    /// so we can prefer "the address dnsd is bound to" as the
    /// source — that's an interface VPP definitely has a route
    /// for, and it makes packets attributable to dnsd in upstream
    /// captures.
    pub fn set_source_ips(
        &mut self,
        v4: Option<std::net::Ipv4Addr>,
        v6: Option<std::net::Ipv6Addr>,
    ) {
        self.source_v4 = v4;
        self.source_v6 = v6;
    }

    fn source_for(&self, peer: SocketAddr) -> Option<std::net::IpAddr> {
        match peer.ip() {
            std::net::IpAddr::V4(_) => self.source_v4.map(std::net::IpAddr::V4),
            std::net::IpAddr::V6(_) => self.source_v6.map(std::net::IpAddr::V6),
        }
    }

    /// Send `query` to the first server that answers (round-robin
    /// through the list, one timeout per server). `query` is the
    /// wire-format request from the client; we rewrite the TXID and
    /// forward, then rewrite the response TXID back on the way out.
    pub async fn query(
        &self,
        servers: &[std::net::IpAddr],
        query: &[u8],
    ) -> Result<Vec<u8>> {
        if servers.is_empty() {
            return Err(anyhow!("forwarder has no upstream servers"));
        }

        let mut last_err = None;
        for server_ip in servers {
            let peer = SocketAddr::new(*server_ip, 53);
            match self.query_one(peer, query).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    tracing::debug!(%peer, "upstream query failed: {e}");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no forwarder server responded")))
    }

    async fn query_one(&self, peer: SocketAddr, orig_query: &[u8]) -> Result<Vec<u8>> {
        let orig_msg = Message::from_bytes(orig_query).context("parse client query")?;
        let client_txid = orig_msg.id();
        let upstream_txid: u16 = rand::thread_rng().gen();

        // Build the upstream wire. Fresh TXID + 0x20-randomised
        // question name; the body is otherwise byte-identical to
        // what the client sent us.
        let mut out = orig_query.to_vec();
        out[0..2].copy_from_slice(&upstream_txid.to_be_bytes());
        let expected_qname = super::zeroxtwenty::encode(&mut out)
            .context("0x20 encode upstream query")?;

        // UDP first.
        let udp_resp = self
            .query_one_udp(peer, &out, upstream_txid, &expected_qname)
            .await?;
        let parsed = Message::from_bytes(&udp_resp).context("parse UDP response")?;

        // TC=1 → retry the same server over TCP per RFC 7766 §6.2.2.
        // Fresh TXID + fresh 0x20 mask for the TCP hop.
        let final_resp = if parsed.truncated() {
            tracing::debug!(%peer, "TC=1 on UDP; retrying over TCP");
            let tcp_txid: u16 = rand::thread_rng().gen();
            let mut tcp_out = orig_query.to_vec();
            tcp_out[0..2].copy_from_slice(&tcp_txid.to_be_bytes());
            let tcp_mask = super::zeroxtwenty::encode(&mut tcp_out)
                .context("0x20 encode TCP retry")?;
            self.query_one_tcp(peer, &tcp_out, tcp_txid, &tcp_mask).await?
        } else {
            udp_resp
        };

        // Parse, lowercase every owner name (kills the 0x20-randomised
        // case leak from upstream into the client response), restore
        // the client's TXID, re-serialise. The case-leak fix matches
        // BIND/Unbound; see `normalize` for the rationale.
        let mut parsed = Message::from_bytes(&final_resp)
            .context("parse upstream response for normalisation")?;
        super::normalize::lowercase_response_names(&mut parsed);
        parsed.set_id(client_txid);
        let resp = parsed
            .to_vec()
            .context("re-encode normalised forwarder response")?;
        Ok(resp)
    }

    async fn query_one_udp(
        &self,
        peer: SocketAddr,
        query: &[u8],
        expected_txid: u16,
        expected_qname: &[u8],
    ) -> Result<Vec<u8>> {
        // Upstream UDP queries dispatch to a dedicated VCL worker
        // thread via the command channel. See `UPSTREAM_WORKERS` for
        // why we don't use tokio's blocking pool: libvppcom 25.10
        // requires every session op to run on the OS thread that
        // owns the worker context, and tokio's blocking pool makes
        // that invariant hard to keep.
        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = UpstreamCmd::Udp {
            peer,
            source: self.source_for(peer),
            query: query.to_vec(),
            timeout: self.timeout,
            reply: reply_tx,
        };
        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| anyhow!("upstream worker pool channel closed"))?;
        let (resp, from) = reply_rx
            .await
            .map_err(|_| anyhow!("upstream worker dropped reply channel for {peer}"))?
            .with_context(|| format!("upstream UDP {peer}"))?;

        if from.ip() != peer.ip() {
            return Err(anyhow!(
                "upstream UDP response from unexpected address {from} (wanted {peer})"
            ));
        }
        let n = resp.len();
        if n < 12 {
            return Err(anyhow!("short upstream UDP response ({n} bytes)"));
        }
        let rx_txid = u16::from_be_bytes([resp[0], resp[1]]);
        if rx_txid != expected_txid {
            return Err(anyhow!(
                "upstream UDP TXID mismatch: got {rx_txid:#06x} expected {expected_txid:#06x}"
            ));
        }
        super::zeroxtwenty::verify(&resp, expected_qname)
            .with_context(|| format!("upstream UDP {peer} 0x20 mismatch"))?;
        Ok(resp)
    }

    /// Send one query to `peer` over TCP (RFC 1035 §4.2.2 2-byte
    /// length framing). Used both for TC-fallback and for forwarders
    /// configured as TCP-only upstreams. Dispatches to the same
    /// dedicated VCL worker pool as UDP — see `UPSTREAM_WORKERS`.
    pub async fn query_one_tcp(
        &self,
        peer: SocketAddr,
        query: &[u8],
        expected_txid: u16,
        expected_qname: &[u8],
    ) -> Result<Vec<u8>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = UpstreamCmd::Tcp {
            peer,
            source: self.source_for(peer),
            query: query.to_vec(),
            timeout: self.timeout,
            reply: reply_tx,
        };
        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| anyhow!("upstream worker pool channel closed"))?;
        let resp = reply_rx
            .await
            .map_err(|_| {
                anyhow!("upstream worker dropped reply channel for TCP {peer}")
            })?
            .with_context(|| format!("upstream TCP {peer}"))?;

        if resp.len() < 12 {
            return Err(anyhow!("short upstream TCP response ({} bytes)", resp.len()));
        }
        if resp.len() > MAX_TCP_MESSAGE {
            return Err(anyhow!("oversized upstream TCP response ({} bytes)", resp.len()));
        }
        let rx_txid = u16::from_be_bytes([resp[0], resp[1]]);
        if rx_txid != expected_txid {
            return Err(anyhow!(
                "upstream TCP TXID mismatch: got {rx_txid:#06x} expected {expected_txid:#06x}"
            ));
        }
        super::zeroxtwenty::verify(&resp, expected_qname)
            .with_context(|| format!("upstream TCP {peer} 0x20 mismatch"))?;
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fwd(domain: &str, servers: &[&str]) -> ForwarderCfg {
        ForwarderCfg {
            domain: domain.into(),
            servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn longest_suffix_wins() {
        let configs = vec![
            fwd("jdt.io", &["10.42.128.19"]),
            fwd("k8s.jdt.io", &["10.42.113.4"]),
            fwd("emeraldbroadband.net", &["10.10.90.35", "10.10.90.36"]),
        ];
        let f = Forwarders::new(&configs).unwrap();

        let hit = f
            .lookup(&Name::from_ascii("foo.k8s.jdt.io.").unwrap())
            .unwrap();
        assert_eq!(hit, &["10.42.113.4".parse::<std::net::IpAddr>().unwrap()]);

        let hit2 = f.lookup(&Name::from_ascii("www.jdt.io.").unwrap()).unwrap();
        assert_eq!(
            hit2,
            &["10.42.128.19".parse::<std::net::IpAddr>().unwrap()]
        );

        let hit3 = f
            .lookup(&Name::from_ascii("ns1.emeraldbroadband.net.").unwrap())
            .unwrap();
        assert_eq!(hit3.len(), 2);
    }

    #[test]
    fn non_matching_returns_none() {
        let f = Forwarders::new(&[fwd("jdt.io", &["10.42.128.19"])]).unwrap();
        assert!(f.lookup(&Name::from_ascii("example.com.").unwrap()).is_none());
    }

    #[test]
    fn config_without_trailing_dot_matches_fqdn_query() {
        // Operator configs usually drop the trailing dot (`iana.org`,
        // not `iana.org.`); query names from the wire always have it.
        // Forwarders::new normalises the config side to FQDN so
        // `zone_of` works across that boundary.
        let f = Forwarders::new(&[fwd("iana.org", &["1.1.1.1"])]).unwrap();
        let hit = f
            .lookup(&Name::from_ascii("www.iana.org.").unwrap())
            .unwrap();
        assert_eq!(hit, &["1.1.1.1".parse::<std::net::IpAddr>().unwrap()]);
    }
}
