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

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hickory_proto::op::Message;
use hickory_proto::rr::Name;
use hickory_proto::serialize::binary::BinDecodable;
use rand::Rng;
use tokio::sync::oneshot;
use vcl_rs::{query_tcp_dns_sync, VclDgramSocket, VclReactor};

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
/// Worker pool size for the *TCP* upstream path. UDP queries no
/// longer go through this pool — they multiplex across two
/// persistent VclDgramSockets owned by `AsyncUdpUpstream` and run
/// directly on the main Tokio thread (which is VCL worker-0,
/// already registered). TCP fallback is rare (only when an
/// upstream NS sets TC=1 to force TCP) so 4 workers is plenty.
/// Each worker holds a long-lived UDP socket per family for
/// fallback that-really-shouldn't-but-might-need-to share UDP, but
/// in practice the TCP path doesn't touch the per-worker UDP
/// sockets.
const UPSTREAM_WORKERS: usize = 4;

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

/// One unit of work for a worker thread. UDP queries used to live
/// here too but moved to the async-multiplexer path
/// (`AsyncUdpUpstream`) which doesn't need a worker pool. TCP
/// stays here because TCP sessions are connection-oriented (can't
/// multiplex on one socket the way UDP can) and libvppcom session
/// ops still need a registered worker thread.
enum UpstreamCmd {
    Tcp {
        peer: SocketAddr,
        source: Option<std::net::IpAddr>,
        query: Vec<u8>,
        timeout: Duration,
        reply: oneshot::Sender<vcl_rs::error::Result<Vec<u8>>>,
    },
}

/// Per-pending-query routing entry. The recv-demux task uses
/// `(peer_ip, txid)` to match incoming UDP datagrams back to the
/// awaiting query future.
type PendingMap = HashMap<(IpAddr, u16), oneshot::Sender<(Vec<u8>, SocketAddr)>>;

/// Async UDP upstream: one persistent VclDgramSocket per address
/// family, plus a demuxer task that reads responses and routes them
/// to the awaiting query future via `(peer_ip, txid)`. Lets dnsd
/// have arbitrarily-many concurrent in-flight UDP queries with no
/// dedicated worker threads — a single spawned recv loop per
/// family is enough.
///
/// Replaces the older "dispatch UDP commands to a dedicated worker
/// thread pool" approach. The worker pool was needed because
/// libvppcom requires every session op to run on the OS thread
/// that owns the worker context AND tokio's blocking pool was
/// off-limits — but the main Tokio thread itself is already
/// VCL-registered (worker-0 by `VclApp::init`), so calling VCL ops
/// on it directly is safe. With persistent sockets bound at
/// startup, all upstream UDP queries run on main and concurrency
/// is bounded only by FIFO/peer-state, not thread count.
struct AsyncUdpUpstream {
    v4_sock: Option<Arc<VclDgramSocket>>,
    v6_sock: Option<Arc<VclDgramSocket>>,
    pending: Arc<Mutex<PendingMap>>,
}

impl AsyncUdpUpstream {
    fn new(
        source_v4: Option<std::net::Ipv4Addr>,
        source_v6: Option<std::net::Ipv6Addr>,
        reactor: VclReactor,
    ) -> Result<Self> {
        let pending = Arc::new(Mutex::new(PendingMap::new()));

        let v4_sock = source_v4
            .map(|ip| {
                bind_ephemeral_with_source(IpAddr::V4(ip), reactor.clone())
                    .map(Arc::new)
                    .with_context(|| format!("bind v4 upstream socket on {ip}"))
            })
            .transpose()?;
        let v6_sock = source_v6
            .map(|ip| {
                bind_ephemeral_with_source(IpAddr::V6(ip), reactor.clone())
                    .map(Arc::new)
                    .with_context(|| format!("bind v6 upstream socket on {ip}"))
            })
            .transpose()?;

        // One demux task per family. Reads responses, looks up the
        // (peer, txid) -> oneshot sender, hands the bytes off.
        if let Some(s) = v4_sock.clone() {
            let p = pending.clone();
            tokio::spawn(async move { recv_demux_loop("v4", s, p).await });
        }
        if let Some(s) = v6_sock.clone() {
            let p = pending.clone();
            tokio::spawn(async move { recv_demux_loop("v6", s, p).await });
        }

        Ok(Self {
            v4_sock,
            v6_sock,
            pending,
        })
    }

    async fn query(
        &self,
        peer: SocketAddr,
        query: &[u8],
        expected_txid: u16,
        timeout: Duration,
    ) -> Result<(Vec<u8>, SocketAddr)> {
        let sock = match peer.ip() {
            IpAddr::V4(_) => self.v4_sock.as_ref(),
            IpAddr::V6(_) => self.v6_sock.as_ref(),
        }
        .ok_or_else(|| anyhow!("no upstream socket for family of {peer}"))?;

        let key = (peer.ip(), expected_txid);
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap();
            // 16-bit TXID across N concurrent queries to the same
            // peer collides with probability ~N/65k. Caller picks
            // TXIDs randomly; on the rare collision, fail the new
            // query so the original gets its expected response.
            // The caller's outer retry loop (query_ns_set or
            // query() in this file) will pick a fresh TXID and try
            // again, so this almost-never propagates to the user.
            if pending.contains_key(&key) {
                return Err(anyhow!(
                    "upstream UDP TXID collision for {peer} (txid={expected_txid:#06x})"
                ));
            }
            pending.insert(key, tx);
        }

        // RAII: ensure we clean up the pending entry on every exit
        // path (timeout, send error, drop). Without this, a query
        // future that's cancelled (e.g. by tokio::time::timeout
        // higher up) leaves a dangling entry that wedges the slot
        // for that (peer, txid) pair.
        struct Cleanup<'a> {
            pending: &'a Mutex<PendingMap>,
            key: (IpAddr, u16),
            disarmed: bool,
        }
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                if !self.disarmed {
                    self.pending.lock().unwrap().remove(&self.key);
                }
            }
        }
        let mut cleanup = Cleanup {
            pending: &self.pending,
            key,
            disarmed: false,
        };

        sock.send_to(query, peer)
            .await
            .map_err(|e| anyhow!("upstream UDP send to {peer}: {e:?}"))?;

        let (resp, from) = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(_)) => {
                return Err(anyhow!("upstream UDP {peer}: response channel closed"));
            }
            Err(_) => {
                return Err(anyhow!("upstream UDP {peer}: timed out"));
            }
        };
        cleanup.disarmed = true; // recv side already removed the entry
        Ok((resp, from))
    }
}

fn bind_ephemeral_with_source(
    source: IpAddr,
    reactor: VclReactor,
) -> Result<VclDgramSocket> {
    // Try a handful of random ephemeral ports — VPP's session
    // table can have a port in use even when Linux's wouldn't.
    const LOW: u16 = 32768;
    const HIGH: u16 = 60999;
    let mut last_err = None;
    for _ in 0..8 {
        let port: u16 = rand::thread_rng().gen_range(LOW..=HIGH);
        let addr = SocketAddr::new(source, port);
        match VclDgramSocket::bind(addr, reactor.clone()) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(anyhow!(
        "ephemeral source bind exhausted: {:?}",
        last_err
    ))
}

async fn recv_demux_loop(
    family: &'static str,
    sock: Arc<VclDgramSocket>,
    pending: Arc<Mutex<PendingMap>>,
) {
    let mut buf = vec![0u8; 4096];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                if n < 12 {
                    tracing::debug!(
                        family,
                        %peer,
                        n,
                        "upstream UDP: short response, dropping"
                    );
                    continue;
                }
                let txid = u16::from_be_bytes([buf[0], buf[1]]);
                let key = (peer.ip(), txid);
                let resp = buf[..n].to_vec();
                let waiter = {
                    let mut p = pending.lock().unwrap();
                    p.remove(&key)
                };
                match waiter {
                    Some(tx) => {
                        let _ = tx.send((resp, peer));
                    }
                    None => {
                        // Late response (caller already timed out
                        // and dropped its entry), or unsolicited
                        // packet, or TXID mismatch. Drop silently
                        // at debug.
                        tracing::debug!(
                            family,
                            %peer,
                            txid = format!("{:#06x}", txid),
                            "upstream UDP: unmatched response, dropping"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    family,
                    "upstream UDP recv loop error: {e:?} — sleeping briefly"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

pub struct UpstreamClient {
    /// Async UDP path: one persistent socket per family +
    /// `(peer, txid)` demultiplexer. Concurrency limited only by
    /// in-flight pending entries, not thread count.
    udp: Arc<AsyncUdpUpstream>,
    /// Sender side of the work queue. Cheap to clone (Arc internally
    /// in async-channel); we keep one and pass it around. Workers
    /// hold the matching Receiver clones. TCP-only now — UDP
    /// doesn't dispatch through here anymore.
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

/// Long-lived worker thread body. Registers as a VCL worker, opens
/// one persistent UDP socket per address family, then loops on the
/// command channel until shutdown.
///
/// Why long-lived sockets: every `vppcom_session_create` allocates a
/// 128 MB shared-memory FIFO segment from VPP's session layer that
/// is NOT reclaimed on `vppcom_session_close`. Creating a fresh
/// session per upstream query OOMed the host within ~130 queries on
/// jt-router. With one v4 + one v6 socket per worker, per-query
/// cost is just a sendto + busy-poll recvfrom on an existing
/// session — no leak.
fn upstream_worker(rx: async_channel::Receiver<UpstreamCmd>, worker_no: usize) {
    vcl_rs::register_worker_thread();
    // Workers that fail VCL registration would GP-fault inside
    // vppcom_session_create on first use; bail out instead.
    let vcl_idx = unsafe { vcl_rs::ffi::vppcom_worker_index() };
    if vcl_idx < 0 {
        tracing::warn!(
            worker_no,
            "upstream TCP worker registration failed — exiting (pool shrinks by one)"
        );
        return;
    }
    tracing::debug!(worker_no, vcl_idx, "upstream TCP worker thread started");

    // No persistent sockets here — TCP fallback creates one
    // ephemeral session per query inside query_tcp_dns_sync. UDP
    // doesn't route through this pool at all (handled by
    // AsyncUdpUpstream on the main Tokio thread). That keeps each
    // worker's per-thread VPP FIFO footprint to whatever
    // query_tcp_dns_sync allocates per query, not 256 MB sitting
    // around bound to family-specific sockets.
    while let Ok(cmd) = rx.recv_blocking() {
        match cmd {
            UpstreamCmd::Tcp { peer, source, query, timeout, reply } => {
                let res = query_tcp_dns_sync(peer, source, &query, timeout);
                let _ = reply.send(res);
            }
        }
    }
    tracing::debug!(worker_no, "upstream TCP worker thread exiting");
    unsafe {
        vcl_rs::ffi::vppcom_worker_unregister();
    }
}

/// Default VPP binary-API socket path. Operators can override per
/// instance if their VPP is bound to a non-default socket; today
/// nothing else in dnsd needs to touch VPP, so we just hardcode.
pub const DEFAULT_VPP_API_SOCKET: &str = "/run/vpp/core-api.sock";

/// Walk every VPP interface and return the first globally-routable
/// IPv6 address found. "Globally routable" excludes link-local
/// (fe80::/10), unique-local (fc00::/7), loopback, multicast,
/// IPv4-mapped, and the unspecified address — anything that
/// shouldn't appear as a public source. Returns None when no usable
/// address exists (e.g. v6-less router).
///
/// Used to auto-populate `source_v6` so dnsd doesn't need an explicit
/// config knob for the common case. The VCL API can't tell us VPP's
/// FIB-derived source, so we go around it via the binary API.
pub async fn discover_v6_source(
    vpp_api_socket: &str,
) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
    use vpp_api::generated::interface::{SwInterfaceDetails, SwInterfaceDump};
    use vpp_api::generated::ip::{AddressFamily, IpAddressDetails, IpAddressDump};
    use vpp_api::VppClient;

    let vpp = VppClient::connect(vpp_api_socket)
        .await
        .with_context(|| format!("connect VPP API socket {vpp_api_socket}"))?;

    let ifaces: Vec<SwInterfaceDetails> = vpp
        .dump::<SwInterfaceDump, SwInterfaceDetails>(SwInterfaceDump::default())
        .await
        .map_err(|e| anyhow!("sw_interface_dump: {e}"))?;

    for vi in &ifaces {
        if !vi.flags.is_admin_up() {
            continue;
        }
        let v6_addrs: Vec<IpAddressDetails> = vpp
            .dump::<IpAddressDump, IpAddressDetails>(IpAddressDump {
                sw_if_index: vi.sw_if_index,
                is_ipv6: true,
            })
            .await
            .unwrap_or_default();
        for d in v6_addrs {
            if d.prefix.af != AddressFamily::Ipv6 {
                continue;
            }
            let v6 = std::net::Ipv6Addr::from(d.prefix.address);
            if is_globally_routable_v6(&v6) {
                let name = vi.interface_name.trim_end_matches('\0');
                tracing::info!(
                    iface = name,
                    sw_if_index = vi.sw_if_index,
                    source_v6 = %v6,
                    "discovered v6 source from VPP"
                );
                return Ok(Some(v6));
            }
        }
    }
    Ok(None)
}

/// Mirror of `discover_v6_source` for v4: walks VPP's interface
/// list, picks the first globally-routable v4 address. Without
/// this, TCP outbound (which can't reliably FIB-pick a source the
/// way UDP does — VPP's TCP handshake state lookup doesn't match
/// when the SYN/ACK arrives if the session was unbound at connect
/// time) sits in NotConnected forever and times out.
pub async fn discover_v4_source(
    vpp_api_socket: &str,
) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
    use vpp_api::generated::interface::{SwInterfaceDetails, SwInterfaceDump};
    use vpp_api::generated::ip::{AddressFamily, IpAddressDetails, IpAddressDump};
    use vpp_api::VppClient;

    let vpp = VppClient::connect(vpp_api_socket)
        .await
        .with_context(|| format!("connect VPP API socket {vpp_api_socket}"))?;

    let ifaces: Vec<SwInterfaceDetails> = vpp
        .dump::<SwInterfaceDump, SwInterfaceDetails>(SwInterfaceDump::default())
        .await
        .map_err(|e| anyhow!("sw_interface_dump: {e}"))?;

    for vi in &ifaces {
        if !vi.flags.is_admin_up() {
            continue;
        }
        let v4_addrs: Vec<IpAddressDetails> = vpp
            .dump::<IpAddressDump, IpAddressDetails>(IpAddressDump {
                sw_if_index: vi.sw_if_index,
                is_ipv6: false,
            })
            .await
            .unwrap_or_default();
        for d in v4_addrs {
            if d.prefix.af != AddressFamily::Ipv4 {
                continue;
            }
            // VPP's `address` field is 16 bytes; for v4 the first
            // four are the address.
            let bytes = d.prefix.address;
            let v4 = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            if is_globally_routable_v4(&v4) {
                let name = vi.interface_name.trim_end_matches('\0');
                tracing::info!(
                    iface = name,
                    sw_if_index = vi.sw_if_index,
                    source_v4 = %v4,
                    "discovered v4 source from VPP"
                );
                return Ok(Some(v4));
            }
        }
    }
    Ok(None)
}

fn is_globally_routable_v4(v4: &std::net::Ipv4Addr) -> bool {
    if v4.is_unspecified() || v4.is_loopback() || v4.is_multicast() || v4.is_broadcast() {
        return false;
    }
    if v4.is_link_local() {
        return false;
    }
    if v4.is_private() {
        return false;
    }
    true
}

fn is_globally_routable_v6(v6: &std::net::Ipv6Addr) -> bool {
    if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() {
        return false;
    }
    let s = v6.segments();
    let high = s[0];
    // fe80::/10 link-local
    if (high & 0xffc0) == 0xfe80 {
        return false;
    }
    // fc00::/7 unique-local
    if (high & 0xfe00) == 0xfc00 {
        return false;
    }
    // ::ffff:0:0/96 IPv4-mapped
    if v6.to_ipv4_mapped().is_some() {
        return false;
    }
    true
}

impl UpstreamClient {
    pub fn new(
        reactor: VclReactor,
        timeout_ms: Option<u32>,
        source_v4: Option<std::net::Ipv4Addr>,
        source_v6: Option<std::net::Ipv6Addr>,
    ) -> Result<Self> {
        let timeout = Duration::from_millis(
            timeout_ms.map(|t| t as u64).unwrap_or(DEFAULT_UPSTREAM_TIMEOUT_MS),
        );

        if source_v6.is_none() {
            tracing::warn!(
                "no source_v6 — IPv6 upstream queries will time out. Set \
                 `dns.recursion.source_v6` to a globally-routable v6 on a \
                 VPP interface (typically the wan v6) to enable them."
            );
        }

        // Async UDP upstream: persistent v4/v6 sockets bound on the
        // main Tokio thread (which is already VCL worker-0). The
        // demux task per family routes responses by (peer, txid).
        let udp = Arc::new(
            AsyncUdpUpstream::new(source_v4, source_v6, reactor.clone())
                .context("AsyncUdpUpstream::new")?,
        );

        // Worker pool now serves only TCP fallback queries —
        // libvppcom requires those to run on a registered worker
        // thread and TCP sessions are connection-oriented (can't
        // multiplex like UDP). 4 workers is plenty for TC=1
        // fallback in normal operation.
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
        Ok(Self {
            udp,
            cmd_tx,
            reactor,
            timeout,
            source_v4,
            source_v6,
        })
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
        // Async multiplexer: send via the persistent per-family
        // socket on the main Tokio thread, await a (peer, txid)-
        // matched response from the demux task. No worker pool
        // dispatch — concurrency is bounded only by the pending
        // map size and per-peer FIFO state, not by thread count.
        let (resp, from) = self
            .udp
            .query(peer, query, expected_txid, self.timeout)
            .await
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
        // TXID match is enforced at the demux layer (the response
        // was routed to us BY the txid match), but verify here for
        // defense in depth.
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
