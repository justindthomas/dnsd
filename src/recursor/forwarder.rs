//! Per-domain forwarder routing + upstream client.
//!
//! Longest-suffix match on the question name picks the forwarder;
//! servers within a forwarder are tried in the configured order with
//! a per-attempt timeout.
//!
//! Upstream transport picks: UDP first via a fresh ephemeral
//! DnsDgramSocket (independent source port per query — baseline
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
use rand::RngExt;
use tokio::sync::oneshot;
use crate::io::transport::{self, DnsDgramSocket, ReactorCtx};

use crate::config::{Forwarder as ForwarderCfg, ForwarderServer};

const DEFAULT_UPSTREAM_TIMEOUT_MS: u64 = 2500;
const MAX_TCP_MESSAGE: usize = 65535;

// Both UDP and TCP upstream paths run async on the main Tokio
// thread — no worker pool, no spawn_blocking. The thread is VCL
// worker-0 (registered by VclApp::init), which satisfies VCL's
// invariant that session ops happen on the worker that owns the
// context. UDP multiplexes across persistent DnsDgramSockets
// (`AsyncUdpUpstream`); TCP uses VclStream::connect_async +
// query_tcp_dns_async with non-blocking sessions and the reactor
// for connect/read/write completion notifications.

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
    servers: Vec<ForwarderServer>,
}

impl Forwarders {
    /// Snapshot of the current forwarder table for control-socket
    /// inspection. Returns (domain, server list) in longest-suffix-
    /// first order — the same order `lookup()` walks.
    pub fn snapshot(&self) -> Vec<(String, Vec<String>)> {
        self.entries
            .iter()
            .map(|e| {
                (
                    e.domain.to_string(),
                    e.servers.iter().map(|s| s.address.to_string()).collect(),
                )
            })
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
                servers: c.resolved_servers()?,
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
    pub fn lookup(&self, qname: &Name) -> Option<&[ForwarderServer]> {
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

/// Per-pending-query routing entry. The recv-demux task uses
/// `(peer_ip, txid)` to match incoming UDP datagrams back to the
/// awaiting query future.
type PendingMap = HashMap<(IpAddr, u16), oneshot::Sender<(Vec<u8>, SocketAddr)>>;

/// One upstream UDP channel: a v4 + v6 socket pair, a recv-demux
/// task per family, and a `(peer, txid)` pending map — all bound to
/// and driven on one vcl-io worker thread. `AsyncUdpUpstream` holds
/// one channel per worker and round-robins queries across them, so
/// upstream UDP throughput scales with the pool instead of
/// funneling every recursive query's ~10 round-trips through a
/// single libvppcom thread.
struct UpstreamUdpChannel {
    v4_sock: Option<Arc<DnsDgramSocket>>,
    v6_sock: Option<Arc<DnsDgramSocket>>,
    pending: Arc<Mutex<PendingMap>>,
    /// The vcl-io worker this channel's sockets are bound to. Every
    /// libvppcom op for this channel (bind, send_to, the demux's
    /// recv_from) runs here — that's the registered VCL context
    /// that owns these sessions.
    #[cfg(feature = "vcl")]
    vcl_io: tokio::runtime::Handle,
}

impl UpstreamUdpChannel {
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
            // peer collides with probability ~N/65k. On collision,
            // fail the new query so the original gets its response;
            // the caller's retry loop picks a fresh TXID.
            if pending.contains_key(&key) {
                return Err(anyhow!(
                    "upstream UDP TXID collision for {peer} (txid={expected_txid:#06x})"
                ));
            }
            pending.insert(key, tx);
        }

        // RAII: clean up the pending entry on every exit path
        // (timeout, send error, drop) so a cancelled query future
        // doesn't wedge the (peer, txid) slot.
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

        // Dispatch the send_to onto this channel's vcl-io worker so
        // the libvppcom write happens on the thread that owns the
        // socket. The oneshot we await is pure-Rust signaling — the
        // main runtime thread parks freely while vcl-io sends.
        // DIAG: `send_ms` measures dispatch→send-complete (how long
        // the vcl-io worker took to pick up + run the send task);
        // `wait_ms` measures send-complete→response (the demux
        // path). Split tells us which side stalls under load.
        let send_t0 = std::time::Instant::now();
        #[cfg(feature = "vcl")]
        {
            let sock_for_send = sock.clone();
            let query_bytes = query.to_vec();
            let (s_tx, s_rx) = oneshot::channel();
            self.vcl_io.spawn(async move {
                let r = sock_for_send.send_to(&query_bytes, peer).await;
                let _ = s_tx.send(r);
            });
            match s_rx.await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(anyhow!("upstream UDP send to {peer}: {e:?}")),
                Err(_) => return Err(anyhow!("vcl-io send_to dispatch dropped")),
            }
        }
        #[cfg(not(feature = "vcl"))]
        {
            sock.send_to(query, peer)
                .await
                .map_err(|e| anyhow!("upstream UDP send to {peer}: {e:?}"))?;
        }
        let send_ms = send_t0.elapsed().as_millis() as u64;

        let wait_t0 = std::time::Instant::now();
        let timed = tokio::time::timeout(timeout, rx).await;
        let wait_ms = wait_t0.elapsed().as_millis() as u64;
        if send_ms + wait_ms >= 500 {
            tracing::debug!(
                %peer,
                send_ms,
                wait_ms,
                outcome = match &timed {
                    Ok(Ok(_)) => "ok",
                    Ok(Err(_)) => "chan-closed",
                    Err(_) => "timeout",
                },
                "upstream-udp: slow channel query",
            );
        }
        let (resp, from) = match timed {
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

/// Async UDP upstream: a pool of `UpstreamUdpChannel`s, one per
/// vcl-io worker. `query` round-robins across channels so the
/// libvppcom send/recv work for concurrent recursive walks spreads
/// across every worker thread rather than bottlenecking on one.
/// Each channel independently demuxes its own responses by
/// `(peer, txid)`.
struct AsyncUdpUpstream {
    channels: Vec<UpstreamUdpChannel>,
    next: std::sync::atomic::AtomicUsize,
}

impl AsyncUdpUpstream {
    /// Build one channel per vcl-io worker. `workers` is the pool's
    /// `(handle, reactor)` set; under kernel-sockets it's a single
    /// synthetic entry.
    async fn new(
        source_v4: Option<std::net::Ipv4Addr>,
        source_v6: Option<std::net::Ipv6Addr>,
        #[cfg(feature = "vcl")] workers: Vec<(tokio::runtime::Handle, ReactorCtx)>,
        #[cfg(not(feature = "vcl"))] reactor: ReactorCtx,
    ) -> Result<Self> {
        // VCL backend: source IP MUST be set or no socket binds —
        // VPP's session lookup needs an explicit local address.
        // Kernel backend: missing source → bind unspecified:eph.
        #[cfg(feature = "vcl")]
        let v4_source = source_v4.map(IpAddr::V4);
        #[cfg(feature = "vcl")]
        let v6_source = source_v6.map(IpAddr::V6);
        #[cfg(feature = "kernel-sockets")]
        let v4_source = Some(source_v4
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)));
        #[cfg(feature = "kernel-sockets")]
        let v6_source = Some(source_v6
            .map(IpAddr::V6)
            .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)));

        let mut channels = Vec::new();

        #[cfg(feature = "vcl")]
        for (vcl_io, reactor) in workers {
            let pending = Arc::new(Mutex::new(PendingMap::new()));
            // Bind dispatched onto this channel's vcl-io worker so
            // the socket-create + reactor registration happen on the
            // thread that will drive every send/recv on it.
            let v4_sock = bind_on_worker(v4_source, &reactor, &vcl_io, "v4").await?;
            let v6_sock = bind_on_worker(v6_source, &reactor, &vcl_io, "v6").await?;
            if let Some(s) = v4_sock.clone() {
                let p = pending.clone();
                vcl_io.spawn(async move { recv_demux_loop("v4", s, p).await });
            }
            if let Some(s) = v6_sock.clone() {
                let p = pending.clone();
                vcl_io.spawn(async move { recv_demux_loop("v6", s, p).await });
            }
            channels.push(UpstreamUdpChannel {
                v4_sock,
                v6_sock,
                pending,
                vcl_io,
            });
        }

        #[cfg(not(feature = "vcl"))]
        {
            let pending = Arc::new(Mutex::new(PendingMap::new()));
            let v4_sock = v4_source
                .map(|ip| {
                    bind_ephemeral_with_source(ip, reactor.clone())
                        .map(Arc::new)
                        .with_context(|| format!("bind v4 upstream socket on {ip}"))
                })
                .transpose()?;
            let v6_sock = v6_source
                .map(|ip| {
                    bind_ephemeral_with_source(ip, reactor.clone())
                        .map(Arc::new)
                        .with_context(|| format!("bind v6 upstream socket on {ip}"))
                })
                .transpose()?;
            if let Some(s) = v4_sock.clone() {
                let p = pending.clone();
                tokio::spawn(async move { recv_demux_loop("v4", s, p).await });
            }
            if let Some(s) = v6_sock.clone() {
                let p = pending.clone();
                tokio::spawn(async move { recv_demux_loop("v6", s, p).await });
            }
            channels.push(UpstreamUdpChannel {
                v4_sock,
                v6_sock,
                pending,
            });
        }

        if channels.is_empty() {
            return Err(anyhow!("AsyncUdpUpstream: no worker channels built"));
        }
        Ok(Self {
            channels,
            next: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Round-robin a query across the channel pool.
    async fn query(
        &self,
        peer: SocketAddr,
        query: &[u8],
        expected_txid: u16,
        timeout: Duration,
    ) -> Result<(Vec<u8>, SocketAddr)> {
        let i = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.channels.len();
        self.channels[i].query(peer, query, expected_txid, timeout).await
    }
}

/// Bind one ephemeral upstream UDP socket on a specific vcl-io
/// worker, dispatching the bind syscall onto that worker's runtime.
#[cfg(feature = "vcl")]
async fn bind_on_worker(
    source: Option<IpAddr>,
    reactor: &ReactorCtx,
    vcl_io: &tokio::runtime::Handle,
    family: &'static str,
) -> Result<Option<Arc<DnsDgramSocket>>> {
    let Some(ip) = source else { return Ok(None) };
    let r = reactor.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    vcl_io.spawn(async move {
        let result = bind_ephemeral_with_source(ip, r)
            .with_context(|| format!("bind {family} upstream socket on {ip}"));
        let _ = tx.send(result);
    });
    Ok(Some(Arc::new(
        rx.await
            .map_err(|_| anyhow!("vcl-io {family} bind dispatch dropped"))??,
    )))
}

fn bind_ephemeral_with_source(
    source: IpAddr,
    reactor: ReactorCtx,
) -> Result<DnsDgramSocket> {
    // Try a handful of random ephemeral ports — VPP's session
    // table can have a port in use even when Linux's wouldn't.
    const LOW: u16 = 32768;
    const HIGH: u16 = 60999;
    let mut last_err = None;
    for _ in 0..8 {
        let port: u16 = rand::rng().random_range(LOW..=HIGH);
        let addr = SocketAddr::new(source, port);
        match DnsDgramSocket::bind(addr, reactor.clone()) {
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
    sock: Arc<DnsDgramSocket>,
    pending: Arc<Mutex<PendingMap>>,
) {
    let mut buf = vec![0u8; 4096];
    // DIAG: track demux wake cadence. `last_wake` measures the gap
    // between successive drain passes — if it balloons, the demux
    // task is being starved on its worker thread (responses sit in
    // the FIFO unread). `total_drained` accumulates between log
    // lines so we see throughput.
    let mut last_wake = std::time::Instant::now();
    loop {
        let wake_gap_ms = last_wake.elapsed().as_millis() as u64;
        last_wake = std::time::Instant::now();
        // Drain greedily before yielding. The default
        // `sock.recv_from(...).await` checkpoints on every
        // datagram, and tokio's current_thread scheduler may
        // interleave dozens of other tasks (DoH connections,
        // listener accepts, etc.) between datagrams. Under load
        // that bottlenecks the demux at ~20 datagrams/s while VPP
        // is queuing >100/s — the RX FIFO grows, callers' 5s
        // upstream timeouts trip on responses that are actually
        // sitting in the FIFO unread.
        //
        // Pull every queued datagram in one sync-FFI tight loop
        // first, then park on the reactor. Cap the burst so a
        // pathological busy session can't monopolize vcl-io —
        // 16 calls × ~1 ms libvppcom floor = ~16 ms between
        // yields, fast enough that sibling listener tasks /
        // per-connection serve loops also get a slice while we
        // still drain meaningful batches per wake.
        let mut drained = 0u32;
        loop {
            if drained >= 16 {
                // Yield once so other tasks can run, then keep
                // draining if more datagrams arrived in the
                // meantime.
                tokio::task::yield_now().await;
                drained = 0;
            }
            match sock.try_recv_from(&mut buf) {
                Ok(Some((n, peer))) => {
                    drained += 1;
                    if n < 12 {
                        tracing::debug!(family, %peer, n, "upstream UDP: short response, dropping");
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
                            tracing::debug!(
                                family,
                                %peer,
                                txid = format!("{:#06x}", txid),
                                "upstream UDP: unmatched response, dropping"
                            );
                        }
                    }
                }
                Ok(None) => break, // FIFO drained — go park
                Err(e) => {
                    tracing::warn!(
                        family,
                        "upstream UDP recv loop error: {e:?} — sleeping briefly"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    break;
                }
            }
        }
        // DIAG: log a wake only when it looks pathological — the
        // demux went >100ms between drains (starved) or pulled a
        // big batch (>8, implying it fell behind). A healthy demux
        // wakes every ~10ms (the reactor tick) draining 0-1.
        let total = drained;
        if wake_gap_ms >= 100 || total > 8 {
            tracing::debug!(
                family,
                wake_gap_ms,
                drained = total,
                "demux: wake",
            );
        }
        if let Err(e) = sock.wait_readable().await {
            tracing::warn!(family, "upstream UDP wait_readable: {e:?}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

pub struct UpstreamClient {
    /// Async UDP path: a pool of per-worker channels (socket pair +
    /// demux), queries round-robined across them.
    udp: Arc<AsyncUdpUpstream>,
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
    /// Every vcl-io worker's `(handle, reactor)`. TCP upstream
    /// queries (DNSKEY fetches, TC=1 fallback) round-robin across
    /// these — `query_tcp_dns_async` issues libvppcom session calls
    /// which are only valid on a registered VCL worker thread, so
    /// each TCP query is dispatched onto a pool worker (with that
    /// worker's reactor). The main multi_thread runtime threads are
    /// NOT registered workers; calling inline there returns
    /// VPPCOM_EINVAL (-22). Round-robin keeps a burst of DNSKEY
    /// fetches from all queueing on one thread.
    #[cfg(feature = "vcl")]
    workers: Vec<(tokio::runtime::Handle, ReactorCtx)>,
    #[cfg(feature = "vcl")]
    tcp_next: std::sync::atomic::AtomicUsize,
    /// Kernel-sockets backend: a single reactor, no worker pool.
    #[cfg(not(feature = "vcl"))]
    reactor: ReactorCtx,
}


/// Default VPP binary-API socket path. Operators can override per
/// instance if their VPP is bound to a non-default socket; today
/// nothing else in dnsd needs to touch VPP, so we just hardcode.
#[cfg(feature = "vcl")]
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
///
/// VCL-only — the kernel-sockets backend lets the kernel FIB pick
/// the source automatically (or honours an explicit `source_v6:`
/// in config). Phase 4 may add a `getifaddrs`-based equivalent if
/// auto-discovery turns out to be wanted there too.
#[cfg(feature = "vcl")]
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
///
/// VCL-only — kernel-sockets backend doesn't have the VPP-TCP
/// session-lookup quirk and can rely on kernel routing.
#[cfg(feature = "vcl")]
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

#[cfg(feature = "vcl")]
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

#[cfg(feature = "vcl")]
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
    pub async fn new(
        #[cfg(not(feature = "vcl"))] reactor: ReactorCtx,
        timeout_ms: Option<u32>,
        source_v4: Option<std::net::Ipv4Addr>,
        source_v6: Option<std::net::Ipv6Addr>,
        #[cfg(feature = "vcl")] workers: Vec<(tokio::runtime::Handle, ReactorCtx)>,
    ) -> Result<Self> {
        let timeout = Duration::from_millis(
            timeout_ms.map(|t| t as u64).unwrap_or(DEFAULT_UPSTREAM_TIMEOUT_MS),
        );

        // Only warn under VCL — that backend NEEDS an explicit source
        // because of VPP's TCP/UDP session-lookup quirk. Kernel
        // backend lets the FIB pick automatically and v6 still works
        // when the host has v6 connectivity.
        #[cfg(feature = "vcl")]
        if source_v6.is_none() {
            tracing::warn!(
                "no source_v6 — IPv6 upstream queries will time out. Set \
                 `dns.recursion.source_v6` to a globally-routable v6 on a \
                 VPP interface (typically the wan v6) to enable them."
            );
        }

        // Async UDP upstream: one channel (socket pair + demux) per
        // vcl-io worker; queries round-robin across the pool so the
        // libvppcom send/recv load for concurrent recursive walks
        // spreads across every worker thread.
        let udp = Arc::new(
            AsyncUdpUpstream::new(
                source_v4,
                source_v6,
                #[cfg(feature = "vcl")]
                workers.clone(),
                #[cfg(not(feature = "vcl"))]
                reactor.clone(),
            )
            .await
            .context("AsyncUdpUpstream::new")?,
        );

        Ok(Self {
            udp,
            timeout,
            source_v4,
            source_v6,
            #[cfg(feature = "vcl")]
            workers,
            #[cfg(feature = "vcl")]
            tcp_next: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(not(feature = "vcl"))]
            reactor,
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
        let client_txid = orig_msg.metadata.id;
        let upstream_txid: u16 = rand::rng().random();

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
        let final_resp = if parsed.metadata.truncation {
            tracing::debug!(%peer, "TC=1 on UDP; retrying over TCP");
            let tcp_txid: u16 = rand::rng().random();
            let mut tcp_out = orig_query.to_vec();
            tcp_out[0..2].copy_from_slice(&tcp_txid.to_be_bytes());
            let tcp_mask = super::zeroxtwenty::encode(&mut tcp_out)
                .context("0x20 encode TCP retry")?;
            // DIAG: time the TCP fallback. DNSKEY responses are
            // large and almost always TC=1, so this path dominates
            // DNSSEC-validation latency. `ok` distinguishes a slow
            // success from a slow failure.
            let tcp_t0 = std::time::Instant::now();
            let r = self.query_one_tcp(peer, &tcp_out, tcp_txid, &tcp_mask).await;
            tracing::debug!(
                %peer,
                tcp_ms = tcp_t0.elapsed().as_millis() as u64,
                ok = r.is_ok(),
                "upstream-tcp: TC=1 fallback",
            );
            r?
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
        parsed.metadata.id = client_txid;
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
    /// configured as TCP-only upstreams. `query_tcp_dns_async` runs
    /// non-blocking VCL TCP + the reactor for connect/read/write —
    /// every step is a libvppcom session op, valid only on a
    /// registered VCL worker thread. Under `vcl`, dispatch onto a
    /// round-robin-picked vcl-io worker (with that worker's reactor);
    /// calling inline on the main multi_thread runtime returns
    /// VPPCOM_EINVAL (-22). Round-robin keeps a DNSKEY-fetch burst
    /// from all queueing behind one thread.
    pub async fn query_one_tcp(
        &self,
        peer: SocketAddr,
        query: &[u8],
        expected_txid: u16,
        expected_qname: &[u8],
    ) -> Result<Vec<u8>> {
        #[cfg(feature = "vcl")]
        let resp = {
            let i = self.tcp_next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                % self.workers.len();
            let (vcl_io, reactor) = self.workers[i].clone();
            let source = self.source_for(peer);
            let query_bytes = query.to_vec();
            let timeout = self.timeout;
            let (tx, rx) = oneshot::channel();
            vcl_io.spawn(async move {
                let r = transport::query_tcp_dns_async(
                    peer, source, &query_bytes, reactor, timeout,
                )
                .await;
                let _ = tx.send(r);
            });
            rx.await
                .map_err(|_| anyhow!("vcl-io TCP dispatch dropped"))?
                .with_context(|| format!("upstream TCP {peer}"))?
        };
        #[cfg(not(feature = "vcl"))]
        let resp = transport::query_tcp_dns_async(
            peer,
            self.source_for(peer),
            query,
            self.reactor.clone(),
            self.timeout,
        )
        .await
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
            servers: servers
                .iter()
                .map(|s| crate::config::ServerSpec::Bare(s.parse().unwrap()))
                .collect(),
        }
    }

    /// Extract just the addresses from a `lookup` result for
    /// assertions (phase 1 — every server is direct UDP).
    fn addrs(servers: &[ForwarderServer]) -> Vec<std::net::IpAddr> {
        servers.iter().map(|s| s.address).collect()
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
        assert_eq!(addrs(hit), vec!["10.42.113.4".parse::<std::net::IpAddr>().unwrap()]);

        let hit2 = f.lookup(&Name::from_ascii("www.jdt.io.").unwrap()).unwrap();
        assert_eq!(
            addrs(hit2),
            vec!["10.42.128.19".parse::<std::net::IpAddr>().unwrap()]
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
        assert_eq!(addrs(hit), vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()]);
    }
}
