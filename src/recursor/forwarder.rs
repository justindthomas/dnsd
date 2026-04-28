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
use vcl_rs::{VclDgramSocket, VclReactor};

use crate::config::Forwarder as ForwarderCfg;

const DEFAULT_UPSTREAM_TIMEOUT_MS: u64 = 2500;
const MAX_TCP_MESSAGE: usize = 65535;

// Both UDP and TCP upstream paths run async on the main Tokio
// thread — no worker pool, no spawn_blocking. The thread is VCL
// worker-0 (registered by VclApp::init), which satisfies VCL's
// invariant that session ops happen on the worker that owns the
// context. UDP multiplexes across persistent VclDgramSockets
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

        // No worker pool any more — both UDP and TCP upstream paths
        // run async on the main Tokio thread (which is VCL worker-0,
        // already registered). UDP via the multiplexer above; TCP
        // via `vcl_rs::query_tcp_dns_async` using non-blocking VCL
        // sessions + the reactor for connect/read/write completion.
        Ok(Self {
            udp,
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
    /// configured as TCP-only upstreams. Runs on the calling Tokio
    /// task — async all the way down via `query_tcp_dns_async`,
    /// which uses non-blocking VCL TCP + the reactor for connect/
    /// read/write. No worker pool, no `spawn_blocking`.
    pub async fn query_one_tcp(
        &self,
        peer: SocketAddr,
        query: &[u8],
        expected_txid: u16,
        expected_qname: &[u8],
    ) -> Result<Vec<u8>> {
        let resp = vcl_rs::query_tcp_dns_async(
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
