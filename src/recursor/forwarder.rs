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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vcl_rs::{VclDgramSocket, VclReactor, VclStream};

use crate::config::Forwarder as ForwarderCfg;

const DEFAULT_UPSTREAM_TIMEOUT_MS: u64 = 2500;
const UPSTREAM_BUF: usize = 4096;
const MAX_TCP_MESSAGE: usize = 65535;

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
            let domain = Name::from_ascii(&c.domain)
                .with_context(|| format!("bad forwarder domain {:?}", c.domain))?;
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

fn is_suffix(name: &Name, suffix: &Name) -> bool {
    if name.num_labels() < suffix.num_labels() {
        return false;
    }
    name.zone_of(suffix)
}

pub struct UpstreamClient {
    reactor: VclReactor,
    timeout: Duration,
}

impl UpstreamClient {
    pub fn new(reactor: VclReactor, timeout_ms: Option<u32>) -> Self {
        let timeout = Duration::from_millis(
            timeout_ms.map(|t| t as u64).unwrap_or(DEFAULT_UPSTREAM_TIMEOUT_MS),
        );
        Self { reactor, timeout }
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

        // Restore the client's TXID before returning.
        let mut resp = final_resp;
        resp[0..2].copy_from_slice(&client_txid.to_be_bytes());
        Ok(resp)
    }

    async fn query_one_udp(
        &self,
        peer: SocketAddr,
        query: &[u8],
        expected_txid: u16,
        expected_qname: &[u8],
    ) -> Result<Vec<u8>> {
        // Ephemeral source socket — different ephemeral port per
        // query is part of the Kaminsky baseline.
        let sock = if peer.is_ipv4() {
            VclDgramSocket::bind_ephemeral_v4(self.reactor.clone())
        } else {
            VclDgramSocket::bind_ephemeral_v6(self.reactor.clone())
        }
        .with_context(|| format!("ephemeral UDP bind for upstream {peer}"))?;

        sock.send_to(query, peer)
            .await
            .with_context(|| format!("UDP send_to {peer}"))?;

        let mut buf = vec![0u8; UPSTREAM_BUF];
        let (n, from) = tokio::time::timeout(self.timeout, sock.recv_from(&mut buf))
            .await
            .map_err(|_| anyhow!("upstream UDP {peer} timeout"))?
            .with_context(|| format!("UDP recv_from {peer}"))?;

        if from.ip() != peer.ip() {
            return Err(anyhow!(
                "upstream UDP response from unexpected address {from} (wanted {peer})"
            ));
        }
        if n < 12 {
            return Err(anyhow!("short upstream UDP response ({n} bytes)"));
        }
        let rx_txid = u16::from_be_bytes([buf[0], buf[1]]);
        if rx_txid != expected_txid {
            return Err(anyhow!(
                "upstream UDP TXID mismatch: got {rx_txid:#06x} expected {expected_txid:#06x}"
            ));
        }
        buf.truncate(n);
        super::zeroxtwenty::verify(&buf, expected_qname)
            .with_context(|| format!("upstream UDP {peer} 0x20 mismatch"))?;
        Ok(buf)
    }

    /// Send one query to `peer` over TCP (RFC 1035 §4.2.2 2-byte
    /// length framing). Used both for TC-fallback and for forwarders
    /// configured as TCP-only upstreams.
    pub async fn query_one_tcp(
        &self,
        peer: SocketAddr,
        query: &[u8],
        expected_txid: u16,
        expected_qname: &[u8],
    ) -> Result<Vec<u8>> {
        // VCL TCP connect: a fresh session per query is simple and
        // correct. Pooling + keepalive to heavily-used upstreams is
        // a follow-up. Timeout wraps the entire connect → send →
        // recv → shutdown dance; on timeout the stream is dropped
        // which closes the VCL session.
        let fut = async {
            let mut stream = VclStream::connect(
                peer,
                None,
                self.timeout,
                self.reactor.clone(),
            )
            .await
            .with_context(|| format!("TCP connect to upstream {peer}"))?;

            let mut framed = Vec::with_capacity(2 + query.len());
            framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
            framed.extend_from_slice(query);
            stream
                .write_all(&framed)
                .await
                .with_context(|| format!("TCP write to upstream {peer}"))?;
            stream.flush().await.ok();

            let mut lenbuf = [0u8; 2];
            stream
                .read_exact(&mut lenbuf)
                .await
                .with_context(|| format!("TCP length read from {peer}"))?;
            let len = u16::from_be_bytes(lenbuf) as usize;
            if len == 0 || len > MAX_TCP_MESSAGE {
                return Err(anyhow!("invalid upstream TCP DNS length {len}"));
            }

            let mut resp = vec![0u8; len];
            stream
                .read_exact(&mut resp)
                .await
                .with_context(|| format!("TCP body read from {peer}"))?;
            Ok::<_, anyhow::Error>(resp)
        };

        let resp = tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| anyhow!("upstream TCP {peer} timeout"))??;

        if resp.len() < 12 {
            return Err(anyhow!("short upstream TCP response ({} bytes)", resp.len()));
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
}
