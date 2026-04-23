//! Per-domain forwarder routing + upstream UDP client.
//!
//! Longest-suffix match on the question name picks the forwarder;
//! servers within a forwarder are tried in the configured order with
//! a per-attempt timeout. Upstream queries source from a fresh
//! ephemeral VclDgramSocket so each gets an independent source port
//! (simple source-port randomisation — enough for a v1 baseline
//! against Kaminsky-class poisoning).
//!
//! TXID randomisation is handled via `rand`; 0x20 case randomisation
//! is a follow-up (the plumbing is compatible — we'd apply it on the
//! question name before send + verify on recv).

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hickory_proto::op::Message;
use hickory_proto::rr::Name;
use hickory_proto::serialize::binary::BinDecodable;
use rand::Rng;
use vcl_rs::{VclDgramSocket, VclReactor};

use crate::config::Forwarder as ForwarderCfg;

const DEFAULT_UPSTREAM_TIMEOUT_MS: u64 = 2500;
const UPSTREAM_BUF: usize = 4096;

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
        // Bind an ephemeral source socket of the right address family.
        let sock = if peer.is_ipv4() {
            VclDgramSocket::bind_ephemeral_v4(self.reactor.clone())
        } else {
            VclDgramSocket::bind_ephemeral_v6(self.reactor.clone())
        }
        .with_context(|| format!("ephemeral bind for upstream {peer}"))?;

        // Rewrite TXID with a fresh random one for the upstream hop.
        // We'll restore the client's TXID on the response before
        // returning to the handler.
        let orig_msg = Message::from_bytes(orig_query).context("parse client query")?;
        let client_txid = orig_msg.id();

        let upstream_txid: u16 = rand::thread_rng().gen();
        let mut out = orig_query.to_vec();
        out[0..2].copy_from_slice(&upstream_txid.to_be_bytes());

        // Send + await one datagram with a global timeout.
        sock.send_to(&out, peer)
            .await
            .with_context(|| format!("send_to {peer}"))?;

        let mut buf = vec![0u8; UPSTREAM_BUF];
        let (n, from) = tokio::time::timeout(self.timeout, sock.recv_from(&mut buf))
            .await
            .map_err(|_| anyhow!("upstream {peer} timeout"))?
            .with_context(|| format!("recv_from {peer}"))?;

        // Reject spoofed responses that didn't come from the server
        // we queried (rudimentary; production 0x20 / cookies add
        // more layers).
        if from.ip() != peer.ip() {
            return Err(anyhow!(
                "upstream response from unexpected address {from} (wanted {peer})"
            ));
        }

        if n < 12 {
            return Err(anyhow!("short upstream response ({n} bytes)"));
        }
        // TXID check
        let rx_txid = u16::from_be_bytes([buf[0], buf[1]]);
        if rx_txid != upstream_txid {
            return Err(anyhow!(
                "upstream TXID mismatch: got {rx_txid:#06x} expected {upstream_txid:#06x}"
            ));
        }
        buf.truncate(n);
        // Restore the client's TXID.
        buf[0..2].copy_from_slice(&client_txid.to_be_bytes());
        Ok(buf)
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
