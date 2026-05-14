//! Unix-socket operator query protocol.
//!
//! Line-delimited JSON over a Unix stream socket at `/run/dnsd.sock`,
//! matching the shape of `/run/bgpd.sock` / `/run/ospfd.sock` /
//! `/run/dhcpd.sock`. Each request is a single JSON object on one
//! line; the response is a single JSON object on one line.
//!
//! Commands:
//!
//! - `{"command":"stats"}` — counter snapshot.
//! - `{"command":"cache","op":"stats"|"flush"|"dump",
//!    "name":"foo.com","rrtype":"A"}` — cache inspection + flush.
//! - `{"command":"forwarders"}` — configured forwarders + live RTT
//!   (RTT populated once recursor health checks land).
//! - `{"command":"listeners"}` — currently-bound listeners (post
//!   reload diff). One row per (address, port, proto).
//! - `{"command":"tls"}` — effective TLS materials in use by DoT /
//!   DoH listeners: cert source, subject, issuer, not_after.
//! - `{"command":"reload"}` — SIGHUP-equivalent reconfigure.
//! - `{"command":"upstream","name":"..."}` — resolution trace.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::metrics::{Metrics, MetricsSnapshot};
use crate::recursor::cache::CacheDumpEntry;
use crate::recursor::{DnsCache, Forwarders};

pub const DEFAULT_SOCKET: &str = "/run/dnsd.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ControlRequest {
    Stats,
    Cache {
        #[serde(default)]
        op: Option<String>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        rrtype: Option<String>,
    },
    Forwarders,
    Listeners,
    Tls,
    Reload,
    Upstream { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResponse {
    Stats(MetricsSnapshot),
    CacheStats {
        entries: u64,
    },
    CacheDump {
        entries: Vec<CacheDumpEntry>,
    },
    Forwarders {
        forwarders: Vec<ForwarderInfo>,
    },
    Listeners {
        listeners: Vec<ListenerInfo>,
    },
    Tls(TlsInfo),
    Ok {
        message: String,
    },
    Trace {
        steps: Vec<String>,
    },
    Error {
        error: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwarderInfo {
    pub domain: String,
    pub servers: Vec<String>,
}

/// One row in the `listeners` response — the live bind set after any
/// SIGHUP-driven diff. Mirrors what the operator put in router.yaml
/// but reflects what actually came up (e.g. a DoT listener listed in
/// config but skipped because no TLS materials are loaded won't
/// appear).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerInfo {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub protocol: String,
    /// CIDRs from `allow_from`. Empty means the listener accepts
    /// from any peer.
    pub allow_from: Vec<String>,
    pub dns64: bool,
}

/// Snapshot of the TLS materials in effect for DoT/DoH. `present` is
/// false when no `dns.tls:` block is configured (DoT/DoH listeners
/// won't bind).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsInfo {
    pub present: bool,
    /// `"file"` | `"acme"` (matches `dns.tls.cert_source`). Empty
    /// string when `present == false`.
    pub cert_source: String,
    /// X.509 Subject DN of the leaf cert, if loaded.
    pub subject: Option<String>,
    /// X.509 Issuer DN of the leaf cert.
    pub issuer: Option<String>,
    /// `notAfter` rendered as RFC 3339. Operators consume this to
    /// notice an expiring cert before clients start failing.
    pub not_after: Option<String>,
    /// SubjectAltName DNS / IP entries from the leaf cert, if any.
    pub sans: Vec<String>,
    /// ALPN list advertised on the handshake (e.g. `dot`, `h2`,
    /// `http/1.1`).
    pub alpn: Vec<String>,
}

/// Read-only view of state the control socket needs. Built once by
/// `main.rs`. The forwarders pointer is wrapped in `ArcSwap` so a
/// SIGHUP-triggered reload can publish a fresh forwarder table
/// without coordinating with the control server thread — every
/// `dnsd-query forwarders` snapshot reads the current Arc.
#[derive(Clone)]
pub struct ControlState {
    pub metrics: Arc<Metrics>,
    pub cache: Arc<DnsCache>,
    pub forwarders: Arc<arc_swap::ArcSwap<Forwarders>>,
    /// Listener bind snapshot. Same hot-swap pattern as `forwarders`:
    /// main.rs publishes a fresh `Vec<ListenerInfo>` after the
    /// initial bind and after every SIGHUP-driven diff. Empty until
    /// the first publish (control socket starts before listeners).
    pub listeners: Arc<arc_swap::ArcSwap<Vec<ListenerInfo>>>,
    /// Live TLS materials. `TlsInfo { present: false, .. }` when no
    /// `dns.tls:` is configured. Updated on reload so an operator
    /// rotating certs sees the new subject/expiry without a daemon
    /// restart.
    pub tls: Arc<arc_swap::ArcSwap<TlsInfo>>,
}

pub struct ControlServer {
    path: PathBuf,
    state: ControlState,
}

impl ControlServer {
    pub fn new<P: Into<PathBuf>>(path: P, state: ControlState) -> Self {
        Self {
            path: path.into(),
            state,
        }
    }

    pub async fn serve(self) -> Result<()> {
        let _ = std::fs::remove_file(&self.path);
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let listener = UnixListener::bind(&self.path)?;
        tracing::info!(socket = %self.path.display(), "control socket bound");
        loop {
            let (stream, _) = listener.accept().await?;
            let state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(stream, state).await {
                    tracing::debug!("control conn ended: {e}");
                }
            });
        }
    }
}

async fn handle_conn(stream: UnixStream, state: ControlState) -> Result<()> {
    let (rx, mut tx) = stream.into_split();
    let mut rx = BufReader::new(rx);
    let mut line = String::new();
    loop {
        line.clear();
        let n = rx.read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<ControlRequest>(trimmed) {
            Ok(req) => dispatch(req, &state).await,
            Err(e) => ControlResponse::Error {
                error: format!("bad request: {e}"),
            },
        };
        let mut out = serde_json::to_string(&resp).unwrap_or_else(|e| {
            format!("{{\"type\":\"error\",\"error\":\"encode: {e}\"}}")
        });
        out.push('\n');
        tx.write_all(out.as_bytes()).await?;
    }
}

async fn dispatch(req: ControlRequest, state: &ControlState) -> ControlResponse {
    match req {
        ControlRequest::Stats => ControlResponse::Stats(state.metrics.snapshot()),
        ControlRequest::Cache { op, name, rrtype } => {
            let op = op.as_deref().unwrap_or("stats");
            match op {
                "stats" => ControlResponse::CacheStats {
                    entries: state.cache.entry_count(),
                },
                "flush" => {
                    state.cache.flush();
                    ControlResponse::Ok {
                        message: "cache flushed".into(),
                    }
                }
                "dump" => {
                    let mut entries = state.cache.dump();
                    // Allow name/rrtype filters for large caches.
                    if let Some(n) = name {
                        let n = n.to_lowercase();
                        entries.retain(|e| e.name.to_lowercase().contains(&n));
                    }
                    if let Some(t) = rrtype {
                        let t = t.to_uppercase();
                        entries.retain(|e| e.rtype.eq_ignore_ascii_case(&t));
                    }
                    ControlResponse::CacheDump { entries }
                }
                other => ControlResponse::Error {
                    error: format!("unknown cache op {other:?} (want stats|flush|dump)"),
                },
            }
        }
        ControlRequest::Forwarders => {
            // Snapshot the live forwarder table — reload swaps the
            // inner Arc on SIGHUP, so we read each call fresh.
            let forwarders = state
                .forwarders
                .load()
                .snapshot()
                .into_iter()
                .map(|(domain, servers)| ForwarderInfo {
                    domain,
                    servers: servers.iter().map(|s| s.to_string()).collect(),
                })
                .collect();
            ControlResponse::Forwarders { forwarders }
        }
        ControlRequest::Listeners => ControlResponse::Listeners {
            listeners: state.listeners.load_full().as_ref().clone(),
        },
        ControlRequest::Tls => ControlResponse::Tls(state.tls.load_full().as_ref().clone()),
        ControlRequest::Reload => {
            // SIGHUP self — main.rs's signal loop picks it up the
            // same way as an external `pkill -HUP`. Keeps the reload
            // path single-sourced.
            let rc = unsafe { libc::kill(std::process::id() as i32, libc::SIGHUP) };
            if rc == 0 {
                ControlResponse::Ok {
                    message: "reload signal sent (SIGHUP to self)".into(),
                }
            } else {
                ControlResponse::Error {
                    error: format!("kill(SIGHUP) failed: rc={rc}"),
                }
            }
        }
        ControlRequest::Upstream { name } => ControlResponse::Trace {
            steps: vec![format!(
                "per-query resolution tracing for {name:?} is a follow-up — \
                 it requires instrumenting the forwarder/recursor path to \
                 capture timings + server choices without affecting the hot \
                 path"
            )],
        },
    }
}

/// Thin client used by the `imp-dnsd-query` binary.
pub async fn send_request(socket: &Path, req: &ControlRequest) -> Result<ControlResponse> {
    let stream = UnixStream::connect(socket).await?;
    let (rx, mut tx) = stream.into_split();
    let mut payload = serde_json::to_string(req)?;
    payload.push('\n');
    tx.write_all(payload.as_bytes()).await?;
    tx.shutdown().await.ok();
    let mut rx = BufReader::new(rx);
    let mut line = String::new();
    rx.read_line(&mut line).await?;
    Ok(serde_json::from_str(line.trim())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listeners_request_round_trips() {
        // The new {"command":"listeners"} shape must serde
        // cleanly — clients (imp-dnsd-query, impd's
        // query_imp_dnsd) build this by hand.
        let req: ControlRequest =
            serde_json::from_str(r#"{"command":"listeners"}"#).unwrap();
        assert!(matches!(req, ControlRequest::Listeners));
        assert_eq!(
            serde_json::to_string(&ControlRequest::Listeners).unwrap(),
            r#"{"command":"listeners"}"#
        );
    }

    #[test]
    fn tls_request_round_trips() {
        let req: ControlRequest =
            serde_json::from_str(r#"{"command":"tls"}"#).unwrap();
        assert!(matches!(req, ControlRequest::Tls));
        assert_eq!(
            serde_json::to_string(&ControlRequest::Tls).unwrap(),
            r#"{"command":"tls"}"#
        );
    }

    #[test]
    fn listeners_response_shape() {
        let info = ListenerInfo {
            name: "lan".into(),
            address: "192.0.2.1".into(),
            port: 853,
            protocol: "dot".into(),
            allow_from: vec!["192.0.2.0/24".into()],
            dns64: false,
        };
        let resp = ControlResponse::Listeners {
            listeners: vec![info],
        };
        let j = serde_json::to_value(&resp).unwrap();
        assert_eq!(j["type"], "listeners");
        assert_eq!(j["listeners"][0]["protocol"], "dot");
        assert_eq!(j["listeners"][0]["port"], 853);
    }

    #[test]
    fn tls_info_default_is_absent() {
        let resp = ControlResponse::Tls(TlsInfo::default());
        let j = serde_json::to_value(&resp).unwrap();
        assert_eq!(j["type"], "tls");
        assert_eq!(j["present"], false);
        assert_eq!(j["cert_source"], "");
    }
}
