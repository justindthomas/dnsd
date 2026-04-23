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

/// Read-only view of state the control socket needs. Built once by
/// `main.rs` after the RecursorHandler is constructed.
#[derive(Clone)]
pub struct ControlState {
    pub metrics: Arc<Metrics>,
    pub cache: Arc<DnsCache>,
    pub forwarders: Arc<Forwarders>,
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
            let forwarders = state
                .forwarders
                .snapshot()
                .into_iter()
                .map(|(domain, servers)| ForwarderInfo {
                    domain,
                    servers: servers.iter().map(|s| s.to_string()).collect(),
                })
                .collect();
            ControlResponse::Forwarders { forwarders }
        }
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
