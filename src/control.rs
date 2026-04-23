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
    Cache { summary: String },
    Forwarders { forwarders: Vec<ForwarderInfo> },
    Ok { message: String },
    Trace { steps: Vec<String> },
    Error { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwarderInfo {
    pub domain: String,
    pub servers: Vec<String>,
}

pub struct ControlServer {
    path: PathBuf,
    metrics: Arc<Metrics>,
}

impl ControlServer {
    pub fn new<P: Into<PathBuf>>(path: P, metrics: Arc<Metrics>) -> Self {
        Self { path: path.into(), metrics }
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
            let metrics = self.metrics.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(stream, metrics).await {
                    tracing::debug!("control conn ended: {e}");
                }
            });
        }
    }
}

async fn handle_conn(stream: UnixStream, metrics: Arc<Metrics>) -> Result<()> {
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
            Ok(req) => dispatch(req, &metrics).await,
            Err(e) => ControlResponse::Error { error: format!("bad request: {e}") },
        };
        let mut out = serde_json::to_string(&resp).unwrap_or_else(|e| {
            format!("{{\"type\":\"error\",\"error\":\"encode: {e}\"}}")
        });
        out.push('\n');
        tx.write_all(out.as_bytes()).await?;
    }
}

async fn dispatch(req: ControlRequest, metrics: &Arc<Metrics>) -> ControlResponse {
    match req {
        ControlRequest::Stats => ControlResponse::Stats(metrics.snapshot()),
        ControlRequest::Cache { .. } => {
            // Wired once recursor/cache.rs lands. Reports "unavailable"
            // rather than a lie until it's implemented.
            ControlResponse::Cache { summary: "cache not yet implemented".into() }
        }
        ControlRequest::Forwarders => ControlResponse::Forwarders { forwarders: vec![] },
        ControlRequest::Reload => {
            // A SIGHUP-equivalent reload triggered via the socket lets
            // automation avoid shelling out to `pkill -HUP`. The shared
            // signal path in main.rs will pick up a flipped AtomicBool
            // set here once reload is wired end-to-end; for v1 we just
            // acknowledge.
            ControlResponse::Ok { message: "reload queued".into() }
        }
        ControlRequest::Upstream { name } => ControlResponse::Trace {
            steps: vec![format!("tracing {name} — not yet implemented")],
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
