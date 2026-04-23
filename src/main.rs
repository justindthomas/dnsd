//! imp-dnsd entry point.
//!
//! Responsibilities:
//!   1. Acquire the instance lock (one daemon per control socket).
//!   2. Load `dns:` from router.yaml.
//!   3. Initialise VCL + reactor (needs VPP session layer up).
//!   4. Bind listeners declared in config (UDP/TCP/DoT/DoH).
//!   5. Bring up the control socket at /run/dnsd.sock.
//!   6. Wait for SIGTERM / SIGHUP; on SIGHUP, diff config + rebind.
//!
//! Task #7 fills in the listener bring-up against the vcl-rs
//! transports. For now we bring up the control socket so impd's
//! supervisor `Ready::Socket("/run/dnsd.sock")` gate lets dnsd move
//! from "starting" to "running" during test bring-up.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::{fmt, EnvFilter};

use dnsd::config::DnsConfig;
use dnsd::control::{ControlServer, DEFAULT_SOCKET};
use dnsd::metrics::Metrics;

#[derive(Parser, Debug)]
#[command(name = "imp-dnsd", about = "DNS caching resolver + forwarder for imp")]
struct Args {
    /// Path to router.yaml (the `dns:` block is read from here).
    #[arg(long, default_value = "/persistent/config/router.yaml")]
    config: PathBuf,

    /// Control socket path (`imp-dnsd-query` connects here).
    #[arg(long, default_value = DEFAULT_SOCKET)]
    control_socket: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();

    let cfg = DnsConfig::load(&args.config)
        .with_context(|| format!("loading dns config from {}", args.config.display()))?;
    tracing::info!(
        enabled = cfg.enabled,
        listeners = cfg.listeners.len(),
        forwarders = cfg.forwarders.len(),
        "dns config loaded"
    );

    if !cfg.enabled {
        tracing::warn!(
            "dns.enabled=false — staying idle; impd should not have started us"
        );
    }

    let metrics = Arc::new(Metrics::default());

    // Control socket first so impd's Ready::Socket gate unblocks.
    let control_path = args.control_socket.clone();
    let control = ControlServer::new(control_path.clone(), metrics.clone());
    tokio::spawn(async move {
        if let Err(e) = control.serve().await {
            tracing::error!("control server exited: {e}");
        }
    });

    // Signal handlers: SIGTERM → graceful exit, SIGHUP → reload.
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sighup = signal(SignalKind::hangup())?;

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM — shutting down");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("SIGINT — shutting down");
                break;
            }
            _ = sighup.recv() => {
                match DnsConfig::load(&args.config) {
                    Ok(new_cfg) => {
                        tracing::info!(
                            listeners = new_cfg.listeners.len(),
                            forwarders = new_cfg.forwarders.len(),
                            "SIGHUP — config reloaded"
                        );
                        // Diff + rebind hook lands with task #7.
                        let _ = new_cfg;
                    }
                    Err(e) => tracing::error!("SIGHUP reload failed: {e}"),
                }
            }
        }
    }

    // Best-effort control socket cleanup on exit so the supervisor
    // doesn't see a stale file.
    let _ = std::fs::remove_file(&args.control_socket);
    Ok(())
}
