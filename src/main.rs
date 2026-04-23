//! imp-dnsd entry point.
//!
//! Responsibilities:
//!   1. Load `dns:` from router.yaml.
//!   2. Initialise VCL + reactor (needs VPP session layer up).
//!   3. Bring up the control socket at /run/dnsd.sock.
//!   4. Bind listeners declared in config (UDP/TCP, later DoT/DoH).
//!   5. Wait for SIGTERM / SIGHUP; SIGHUP re-reads config (listener
//!      rebind follow-up; for now a reload is logged + cached).
//!
//! The handler is currently a REFUSED stub. Task #8 swaps in the real
//! recursor + forwarder + cache.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tracing_subscriber::{fmt, EnvFilter};

use dnsd::config::DnsConfig;
use dnsd::control::{ControlServer, DEFAULT_SOCKET};
use dnsd::handler::SharedHandler;
use dnsd::io::{tcp::TcpListener, udp::UdpListener};
use dnsd::metrics::Metrics;
use dnsd::recursor::RecursorHandler;
use vcl_rs::{VclApp, VclReactor};

#[derive(Parser, Debug)]
#[command(name = "imp-dnsd", about = "DNS caching resolver + forwarder for imp")]
struct Args {
    /// Path to router.yaml.
    #[arg(long, default_value = "/persistent/config/router.yaml")]
    config: PathBuf,

    /// Control socket path.
    #[arg(long, default_value = DEFAULT_SOCKET)]
    control_socket: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
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

    let metrics = Arc::new(Metrics::default());

    // Control socket first so the impd supervisor's Ready::Socket gate
    // unblocks; we don't want the whole startup to stall behind VCL
    // init if something is wrong with VPP.
    let control_path = args.control_socket.clone();
    let control = ControlServer::new(control_path.clone(), metrics.clone());
    tokio::spawn(async move {
        if let Err(e) = control.serve().await {
            tracing::error!("control server exited: {e}");
        }
    });

    if !cfg.enabled {
        tracing::warn!("dns.enabled=false — serving control socket only");
        wait_for_exit(&args.control_socket).await;
        return Ok(());
    }

    // VCL init + reactor come up once, shared across every listener.
    let _vcl_app =
        VclApp::init("imp-dnsd").with_context(|| "VclApp::init — is VPP up and vcl.conf readable?")?;
    let reactor = VclReactor::new().with_context(|| "VclReactor::new")?;

    // Forwarder + cache. Iterative recursion against the root is a
    // follow-up; until then queries with no matching forwarder
    // return SERVFAIL.
    let handler: SharedHandler = Arc::new(
        RecursorHandler::from_config(&cfg, reactor.clone(), metrics.clone())
            .context("RecursorHandler init")?,
    );

    let mut listener_tasks = Vec::new();
    for listener_cfg in &cfg.listeners {
        let name = listener_cfg.name.clone();
        if listener_cfg.has_protocol("udp") {
            match UdpListener::spawn(
                listener_cfg.clone(),
                reactor.clone(),
                handler.clone(),
                metrics.clone(),
            )
            .await
            {
                Ok(h) => listener_tasks.push(h),
                Err(e) => tracing::error!(listener = %name, "UDP bind failed: {e}"),
            }
        }
        if listener_cfg.has_protocol("tcp") {
            match TcpListener::spawn(
                listener_cfg.clone(),
                reactor.clone(),
                handler.clone(),
                metrics.clone(),
            )
            .await
            {
                Ok(h) => listener_tasks.push(h),
                Err(e) => tracing::error!(listener = %name, "TCP bind failed: {e}"),
            }
        }
        // DoT / DoH listeners land with task #10; noted-but-not-bound
        // so operator config doesn't silently get ignored.
        if listener_cfg.has_protocol("dot") {
            tracing::warn!(listener = %name, "DoT requested but not yet implemented");
        }
        if listener_cfg.has_protocol("doh") {
            tracing::warn!(listener = %name, "DoH requested but not yet implemented");
        }
    }

    if listener_tasks.is_empty() {
        tracing::warn!(
            "dns.enabled=true but no listeners came up — check listener config"
        );
    } else {
        tracing::info!(n = listener_tasks.len(), "listeners bound");
    }

    wait_for_exit(&args.control_socket).await;
    Ok(())
}

async fn wait_for_exit(control_socket: &std::path::Path) {
    let mut sigterm = signal(SignalKind::terminate()).expect("sigterm");
    let mut sigint = signal(SignalKind::interrupt()).expect("sigint");
    let mut sighup = signal(SignalKind::hangup()).expect("sighup");

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
                // Full rebind-on-change lands when listener lifecycle
                // gains a drop-and-rebind path. For now: re-parse YAML
                // so typos surface in the log.
                tracing::info!("SIGHUP — reload noted (rebind is follow-up)");
            }
        }
    }

    let _ = std::fs::remove_file(control_socket);
}
