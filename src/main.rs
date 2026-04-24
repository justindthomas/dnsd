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

use dnsd::acme;
use dnsd::config::DnsConfig;
use dnsd::control::{ControlServer, ControlState, DEFAULT_SOCKET};
use dnsd::handler::SharedHandler;
use dnsd::io::{doh::DohListener, dot::DotListener, tcp::TcpListener, udp::UdpListener};
use dnsd::metrics::Metrics;
use dnsd::recursor::RecursorHandler;
use vcl_rs::{register_worker_thread, VclApp, VclReactor};

#[derive(Parser, Debug)]
#[command(name = "imp-dnsd", about = "DNS caching resolver + forwarder for imp")]
struct Args {
    /// Path to router.yaml.
    #[arg(long, default_value = "/persistent/config/router.yaml")]
    config: PathBuf,

    /// Directory for persistent daemon state (root-hints cache,
    /// ACME certs once that lands, etc.). Created on first boot if
    /// missing. Kept separate from `--config` because on imp this
    /// lives under `/persistent/data` while config lives under
    /// `/persistent/config`.
    #[arg(long, default_value = "/persistent/data/dnsd")]
    data_dir: PathBuf,

    /// Control socket path.
    #[arg(long, default_value = DEFAULT_SOCKET)]
    control_socket: PathBuf,
}

fn main() -> Result<()> {
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

    if !cfg.enabled {
        // No VCL init needed — a basic runtime is enough for the
        // control socket; impd can still query stats.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building tokio runtime (disabled mode)")?;
        return rt.block_on(run_control_only(args, cfg));
    }

    // VCL init MUST happen before the tokio runtime is built: the
    // multi-threaded runtime eagerly spins up worker threads, and each
    // worker's `on_thread_start` needs to call `vppcom_worker_register`
    // which itself requires `vppcom_app_create` (i.e. VclApp::init) to
    // have run. Registering a worker before app-create SEGVs libvppcom.
    let vcl_app = VclApp::init("imp-dnsd")
        .with_context(|| "VclApp::init — is VPP up and vcl.conf readable?")?;

    // VCL has a worker-per-thread model: every session is owned by the
    // thread that created it, and cross-thread operations on that
    // session return VPPCOM_EBADFD (-77). Tokio's default multi-thread
    // runtime work-steals tasks between workers, which breaks that
    // invariant. For the v1 standalone path we use a single-threaded
    // runtime so the main thread (already registered as VCL worker-0
    // by VclApp::init) owns every listener and every spawned task.
    //
    // `spawn_blocking` tasks still land on a pool thread; those re-
    // register via `on_thread_start`. But no VCL session ever crosses
    // the boundary — the blocking pool is only used for CPU work and
    // synchronous file I/O, not for VCL session access.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .on_thread_start(register_worker_thread)
        .build()
        .context("building tokio runtime")?;
    runtime.block_on(async_main(args, cfg, vcl_app))
}

async fn run_control_only(args: Args, cfg: DnsConfig) -> Result<()> {
    tracing::warn!("dns.enabled=false — serving control socket only");
    let metrics = Arc::new(Metrics::default());
    let cache = RecursorHandler::build_cache_from_config(&cfg);
    let forwarders =
        RecursorHandler::build_forwarders_from_config(&cfg).context("forwarder config")?;
    let state = ControlState {
        metrics,
        cache,
        forwarders,
    };
    let control = ControlServer::new(args.control_socket.clone(), state);
    tokio::spawn(async move {
        if let Err(e) = control.serve().await {
            tracing::error!("control server exited: {e}");
        }
    });
    wait_for_exit(&args.control_socket).await;
    Ok(())
}

async fn async_main(args: Args, cfg: DnsConfig, _vcl_app: VclApp) -> Result<()> {
    let metrics = Arc::new(Metrics::default());

    // Ensure the persistent data dir exists — the iterative recursor
    // writes root-hints here after priming, and future ACME state
    // will live here too.
    if let Err(e) = std::fs::create_dir_all(&args.data_dir) {
        tracing::warn!(
            dir = %args.data_dir.display(),
            "could not create data dir: {e} (persistence features disabled)"
        );
    }
    let root_hints_path = args.data_dir.join("root-hints");

    // Build cache + forwarders up front. Neither needs VCL/VPP, and
    // sharing them with both the RecursorHandler and the control
    // socket means `imp-dnsd-query cache dump` sees live state from
    // the same instance the handler is populating.
    let cache = RecursorHandler::build_cache_from_config(&cfg);
    let forwarders =
        RecursorHandler::build_forwarders_from_config(&cfg).context("forwarder config")?;

    // Control socket first so the impd supervisor's Ready::Socket gate
    // unblocks; we don't want the whole startup to stall behind VCL
    // init if something is wrong with VPP.
    let control_path = args.control_socket.clone();
    let state = ControlState {
        metrics: metrics.clone(),
        cache: cache.clone(),
        forwarders: forwarders.clone(),
    };
    let control = ControlServer::new(control_path.clone(), state);
    tokio::spawn(async move {
        if let Err(e) = control.serve().await {
            tracing::error!("control server exited: {e}");
        }
    });

    let reactor = VclReactor::new().with_context(|| "VclReactor::new")?;

    // Forwarder + cache. Iterative recursion against the root is a
    // follow-up; until then queries with no matching forwarder
    // return SERVFAIL.
    let handler: SharedHandler = Arc::new(
        RecursorHandler::from_parts(
            &cfg,
            reactor.clone(),
            metrics.clone(),
            cache.clone(),
            forwarders.clone(),
            Some(root_hints_path),
        )
        .context("RecursorHandler init")?,
    );

    // TLS config is shared between DoT and DoH. None means
    // cert_source is 'acme' (not yet wired) or no TLS listeners.
    let tls_config = acme::server_config_from_dns(&cfg).context("loading TLS config")?;

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
        if listener_cfg.has_protocol("dot") {
            match tls_config.as_ref() {
                Some(tls) => match DotListener::spawn(
                    listener_cfg.clone(),
                    reactor.clone(),
                    handler.clone(),
                    metrics.clone(),
                    tls.clone(),
                )
                .await
                {
                    Ok(h) => listener_tasks.push(h),
                    Err(e) => tracing::error!(listener = %name, "DoT bind failed: {e}"),
                },
                None => tracing::warn!(listener = %name, "DoT requested but no TLS config available"),
            }
        }
        if listener_cfg.has_protocol("doh") {
            match tls_config.as_ref() {
                Some(tls) => match DohListener::spawn(
                    listener_cfg.clone(),
                    reactor.clone(),
                    handler.clone(),
                    metrics.clone(),
                    tls.clone(),
                )
                .await
                {
                    Ok(h) => listener_tasks.push(h),
                    Err(e) => tracing::error!(listener = %name, "DoH bind failed: {e}"),
                },
                None => tracing::warn!(listener = %name, "DoH requested but no TLS config available"),
            }
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
