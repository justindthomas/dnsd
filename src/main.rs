//! dnsd entry point.
//!
//! Responsibilities:
//!   1. Load `dns:` from router.yaml.
//!   2. Initialise VCL + reactor (needs VPP session layer up).
//!   3. Bring up the control socket at /run/dnsd.sock.
//!   4. Bind listeners declared in config (UDP/TCP/DoT/DoH).
//!   5. Wait for SIGTERM / SIGHUP. SIGTERM = clean shutdown.
//!      SIGHUP = re-read config + atomically swap the recursor
//!      handler + diff listeners (abort removed, spawn added,
//!      keep unchanged) without dropping the cache.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinHandle;
use tracing_subscriber::{fmt, EnvFilter};

use dnsd::acme;
use dnsd::config::{DnsConfig, Listener as ListenerCfg};
use dnsd::control::{ControlServer, ControlState, DEFAULT_SOCKET};
use dnsd::handler::{LiveHandler, SharedHandler};
use dnsd::io::{doh::DohListener, dot::DotListener, tcp::TcpListener, udp::UdpListener};
use dnsd::metrics::Metrics;
use dnsd::recursor::{DnsCache, Forwarders, RecursorHandler};
use vcl_rs::{register_worker_thread, VclApp, VclReactor};

/// Identity of a single bound listener — what the diff-on-reload
/// path uses to decide "same listener, leave alone" vs "addr/port/
/// proto changed, abort + spawn fresh".
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ListenerKey {
    addr: IpAddr,
    port: u16,
    proto: &'static str, // "udp" | "tcp" | "dot" | "doh"
}

struct LiveListener {
    name: String,
    handle: JoinHandle<()>,
}

type LiveListeners = HashMap<ListenerKey, LiveListener>;

#[derive(Parser, Debug)]
#[command(name = "dnsd", about = "DNS caching resolver + forwarder")]
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
    let vcl_app = VclApp::init("dnsd")
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
        forwarders: Arc::new(arc_swap::ArcSwap::new(forwarders)),
    };
    let control = ControlServer::new(args.control_socket.clone(), state);
    tokio::spawn(async move {
        if let Err(e) = control.serve().await {
            tracing::error!("control server exited: {e}");
        }
    });
    // No listeners in disabled mode — just wait for shutdown.
    let mut sigterm = signal(SignalKind::terminate()).expect("sigterm");
    let mut sigint = signal(SignalKind::interrupt()).expect("sigint");
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("SIGTERM — shutting down"),
        _ = sigint.recv() => tracing::info!("SIGINT — shutting down"),
    }
    let _ = std::fs::remove_file(&args.control_socket);
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
    // socket means `dnsd-query cache dump` sees live state from
    // the same instance the handler is populating.
    let cache = RecursorHandler::build_cache_from_config(&cfg);
    let forwarders_initial =
        RecursorHandler::build_forwarders_from_config(&cfg).context("forwarder config")?;
    // Wrap the forwarder pointer in ArcSwap so SIGHUP-triggered
    // reload can swap a fresh Forwarders table without coordinating
    // with the control server thread. The control socket reads it
    // every `forwarders` query; the recursor handler holds its own
    // snapshot at construction (rebuilt on reload).
    let forwarders_swap: Arc<arc_swap::ArcSwap<Forwarders>> =
        Arc::new(arc_swap::ArcSwap::new(forwarders_initial.clone()));

    // Control socket first so the impd supervisor's Ready::Socket gate
    // unblocks; we don't want the whole startup to stall behind VCL
    // init if something is wrong with VPP.
    let control_path = args.control_socket.clone();
    let state = ControlState {
        metrics: metrics.clone(),
        cache: cache.clone(),
        forwarders: forwarders_swap.clone(),
    };
    let control = ControlServer::new(control_path.clone(), state);
    tokio::spawn(async move {
        if let Err(e) = control.serve().await {
            tracing::error!("control server exited: {e}");
        }
    });

    let reactor = VclReactor::new().with_context(|| "VclReactor::new")?;

    // Build the initial recursor and wrap it for hot-swap on SIGHUP.
    // Listener tasks hold the LiveHandler — they keep working across
    // reloads because LiveHandler dispatches through an ArcSwap that
    // we update with a fresh RecursorHandler.
    let initial_recursor = RecursorHandler::from_parts(
        &cfg,
        reactor.clone(),
        metrics.clone(),
        cache.clone(),
        forwarders_initial,
        Some(root_hints_path.clone()),
    )
    .context("RecursorHandler init")?;
    let live: Arc<LiveHandler<RecursorHandler>> = Arc::new(LiveHandler::new(initial_recursor));
    let handler: SharedHandler = live.clone();

    // TLS config is shared between DoT and DoH. None means
    // cert_source is 'acme' (not yet wired) or no TLS listeners.
    let tls_config = acme::server_config_from_dns(&cfg).context("loading TLS config")?;

    let mut listeners: LiveListeners = HashMap::new();
    bind_listener_set_with_retry(
        &cfg,
        &reactor,
        &handler,
        &metrics,
        tls_config.as_ref(),
        &mut listeners,
        Duration::from_secs(20), // initial bind: VPP may still be settling
    )
    .await;

    if listeners.is_empty() {
        tracing::warn!(
            "dns.enabled=true but no listeners came up — check VPP / FIB state"
        );
    } else {
        tracing::info!(n = listeners.len(), "listeners bound");
    }

    wait_for_exit_with_reload(
        WaitArgs {
            control_socket: args.control_socket.clone(),
            config_path: args.config.clone(),
            root_hints_path,
            reactor,
            metrics: metrics.clone(),
            cache,
            live,
            tls_config,
            forwarders_swap,
        },
        listeners,
    )
    .await;
    Ok(())
}

// ---- listener-spawn helpers ------------------------------------

/// Attempts to bind a single (listener, protocol) pair once.
/// Returns:
/// * `Ok(Some(handle))` — bound, listener task spawned.
/// * `Ok(None)` — permanently skipped (DoT/DoH without TLS, or
///   unknown protocol).
/// * `Err(_)` — transient bind failure; caller should retry.
async fn try_bind_one(
    lc: &ListenerCfg,
    proto: &'static str,
    reactor: &VclReactor,
    handler: &SharedHandler,
    metrics: &Arc<Metrics>,
    tls: Option<&Arc<rustls::ServerConfig>>,
) -> Result<Option<JoinHandle<()>>> {
    let name = lc.name.clone();
    match proto {
        "udp" => UdpListener::spawn(lc.clone(), reactor.clone(), handler.clone(), metrics.clone())
            .await
            .map(Some),
        "tcp" => TcpListener::spawn(lc.clone(), reactor.clone(), handler.clone(), metrics.clone())
            .await
            .map(Some),
        "dot" => match tls {
            Some(t) => DotListener::spawn(
                lc.clone(),
                reactor.clone(),
                handler.clone(),
                metrics.clone(),
                t.clone(),
            )
            .await
            .map(Some),
            None => {
                tracing::warn!(listener = %name, "DoT requested but no TLS config available");
                Ok(None)
            }
        },
        "doh" => match tls {
            Some(t) => DohListener::spawn(
                lc.clone(),
                reactor.clone(),
                handler.clone(),
                metrics.clone(),
                t.clone(),
            )
            .await
            .map(Some),
            None => {
                tracing::warn!(listener = %name, "DoH requested but no TLS config available");
                Ok(None)
            }
        },
        _ => Ok(None),
    }
}

/// Bind every (listener, protocol) pair declared in `cfg` that's
/// not already in `out`, retrying transient bind failures every
/// 200ms until either everything is bound or `deadline` elapses.
/// VPP's FIB may not have addresses ready when dnsd starts; this
/// retry handles that race. Items in `out` already are left alone.
async fn bind_listener_set_with_retry(
    cfg: &DnsConfig,
    reactor: &VclReactor,
    handler: &SharedHandler,
    metrics: &Arc<Metrics>,
    tls: Option<&Arc<rustls::ServerConfig>>,
    out: &mut LiveListeners,
    total_deadline: Duration,
) {
    let deadline = Instant::now() + total_deadline;
    let backoff = Duration::from_millis(200);

    let mut pending: Vec<(ListenerCfg, &'static str)> = Vec::new();
    for lc in &cfg.listeners {
        for proto in ["udp", "tcp", "dot", "doh"] {
            if !lc.has_protocol(proto) {
                continue;
            }
            let key = ListenerKey {
                addr: lc.address,
                port: lc.port,
                proto,
            };
            if out.contains_key(&key) {
                continue; // already bound (this is the reload-diff path)
            }
            pending.push((lc.clone(), proto));
        }
    }

    let mut attempt: u32 = 0;
    while !pending.is_empty() {
        attempt += 1;
        let mut still_pending = Vec::new();
        for (lc, proto) in pending.drain(..) {
            let key = ListenerKey {
                addr: lc.address,
                port: lc.port,
                proto,
            };
            match try_bind_one(&lc, proto, reactor, handler, metrics, tls).await {
                Ok(Some(handle)) => {
                    out.insert(
                        key,
                        LiveListener {
                            name: lc.name.clone(),
                            handle,
                        },
                    );
                }
                Ok(None) => {} // permanent skip
                Err(e) => {
                    tracing::debug!(
                        listener = %lc.name,
                        proto,
                        attempt,
                        "bind failed (will retry): {e}"
                    );
                    still_pending.push((lc, proto));
                }
            }
        }
        pending = still_pending;
        if pending.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            for (lc, proto) in &pending {
                tracing::error!(
                    listener = %lc.name,
                    proto,
                    "bind giving up after retry deadline"
                );
            }
            break;
        }
        tokio::time::sleep(backoff).await;
    }
}

// ---- SIGHUP reload ---------------------------------------------

struct WaitArgs {
    control_socket: PathBuf,
    config_path: PathBuf,
    root_hints_path: PathBuf,
    reactor: VclReactor,
    metrics: Arc<Metrics>,
    cache: Arc<DnsCache>,
    live: Arc<LiveHandler<RecursorHandler>>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    /// Same ArcSwap the control socket holds — reload publishes the
    /// fresh Forwarders here so `dnsd-query forwarders` sees the
    /// new table immediately.
    forwarders_swap: Arc<arc_swap::ArcSwap<Forwarders>>,
}

/// Re-read router.yaml, build a fresh RecursorHandler, atomically
/// swap it into `live`, and diff the listener set against the new
/// config — abort listeners that no longer exist or whose address/
/// port/proto changed, leave unchanged listeners alone, spawn the
/// new ones. Cache is shared across the swap (no flush).
async fn reload(args: &WaitArgs, listeners: &mut LiveListeners) {
    tracing::info!(config = %args.config_path.display(), "SIGHUP — reloading");

    let new_cfg = match DnsConfig::load(&args.config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                config = %args.config_path.display(),
                "reload aborted, config read failed: {e}"
            );
            return;
        }
    };

    // Forwarders rebuild — most common reason for reload, isolated
    // path. If it fails (bad config), bail before swapping anything.
    let new_forwarders = match Forwarders::new(&new_cfg.forwarders).map(Arc::new) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("reload aborted, forwarder config invalid: {e}");
            return;
        }
    };

    // Publish the new forwarder table to the control socket's
    // shared view BEFORE swapping the recursor — that way
    // `dnsd-query forwarders` won't briefly disagree with the
    // recursor's actual lookup behaviour.
    args.forwarders_swap.store(new_forwarders.clone());

    // Build a fresh recursor from the new config. Cache + reactor
    // + metrics carry over so we don't lose the warm cache or
    // re-init VCL.
    let new_recursor = match RecursorHandler::from_parts(
        &new_cfg,
        args.reactor.clone(),
        args.metrics.clone(),
        args.cache.clone(),
        new_forwarders,
        Some(args.root_hints_path.clone()),
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("reload aborted, recursor init failed: {e}");
            return;
        }
    };

    // Atomic swap. In-flight queries finish on the old handler;
    // new ones see the new handler.
    args.live.swap(new_recursor);
    tracing::info!("recursor handler swapped");

    // Listener diff. Compute desired set from new_cfg, abort any
    // listener whose key isn't there anymore.
    let mut desired: std::collections::HashSet<ListenerKey> =
        std::collections::HashSet::new();
    for lc in &new_cfg.listeners {
        for proto in ["udp", "tcp", "dot", "doh"] {
            if lc.has_protocol(proto) {
                desired.insert(ListenerKey {
                    addr: lc.address,
                    port: lc.port,
                    proto,
                });
            }
        }
    }

    let mut aborted = 0u32;
    listeners.retain(|key, live| {
        if desired.contains(key) {
            true
        } else {
            tracing::info!(
                listener = %live.name,
                addr = %key.addr,
                port = key.port,
                proto = key.proto,
                "aborting listener (no longer in config)"
            );
            live.handle.abort();
            aborted += 1;
            false
        }
    });

    let handler: SharedHandler = args.live.clone();
    let before = listeners.len();
    bind_listener_set_with_retry(
        &new_cfg,
        &args.reactor,
        &handler,
        &args.metrics,
        args.tls_config.as_ref(),
        listeners,
        Duration::from_secs(5), // post-startup: VPP should be ready
    )
    .await;
    let added = listeners.len().saturating_sub(before);

    tracing::info!(
        active = listeners.len(),
        aborted,
        added,
        "reload complete"
    );
}

async fn wait_for_exit_with_reload(args: WaitArgs, mut listeners: LiveListeners) {
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
                reload(&args, &mut listeners).await;
            }
        }
    }

    // Clean shutdown: abort every listener so its task drops the
    // VclDgramSocket / VclListener and the deregister-on-drop runs
    // before we exit.
    for (_, l) in listeners.drain() {
        l.handle.abort();
    }

    let _ = std::fs::remove_file(&args.control_socket);
}
