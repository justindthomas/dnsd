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
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinHandle;
use tracing_subscriber::{fmt, EnvFilter};

use dnsd::acl::ClientAcl;
use dnsd::acme;
use dnsd::config::{DnsConfig, Listener as ListenerCfg, DEFAULT_MAX_INFLIGHT};
use dnsd::control::{ControlServer, ControlState, ListenerInfo, TlsInfo, DEFAULT_SOCKET};
use dnsd::handler::{AclSwap, CtxSwap, ListenerContext, LiveHandler, SharedHandler};
use dnsd::io::{doh::DohListener, dot::DotListener, tcp::TcpListener, udp::UdpListener};
use dnsd::metrics::Metrics;
use dnsd::recursor::{DnsCache, Forwarders, RecursorHandler};
use dnsd::io::transport::{self, ReactorCtx};
#[cfg(feature = "vcl")]
use dnsd::worker::{effective_worker_count, MainDispatchHandler, VclIoExecutor};
#[cfg(feature = "vcl")]
use vcl_rs::VclApp;

// VCL ops do NOT go through tokio's blocking pool. libvppcom 25.10
// pins each session to the OS thread that registered the worker
// context, and tokio's blocking pool reuses threads in a way that
// breaks that pin (`vppcom_session_create` GP-faults on
// `__vcl_worker_index` arithmetic when the calling thread isn't
// registered against a live worker). Upstream UDP/TCP queries
// dispatch to a dedicated long-lived `std::thread` worker pool
// inside `UpstreamClient`; the listener side runs on the main
// runtime thread (worker-0, registered by `VclApp::init`). No
// `on_thread_start` registration callback here — if you find
// yourself wanting to add `spawn_blocking` for VCL work, use the
// upstream worker pool pattern instead.

/// Identity of a single bound listener — what the diff-on-reload
/// path uses to decide "same listener, leave alone" vs "addr/port/
/// proto changed, abort + spawn fresh".
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ListenerKey {
    addr: IpAddr,
    port: u16,
    proto: &'static str, // "udp" | "tcp" | "dot" | "doh"
}

/// Hot-swappable runtime for a bound listener. The listener task
/// loads `acl` and `ctx` on every recv/accept, so reload can publish
/// fresh values (allow_from CIDRs, dns64 toggle, name) without
/// rebinding — already-connected TCP/DoT/DoH peers see the change on
/// their next request.
///
/// `handles` holds one `JoinHandle` per *binding instance*. UDP
/// listeners always have len = 1 (bound once on the main reactor).
/// TCP/DoT/DoH listeners have len = 1 when `tcp_workers = 1` (bound
/// on the main reactor) or len = N when `tcp_workers = N > 1` (bound
/// once on each frontend worker's reactor — VPP's session-layer
/// load-balances incoming connections across the N listener
/// instances). Abort-on-shutdown / abort-on-reload iterates over the
/// whole vec.
struct LiveListener {
    name: String,
    acl: AclSwap,
    ctx: CtxSwap,
    handles: Vec<JoinHandle<()>>,
}

type LiveListeners = HashMap<ListenerKey, LiveListener>;

fn make_acl_swap(lc: &ListenerCfg) -> AclSwap {
    Arc::new(arc_swap::ArcSwap::from_pointee(ClientAcl::new(
        lc.allow_from.clone(),
    )))
}

fn make_ctx_swap(lc: &ListenerCfg) -> CtxSwap {
    Arc::new(arc_swap::ArcSwap::from_pointee(ListenerContext::new(
        &lc.name, lc.dns64,
    )))
}

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

    /// Per-VRF instance name. When set, dnsd reads only the
    /// matching `dns.vrfs[name]` slice from router.yaml; without
    /// it the daemon falls back to the legacy single-tenant
    /// top-level `dns:` block. impd's supervisor passes this for
    /// every non-default-VRF child it spawns (`imp-dnsd@<vrf>`).
    #[arg(long)]
    vrf: Option<String>,
}

fn main() -> Result<()> {
    // Honour NO_COLOR — keeps ANSI escapes out of impd-captured
    // stderr → journald.
    //
    // Skip the per-event timestamp when stderr isn't a terminal:
    // under impd the captured line already gets impd's own timestamp
    // and journald adds a third on top. Triple-stamping was just
    // visual noise in `journalctl -u impd`. When dnsd runs standalone
    // (foreground in a shell, kernel-sockets dev mode) stderr IS a
    // terminal and timestamps stay on.
    use std::io::IsTerminal as _;
    let stderr_is_tty = std::io::stderr().is_terminal();
    let builder = fmt()
        .with_ansi(stderr_is_tty && std::env::var_os("NO_COLOR").is_none())
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        );
    if stderr_is_tty {
        builder.init();
    } else {
        // Drop both timestamp and level prefix — impd's capture
        // already prepends both. Without this we'd see e.g.
        // `... impd[88]: 2026-... INFO  INFO dnsd::recursor: ...`
        // (impd adds the leading "INFO ts", dnsd contributes the
        // second "INFO").
        builder.without_time().with_level(false).init();
    }

    let args = Args::parse();

    let cfg = match &args.vrf {
        None => DnsConfig::load(&args.config)
            .with_context(|| format!("loading dns config from {}", args.config.display()))?,
        Some(name) => DnsConfig::load_for_vrf(&args.config, name).with_context(|| {
            format!(
                "loading dns config from {} for vrf {}",
                args.config.display(),
                name
            )
        })?,
    };
    tracing::info!(
        enabled = cfg.enabled,
        listeners = cfg.listeners.len(),
        forwarders = cfg.forwarders.len(),
        vrf = ?args.vrf,
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
    // Drop order at function exit is reverse declaration order.
    // We need the runtime (and everything it owns — listener tasks,
    // RecursorHandler, UpstreamClient, the cmd channel feeding the
    // dedicated worker threads) to drop BEFORE `vcl_app` so that
    // `vppcom_app_destroy` runs after every VCL session is already
    // closed. If we did it the other way, the worker threads would
    // still be in their recv loop holding sessions when libvppcom
    // tears the app down — and the SIGTERM-triggered shutdown wedges.
    // Hence: declare `vcl_app` first (drops last), then `runtime`.
    //
    // Kernel-sockets backend has no equivalent: no shared library
    // state to initialise, no worker-thread registration, no shutdown
    // ordering hazard.
    #[cfg(feature = "vcl")]
    let vcl_app = VclApp::init("dnsd")
        .with_context(|| "VclApp::init — is VPP up and vcl.conf readable?")?;

    // Dedicated VCL I/O thread. Owns the VclReactor + every
    // libvppcom call (listener accept/serve loops, upstream UDP
    // socket binds, upstream send/recv). Created before the main
    // multi_thread runtime so its tokio Handle + ReactorCtx are
    // available at the moment the main runtime starts servicing
    // async_main. Drop order at exit: main runtime drops first
    // (tasks abort, dispatches into vcl-io's oneshots fail
    // cleanly), then vcl_io drops (its runtime tears down,
    // listeners close, sessions Drop), then vcl_app drops
    // (vppcom_app_destroy).
    // Pool size mirrors the main tokio runtime's worker count. The
    // vcl-io pool's job is to spread libvppcom-touching tasks
    // (listener accept/serve loops, upstream UDP demux, response
    // send_to) across multiple threads so a busy DoH connection on
    // one thread can't starve recv_demux for upstream UDP responses
    // on another. VLS still serializes the actual libvppcom
    // syscalls, but each thread runs Rust code (rustls, HTTP parse,
    // response build) between syscalls — so while thread A is
    // parked in `svm_msg_q_timedwait`, thread B is free to do
    // useful non-libvppcom work AND, when it does need libvppcom,
    // gets its slice on the VLS lock without queueing behind a
    // dozen of thread A's pending operations.
    #[cfg(feature = "vcl")]
    let vcl_io_pool_size = {
        let n = effective_worker_count(cfg.tcp_workers);
        tracing::info!(vcl_io_threads = n, "vcl-io pool size");
        n
    };
    #[cfg(feature = "vcl")]
    let vcl_io = std::sync::Arc::new(
        VclIoExecutor::spawn(vcl_io_pool_size).context("spawning vcl-io pool")?,
    );

    // Multi-thread tokio runtime sized from `dns.tcp_workers`
    // (env override `DNSD_TCP_WORKERS`). Under VLS every libvppcom
    // call takes a process-wide lock and auto-registers the calling
    // thread, so tokio's worker threads are free to do work-stealing
    // and ANY thread can drive ANY session — sessions are no longer
    // pinned to a single OS thread. This is the whole point of the
    // VLS port: under classic libvppcom the runtime had to be
    // single-threaded so sessions stayed on `__vcl_worker_index=0`;
    // under VLS we can size the runtime to the workload, and a slow
    // libvppcom call on one worker thread no longer blocks timers
    // and other tasks from making progress on the others.
    //
    // The old per-worker pool (`WorkerPool`) bound listeners on each
    // worker's own VCL app-worker context, with cross-worker
    // listener replication via VPP's session layer. Under VLS that
    // is unnecessary: a single set of listeners, with accepted
    // sessions dispatched by tokio's work-stealing scheduler, gives
    // the same parallelism without doubling VPP-side fifo segments.
    //
    // max_blocking_threads is capped to a small number so a
    // misbehaving caller can't fan out hundreds of spawn_blocking
    // tasks. We hit this in production when impd misbehaved and
    // double-spawned dnsd: the second instance saw VPP-side
    // "ip port pair already listened on" errors and entered some
    // path that grew the blocking pool to 500 threads, every one
    // of which then GP-faulted inside libvppcom because it wasn't
    // VCL-registered. dnsd itself doesn't intentionally use
    // spawn_blocking for VCL ops (see UPSTREAM_WORKERS), so 16 is
    // enough headroom for tokio internals + tokio-rustls handshakes.
    #[cfg(feature = "vcl")]
    let worker_threads = {
        let n = effective_worker_count(cfg.tcp_workers);
        tracing::info!(
            tcp_workers_cfg = ?cfg.tcp_workers,
            tcp_workers_env = ?std::env::var("DNSD_TCP_WORKERS").ok(),
            available_parallelism = ?std::thread::available_parallelism().ok().map(|n| n.get()),
            effective_n = n,
            "tokio worker count resolved",
        );
        n
    };
    #[cfg(not(feature = "vcl"))]
    let worker_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .max_blocking_threads(16)
        .thread_name("dnsd-tokio")
        .build()
        .context("building tokio runtime")?;
    #[cfg(feature = "vcl")]
    let result = runtime.block_on(async_main(args, cfg, vcl_io.clone()));
    #[cfg(not(feature = "vcl"))]
    let result = runtime.block_on(async_main(args, cfg));
    // Explicit drops to make the order obvious to a future reader
    // and to guarantee it even if something later inserts another
    // local between `vcl_app` and `runtime`.
    drop(runtime);
    #[cfg(feature = "vcl")]
    drop(vcl_io);
    #[cfg(feature = "vcl")]
    drop(vcl_app);
    result
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
        // Disabled mode has no bound listeners and no TLS materials;
        // operator queries still get a well-formed empty response.
        listeners: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::<ListenerInfo>::new())),
        tls: Arc::new(arc_swap::ArcSwap::from_pointee(TlsInfo::default())),
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

async fn async_main(
    args: Args,
    cfg: DnsConfig,
    #[cfg(feature = "vcl")] vcl_io: std::sync::Arc<VclIoExecutor>,
) -> Result<()> {
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

    // Same hot-swap pattern for the listener bind set and the TLS
    // materials snapshot. Both start empty; main publishes a fresh
    // value after the initial bind and after every SIGHUP-driven
    // diff, so the control socket reads the live state without
    // coordinating with the listener loop.
    let listeners_swap: Arc<arc_swap::ArcSwap<Vec<ListenerInfo>>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
    let tls_swap: Arc<arc_swap::ArcSwap<TlsInfo>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(TlsInfo::default()));

    // Control socket first so the impd supervisor's Ready::Socket gate
    // unblocks; we don't want the whole startup to stall behind VCL
    // init if something is wrong with VPP.
    let control_path = args.control_socket.clone();
    let state = ControlState {
        metrics: metrics.clone(),
        cache: cache.clone(),
        forwarders: forwarders_swap.clone(),
        listeners: listeners_swap.clone(),
        tls: tls_swap.clone(),
    };
    let control = ControlServer::new(control_path.clone(), state);
    tokio::spawn(async move {
        if let Err(e) = control.serve().await {
            tracing::error!("control server exited: {e}");
        }
    });

    // Under vcl, every reactor lives inside the vcl-io pool — the
    // recursor's upstream client builds its channels from
    // `vcl_io.workers()`, and listener binds pick a worker each.
    // No standalone reactor needed here. Kernel-sockets builds one.
    #[cfg(not(feature = "vcl"))]
    let reactor = transport::new_reactor().with_context(|| "transport::new_reactor")?;

    // Ask VPP for a globally-routable v6 source IP. Used as the
    // outbound source for IPv6 upstream queries when neither
    // `recursion.source_v6` nor a v6 listener provides one. The VCL
    // API can't tell us VPP's FIB-derived source, so we go around
    // it via the binary API (vpp-api crate). Discovery failure is
    // non-fatal — dnsd just won't have a v6 source and v6 NS
    // queries will time out.
    //
    // Kernel-sockets backend skips this: kernel routing picks the
    // source automatically (or honours an explicit `source_v6:` from
    // config). No VPP API is reachable in that build anyway.
    #[cfg(feature = "vcl")]
    let discovered_v6 = match dnsd::recursor::forwarder::discover_v6_source(
        dnsd::recursor::forwarder::DEFAULT_VPP_API_SOCKET,
    )
    .await
    {
        Ok(v6) => v6,
        Err(e) => {
            tracing::warn!("v6 source auto-discovery failed: {e:#}");
            None
        }
    };
    #[cfg(not(feature = "vcl"))]
    let discovered_v6: Option<std::net::Ipv6Addr> = None;
    // Same for v4. Required for outbound TCP — VPP's TCP stack
    // doesn't reliably match the SYN/ACK back to a session whose
    // source was picked by FIB at SYN-emit time. With an explicit
    // bind the session-lookup just works.
    #[cfg(feature = "vcl")]
    let discovered_v4 = match dnsd::recursor::forwarder::discover_v4_source(
        dnsd::recursor::forwarder::DEFAULT_VPP_API_SOCKET,
    )
    .await
    {
        Ok(v4) => v4,
        Err(e) => {
            tracing::warn!("v4 source auto-discovery failed: {e:#}");
            None
        }
    };
    #[cfg(not(feature = "vcl"))]
    let discovered_v4: Option<std::net::Ipv4Addr> = None;

    // Build the initial recursor and wrap it for hot-swap on SIGHUP.
    // Listener tasks hold the LiveHandler — they keep working across
    // reloads because LiveHandler dispatches through an ArcSwap that
    // we update with a fresh RecursorHandler.
    let initial_recursor = RecursorHandler::from_parts(
        &cfg,
        #[cfg(not(feature = "vcl"))]
        reactor.clone(),
        metrics.clone(),
        cache.clone(),
        forwarders_initial,
        Some(root_hints_path.clone()),
        discovered_v6,
        discovered_v4,
        Some(args.data_dir.join("anchor")),
        #[cfg(feature = "vcl")]
        vcl_io.workers(),
    )
    .await
    .context("RecursorHandler init")?;
    initial_recursor.spawn_dnssec_prewarm();
    let live: Arc<LiveHandler<RecursorHandler>> = Arc::new(LiveHandler::new(initial_recursor));
    // Listener tasks run on the vcl-io thread (so all libvppcom
    // calls funnel through one OS thread, keeping the main multi_
    // thread runtime free of libvppcom contention). The actual
    // recursor work (cache lookup, iterative walk, DNSSEC,
    // response build) should run on the *main* runtime instead so
    // it can use multiple worker threads in parallel. Wrap the
    // handler in `MainDispatchHandler`: each listener-side
    // `handle_bytes` call dispatches the work to main and awaits
    // the result via oneshot. While the dispatch is in flight, the
    // vcl-io listener task is parked — vcl-io is free to service
    // its other listeners, the MQ drain, accept loops, etc.
    #[cfg(feature = "vcl")]
    let handler: SharedHandler = Arc::new(MainDispatchHandler::new(
        live.clone(),
        tokio::runtime::Handle::current(),
    ));
    #[cfg(not(feature = "vcl"))]
    let handler: SharedHandler = live.clone();

    // TLS materials shared by DoT and DoH. `None` means no
    // `dns.tls:` block (DoT/DoH listeners will be skipped at bind
    // time with a warning).
    let tls_setup = acme::build_tls(&cfg).context("loading TLS config")?;
    let tls_config = tls_setup.as_ref().map(|s| s.server_config.clone());
    if let Some(s) = &tls_setup {
        tls_swap.store(Arc::new(s.info.clone()));
    }

    let mut listeners: LiveListeners = HashMap::new();
    bind_listener_set_with_retry(
        &cfg,
        #[cfg(not(feature = "vcl"))]
        &reactor,
        #[cfg(feature = "vcl")]
        vcl_io.as_ref(),
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
    listeners_swap.store(Arc::new(snapshot_listeners(&listeners)));

    wait_for_exit_with_reload(
        WaitArgs {
            control_socket: args.control_socket.clone(),
            config_path: args.config.clone(),
            root_hints_path,
            #[cfg(not(feature = "vcl"))]
            reactor,
            #[cfg(feature = "vcl")]
            vcl_io: vcl_io.clone(),
            metrics: metrics.clone(),
            cache,
            live,
            tls_config,
            forwarders_swap,
            listeners_swap,
            tls_swap,
            discovered_v6_source: discovered_v6,
            discovered_v4_source: discovered_v4,
            anchor_dir: args.data_dir.join("anchor"),
        },
        listeners,
    )
    .await;
    Ok(())
}

/// Render the live listener map into the shape consumed by the
/// control socket. Called after every bind/diff so
/// `imp-dnsd-query listeners` always reflects the current state.
fn snapshot_listeners(listeners: &LiveListeners) -> Vec<ListenerInfo> {
    let mut out: Vec<ListenerInfo> = listeners
        .iter()
        .map(|(key, live)| {
            let acl_snap = live.acl.load();
            let ctx_snap = live.ctx.load();
            let allow_from: Vec<String> =
                acl_snap.cidrs().iter().map(|c| c.to_string()).collect();
            ListenerInfo {
                name: live.name.clone(),
                address: key.addr.to_string(),
                port: key.port,
                protocol: key.proto.to_string(),
                allow_from,
                dns64: ctx_snap.dns64,
            }
        })
        .collect();
    // Stable sort so the operator-facing output is reproducible
    // across calls and across reloads — same (addr, port, proto)
    // always lands in the same row.
    out.sort_by(|a, b| {
        (a.address.as_str(), a.port, a.protocol.as_str())
            .cmp(&(b.address.as_str(), b.port, b.protocol.as_str()))
    });
    out
}

// ---- listener-spawn helpers ------------------------------------

/// Attempts to bind a single (listener, protocol) pair once.
/// Returns:
/// * `Ok(Some(handle))` — bound, listener task spawned.
/// * `Ok(None)` — permanently skipped (DoT/DoH without TLS, or
///   unknown protocol).
/// * `Err(_)` — transient bind failure; caller should retry. The
///   provided `acl` / `ctx` swaps are reused across retries so the
///   reload path's hot-swap pointers stay stable.
async fn try_bind_one(
    lc: &ListenerCfg,
    proto: &'static str,
    reactor: &ReactorCtx,
    handler: &SharedHandler,
    metrics: &Arc<Metrics>,
    tls: Option<&Arc<rustls::ServerConfig>>,
    acl: &AclSwap,
    ctx: &CtxSwap,
) -> Result<Option<JoinHandle<()>>> {
    let bind = SocketAddr::new(lc.address, lc.port);
    let name = lc.name.clone();
    let max_inflight = lc.max_inflight.unwrap_or(DEFAULT_MAX_INFLIGHT);
    match proto {
        "udp" => UdpListener::spawn(
            bind,
            reactor.clone(),
            handler.clone(),
            metrics.clone(),
            acl.clone(),
            ctx.clone(),
            max_inflight,
        )
        .await
        .map(Some),
        "tcp" => TcpListener::spawn(
            bind,
            reactor.clone(),
            handler.clone(),
            metrics.clone(),
            acl.clone(),
            ctx.clone(),
        )
        .await
        .map(Some),
        "dot" => match tls {
            Some(t) => DotListener::spawn(
                bind,
                reactor.clone(),
                handler.clone(),
                metrics.clone(),
                t.clone(),
                acl.clone(),
                ctx.clone(),
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
                bind,
                reactor.clone(),
                handler.clone(),
                metrics.clone(),
                t.clone(),
                acl.clone(),
                ctx.clone(),
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

/// Result of binding a (listener, protocol) pair. Wraps the vector
/// of `JoinHandle`s so the bind path can tell "permanent skip"
/// (`Skipped`) from "bound on N workers" (`Bound(handles)`). UDP and
/// the single-reactor TCP/DoT/DoH paths return `Bound(vec![h])` with
/// one handle.
enum BindOutcome {
    Bound(Vec<JoinHandle<()>>),
    Skipped,
}

/// Bind every (listener, protocol) pair declared in `cfg` that's
/// not already in `out`, retrying transient bind failures every
/// 200ms until either everything is bound or `deadline` elapses.
/// VPP's FIB may not have addresses ready when dnsd starts; this
/// retry handles that race. Items already in `out` are left alone.
///
/// Per-listener `acl` and `ctx` swaps are allocated once per
/// (lc, proto) and reused across retries — the same Arc pointers
/// land in `out` so reload's hot-swap path can find them later.
///
/// Under VLS + multi-thread tokio, one bind per (addr, port, proto)
/// is enough — tokio's work-stealing scheduler spreads accepted
/// sessions across worker threads, and the VLS lock keeps libvppcom
/// safe across threads.
async fn bind_listener_set_with_retry(
    cfg: &DnsConfig,
    #[cfg(not(feature = "vcl"))] reactor: &ReactorCtx,
    #[cfg(feature = "vcl")] vcl_io: &VclIoExecutor,
    handler: &SharedHandler,
    metrics: &Arc<Metrics>,
    tls: Option<&Arc<rustls::ServerConfig>>,
    out: &mut LiveListeners,
    total_deadline: Duration,
) {
    let deadline = Instant::now() + total_deadline;
    let backoff = Duration::from_millis(200);

    struct Pending {
        lc: ListenerCfg,
        proto: &'static str,
        acl: AclSwap,
        ctx: CtxSwap,
    }

    let mut pending: Vec<Pending> = Vec::new();
    for lc in &cfg.listeners {
        // One ACL/ctx swap per logical listener; UDP and TCP for the
        // same listener share so an allow_from edit applies to both
        // protocols at once.
        let acl = make_acl_swap(lc);
        let ctx = make_ctx_swap(lc);
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
            pending.push(Pending {
                lc: lc.clone(),
                proto,
                acl: acl.clone(),
                ctx: ctx.clone(),
            });
        }
    }

    let mut attempt: u32 = 0;
    while !pending.is_empty() {
        attempt += 1;
        let mut still_pending = Vec::new();
        for p in pending.drain(..) {
            let key = ListenerKey {
                addr: p.lc.address,
                port: p.lc.port,
                proto: p.proto,
            };
            // Dispatch the bind onto a pool-picked vcl-io thread.
            // The listener's accept loop (and every per-connection
            // serve task it spawns) inherits that thread's runtime
            // as ambient, so all subsequent libvppcom calls for
            // sessions on this listener stay on that one thread.
            // Different listeners pick different threads via the
            // pool's round-robin, so e.g. bvi100-doh on one thread
            // doesn't starve bvi100-v6-udp's recv_demux on another.
            #[cfg(feature = "vcl")]
            let outcome: Result<BindOutcome> = {
                let (vcl_handle, picked_reactor) = vcl_io.pick_listener();
                let lc = p.lc.clone();
                let proto = p.proto;
                let handler = handler.clone();
                let metrics = metrics.clone();
                let tls = tls.cloned();
                let acl = p.acl.clone();
                let ctx = p.ctx.clone();
                let (tx, rx) = tokio::sync::oneshot::channel();
                vcl_handle.spawn(async move {
                    let result = try_bind_one(
                        &lc, proto, &picked_reactor, &handler, &metrics, tls.as_ref(), &acl, &ctx,
                    )
                    .await;
                    let _ = tx.send(result);
                });
                match rx.await {
                    Ok(Ok(Some(h))) => Ok(BindOutcome::Bound(vec![h])),
                    Ok(Ok(None)) => Ok(BindOutcome::Skipped),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(anyhow::anyhow!("vcl-io bind dispatch dropped")),
                }
            };
            #[cfg(not(feature = "vcl"))]
            let outcome: Result<BindOutcome> = match try_bind_one(
                &p.lc, p.proto, reactor, handler, metrics, tls, &p.acl, &p.ctx,
            )
            .await
            {
                Ok(Some(h)) => Ok(BindOutcome::Bound(vec![h])),
                Ok(None) => Ok(BindOutcome::Skipped),
                Err(e) => Err(e),
            };

            match outcome {
                Ok(BindOutcome::Bound(handles)) => {
                    out.insert(
                        key,
                        LiveListener {
                            name: p.lc.name.clone(),
                            acl: p.acl,
                            ctx: p.ctx,
                            handles,
                        },
                    );
                }
                Ok(BindOutcome::Skipped) => {} // permanent skip
                Err(e) => {
                    tracing::debug!(
                        listener = %p.lc.name,
                        proto = p.proto,
                        attempt,
                        "bind failed (will retry): {e}"
                    );
                    still_pending.push(p);
                }
            }
        }
        pending = still_pending;
        if pending.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            for p in &pending {
                tracing::error!(
                    listener = %p.lc.name,
                    proto = p.proto,
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
    /// Kernel-sockets backend: the lone reactor. Under vcl, reactors
    /// live per-worker inside `vcl_io` and there's no standalone one.
    #[cfg(not(feature = "vcl"))]
    reactor: ReactorCtx,
    /// The vcl-io worker pool. Reload rebuilds the recursor from
    /// `vcl_io.workers()` and re-binds listeners via `pick_listener`.
    #[cfg(feature = "vcl")]
    vcl_io: std::sync::Arc<VclIoExecutor>,
    metrics: Arc<Metrics>,
    cache: Arc<DnsCache>,
    live: Arc<LiveHandler<RecursorHandler>>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    /// Same ArcSwap the control socket holds — reload publishes the
    /// fresh Forwarders here so `dnsd-query forwarders` sees the
    /// new table immediately.
    forwarders_swap: Arc<arc_swap::ArcSwap<Forwarders>>,
    /// Listener bind snapshot published after every diff — drives
    /// `imp-dnsd-query listeners`.
    listeners_swap: Arc<arc_swap::ArcSwap<Vec<ListenerInfo>>>,
    /// TLS materials snapshot published when `dns.tls:` is built.
    /// Rebuilt on SIGHUP so an operator who rotated certs (or
    /// flipped cert_source) sees the change without a daemon
    /// restart.
    tls_swap: Arc<arc_swap::ArcSwap<TlsInfo>>,
    /// VPP-discovered global v6 source IP, captured once at startup.
    /// Re-used across SIGHUP reloads so the same source binds across
    /// the whole process lifetime — interface addresses don't
    /// typically change between SIGHUPs, and re-querying VPP on
    /// every reload would slow it down for no benefit.
    discovered_v6_source: Option<std::net::Ipv6Addr>,
    /// VPP-discovered v4 source IP. Same rationale as v6.
    discovered_v4_source: Option<std::net::Ipv4Addr>,
    /// Self-managed trust-anchor directory (`<data_dir>/anchor/`).
    /// Used when no operator `trust_anchor:` path is set; the
    /// RFC 5011 refresh task and (in phase 5) the bootstrap fetch
    /// both write here.
    anchor_dir: PathBuf,
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
        #[cfg(not(feature = "vcl"))]
        args.reactor.clone(),
        args.metrics.clone(),
        args.cache.clone(),
        new_forwarders,
        Some(args.root_hints_path.clone()),
        args.discovered_v6_source,
        args.discovered_v4_source,
        Some(args.anchor_dir.clone()),
        #[cfg(feature = "vcl")]
        args.vcl_io.workers(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("reload aborted, recursor init failed: {e}");
            return;
        }
    };

    // Rebuild TLS materials from the new config. If the operator
    // *added* a `dns.tls:` block on this reload, we need the fresh
    // ServerConfig in hand before the listener-bind path runs so
    // newly-declared DoT/DoH listeners actually bind. Without this
    // path, the bind would fall back to `args.tls_config` (captured
    // at startup) and silently skip the DoT/DoH protocols with
    // "DoT requested but no TLS config available". Already-bound
    // listeners stay on the original ServerConfig — hot-swapping a
    // running rustls::ServerConfig across in-flight handshakes is
    // not something rustls exposes; cert rotation still needs a
    // process restart.
    let new_tls_setup = match acme::build_tls(&new_cfg) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("reload: TLS rebuild failed: {e}");
            None
        }
    };
    let effective_tls = new_tls_setup
        .as_ref()
        .map(|s| s.server_config.clone())
        .or_else(|| args.tls_config.clone());
    let new_tls_info = new_tls_setup
        .as_ref()
        .map(|s| s.info.clone())
        .unwrap_or_default();
    args.tls_swap.store(Arc::new(new_tls_info));

    // Atomic swap. In-flight queries finish on the old handler;
    // new ones see the new handler.
    new_recursor.spawn_dnssec_prewarm();
    args.live.swap(new_recursor);
    tracing::info!("recursor handler swapped");

    // Listener diff. Build the desired set indexed by ListenerKey
    // so we can correlate each existing listener with its new
    // ListenerCfg for hot-swap of allow_from / dns64 / name.
    let mut desired: HashMap<ListenerKey, ListenerCfg> = HashMap::new();
    for lc in &new_cfg.listeners {
        for proto in ["udp", "tcp", "dot", "doh"] {
            if lc.has_protocol(proto) {
                desired.insert(
                    ListenerKey {
                        addr: lc.address,
                        port: lc.port,
                        proto,
                    },
                    lc.clone(),
                );
            }
        }
    }

    // Abort listeners whose (addr, port, proto) is no longer in
    // config. The remaining ones get an in-place ACL/ctx update.
    let mut aborted = 0u32;
    listeners.retain(|key, live| {
        if desired.contains_key(key) {
            true
        } else {
            tracing::info!(
                listener = %live.name,
                addr = %key.addr,
                port = key.port,
                proto = key.proto,
                n_handles = live.handles.len(),
                "aborting listener (no longer in config)"
            );
            for h in &live.handles {
                h.abort();
            }
            aborted += 1;
            false
        }
    });

    // Hot-swap ACL + ctx for kept listeners. The listener task picks
    // up the new values on its next recv/accept (and on every read
    // inside an open TCP/DoT/DoH connection), so a CIDR change or
    // dns64 toggle takes effect without dropping live connections.
    let mut updated = 0u32;
    for (key, lc) in &desired {
        if let Some(live) = listeners.get_mut(key) {
            let new_acl = Arc::new(ClientAcl::new(lc.allow_from.clone()));
            let new_ctx = Arc::new(ListenerContext::new(&lc.name, lc.dns64));
            live.acl.store(new_acl);
            live.ctx.store(new_ctx);
            // Cached name is what we use in the abort log line; keep
            // it in sync with the swap so logs reflect renames.
            if live.name != lc.name {
                live.name = lc.name.clone();
            }
            updated += 1;
        }
    }

    // Wrap handler for vcl-io→main dispatch, same as initial bind.
    // Already-bound listeners hold their original wrapped handler;
    // newly-bound ones get this fresh wrap with the same target.
    #[cfg(feature = "vcl")]
    let handler: SharedHandler = Arc::new(MainDispatchHandler::new(
        args.live.clone(),
        tokio::runtime::Handle::current(),
    ));
    #[cfg(not(feature = "vcl"))]
    let handler: SharedHandler = args.live.clone();
    let before = listeners.len();
    bind_listener_set_with_retry(
        &new_cfg,
        #[cfg(not(feature = "vcl"))]
        &args.reactor,
        #[cfg(feature = "vcl")]
        args.vcl_io.as_ref(),
        &handler,
        &args.metrics,
        effective_tls.as_ref(),
        listeners,
        Duration::from_secs(5), // post-startup: VPP should be ready
    )
    .await;
    let added = listeners.len().saturating_sub(before);

    // Publish the post-diff bind state for the `listeners` control
    // command. ACL/ctx hot-swaps already applied to the kept
    // listeners are reflected because we read straight off the live
    // ArcSwaps via `snapshot_listeners`.
    args.listeners_swap
        .store(Arc::new(snapshot_listeners(listeners)));

    tracing::info!(
        active = listeners.len(),
        aborted,
        updated,
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
    // before we exit. TCP/DoT/DoH listeners may have a vec of
    // handles (one per frontend worker) when `tcp_workers > 1`.
    for (_, l) in listeners.drain() {
        for h in l.handles {
            h.abort();
        }
    }

    let _ = std::fs::remove_file(&args.control_socket);
}
