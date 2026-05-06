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
use dnsd::control::{ControlServer, ControlState, DEFAULT_SOCKET};
use dnsd::handler::{AclSwap, CtxSwap, ListenerContext, LiveHandler, SharedHandler};
use dnsd::io::{doh::DohListener, dot::DotListener, tcp::TcpListener, udp::UdpListener};
use dnsd::metrics::Metrics;
use dnsd::recursor::{DnsCache, Forwarders, RecursorHandler};
use dnsd::io::transport::{self, ReactorCtx};
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
struct LiveListener {
    name: String,
    acl: AclSwap,
    ctx: CtxSwap,
    handle: JoinHandle<()>,
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

    // Single-threaded runtime so the main thread (worker-0,
    // registered implicitly by VclApp::init above) owns the listener
    // and control-socket tasks for the whole process. Upstream
    // queries don't run on this runtime's thread — see
    // UpstreamClient's worker pool.
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(16)
        .build()
        .context("building tokio runtime")?;
    let result = runtime.block_on(async_main(args, cfg));
    // Explicit drops to make the order obvious to a future reader
    // and to guarantee it even if something later inserts another
    // local between `vcl_app` and `runtime`.
    drop(runtime);
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

async fn async_main(args: Args, cfg: DnsConfig) -> Result<()> {
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
        reactor.clone(),
        metrics.clone(),
        cache.clone(),
        forwarders_initial,
        Some(root_hints_path.clone()),
        discovered_v6,
        discovered_v4,
        Some(args.data_dir.join("anchor")),
    )
    .context("RecursorHandler init")?;
    initial_recursor.spawn_dnssec_prewarm();
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
            discovered_v6_source: discovered_v6,
            discovered_v4_source: discovered_v4,
            anchor_dir: args.data_dir.join("anchor"),
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

/// Bind every (listener, protocol) pair declared in `cfg` that's
/// not already in `out`, retrying transient bind failures every
/// 200ms until either everything is bound or `deadline` elapses.
/// VPP's FIB may not have addresses ready when dnsd starts; this
/// retry handles that race. Items already in `out` are left alone.
///
/// Per-listener `acl` and `ctx` swaps are allocated once per
/// (lc, proto) and reused across retries — the same Arc pointers
/// land in `out` so reload's hot-swap path can find them later.
async fn bind_listener_set_with_retry(
    cfg: &DnsConfig,
    reactor: &ReactorCtx,
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
            match try_bind_one(&p.lc, p.proto, reactor, handler, metrics, tls, &p.acl, &p.ctx)
                .await
            {
                Ok(Some(handle)) => {
                    out.insert(
                        key,
                        LiveListener {
                            name: p.lc.name.clone(),
                            acl: p.acl,
                            ctx: p.ctx,
                            handle,
                        },
                    );
                }
                Ok(None) => {} // permanent skip
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
    reactor: ReactorCtx,
    metrics: Arc<Metrics>,
    cache: Arc<DnsCache>,
    live: Arc<LiveHandler<RecursorHandler>>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    /// Same ArcSwap the control socket holds — reload publishes the
    /// fresh Forwarders here so `dnsd-query forwarders` sees the
    /// new table immediately.
    forwarders_swap: Arc<arc_swap::ArcSwap<Forwarders>>,
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
        args.reactor.clone(),
        args.metrics.clone(),
        args.cache.clone(),
        new_forwarders,
        Some(args.root_hints_path.clone()),
        args.discovered_v6_source,
        args.discovered_v4_source,
        Some(args.anchor_dir.clone()),
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("reload aborted, recursor init failed: {e}");
            return;
        }
    };

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
                "aborting listener (no longer in config)"
            );
            live.handle.abort();
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
    // before we exit.
    for (_, l) in listeners.drain() {
        l.handle.abort();
    }

    let _ = std::fs::remove_file(&args.control_socket);
}
