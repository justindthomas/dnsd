//! VCL frontend worker pool.
//!
//! libvppcom pins every session to the OS thread whose worker
//! context originated it. When we ran a single tokio current_thread
//! runtime on the main thread (= app-worker-0), VPP's per-VPP-worker
//! session distribution meant ESTABLISHED DoH/DoT sessions could
//! land on a different VPP worker than the app worker driving them
//! — event delivery cross-worker is unreliable and DoH keep-alive
//! wedges. This module spawns N std::thread workers each registered
//! as their own VCL app-worker, each with its own `VclReactor` and
//! current_thread tokio runtime. The configured TCP/DoT/DoH listeners
//! are bound on every worker (VPP's session-layer load-balances
//! incoming connections across the listener instances), so a session
//! always ends up at an app-worker with a co-located VCL context.
//!
//! UDP stays on the main thread (= app-worker-0): its session pool
//! is flat and the cross-worker wedge doesn't apply.
//!
//! Each worker exposes a `tokio::runtime::Handle` so the main
//! thread's bind/diff/abort logic can schedule listener tasks onto
//! the worker without doing VCL ops itself.
//!
//! Worker count comes from `dns.tcp_workers` (or env override
//! `DNSD_TCP_WORKERS`), defaulting to `1`. Setting it higher trades
//! VPP-side fifo segments (128 MB each by default) for connection-
//! oriented parallelism.

use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::runtime::Handle;
use tokio::sync::oneshot;

use crate::io::transport::{self, ReactorCtx};

/// Resolve the effective worker count from config, env, and CPU
/// availability. Order of precedence (highest wins):
///   1. `DNSD_TCP_WORKERS` env var
///   2. `dns.tcp_workers` from router.yaml
///   3. Default `1` (current behavior — main thread alone handles
///      every listener)
///
/// The sentinel value `0` from either source means "auto" — use
/// `std::thread::available_parallelism()`. This lets operators
/// scale workers with the host's CPU count without rewriting config
/// when dnsd is deployed across heterogeneous hardware (the router
/// build has 8 logical CPUs; future Pi-class deployments might
/// have 4).
///
/// Result is clamped to `[1, available_parallelism()]`. Going above
/// the CPU count buys nothing (the workers contend on the same
/// physical cores) and burns VPP-side fifo segments (default 128 MB
/// each per registered VCL worker).
pub fn effective_worker_count(cfg_value: Option<u32>) -> usize {
    let cap = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let raw = std::env::var("DNSD_TCP_WORKERS")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .or(cfg_value);
    let n = match raw {
        Some(0) => cap,       // explicit auto
        Some(n) => n as usize, // explicit fixed
        None => 1,            // unset → single-thread default
    };
    n.clamp(1, cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_sentinel_maps_to_cpu_count() {
        let cap = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        assert_eq!(effective_worker_count(Some(0)), cap);
    }

    #[test]
    fn unset_defaults_to_single_worker() {
        // The env var would override; assume tests don't set it.
        std::env::remove_var("DNSD_TCP_WORKERS");
        assert_eq!(effective_worker_count(None), 1);
    }

    #[test]
    fn explicit_value_passes_through_clamped() {
        std::env::remove_var("DNSD_TCP_WORKERS");
        let cap = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        // Below cap: passes through.
        assert_eq!(effective_worker_count(Some(2)), 2usize.min(cap));
        // Above cap: clamped.
        assert_eq!(effective_worker_count(Some(9999)), cap);
    }
}

/// A spawned VCL worker thread plus the handles main needs to drive it.
pub struct Worker {
    pub id: usize,
    /// Tokio runtime handle for the worker's current_thread runtime.
    /// Use `handle.spawn(...)` from main to put a future onto this
    /// worker. The future then runs on the worker's OS thread, where
    /// VCL ops are valid against the worker's registered context.
    pub handle: Handle,
    /// Per-worker reactor. Clone freely — the clones share the
    /// underlying `Arc<Mutex<ReactorInner>>` and `Arc<AsyncFd<MqFd>>`.
    /// Critical caveat: VCL methods on this reactor (drain_events,
    /// register, deregister) call `vppcom_epoll_*` which look up the
    /// CURRENT thread's worker context. Only use the reactor from
    /// inside a future that's running on this worker's runtime.
    pub reactor: ReactorCtx,
    join: Option<thread::JoinHandle<()>>,
    /// One-shot to tell the worker thread to exit its `block_on`.
    /// Dropping it before the worker's runtime tears down triggers
    /// a graceful shutdown (the runtime aborts its tasks and drops
    /// its reactor, which deregisters every listener / accepted
    /// session via `Drop`).
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl Worker {
    /// Convenience: spawn `fut` on the worker's runtime and await
    /// its result on the caller's side. Use this when main needs
    /// the return value of a per-worker VCL op (e.g., bind result).
    pub async fn run<F, T>(&self, fut: F) -> Result<T>
    where
        F: std::future::Future<Output = Result<T>> + Send + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        self.handle.spawn(async move {
            let result = fut.await;
            let _ = tx.send(result);
        });
        rx.await
            .map_err(|_| anyhow!("worker {} dropped task before completing", "?"))?
    }
}

/// Pool of N VCL frontend workers. Worker 0 is the *first additional*
/// worker — it is NOT app-worker-0 (that's the main thread, where
/// UDP + control socket + signals run). I.e. when `tcp_workers = 4`,
/// the process has 5 VCL app-workers total: main (worker-0) + four
/// frontend workers.
pub struct WorkerPool {
    workers: Vec<Worker>,
}

impl WorkerPool {
    /// Spawn `n` VCL worker threads. Each thread:
    ///   1. Registers as a VCL app-worker (`register_worker_thread`).
    ///   2. Builds a `VclReactor` (with its own MQ epoll fd).
    ///   3. Builds a current_thread tokio runtime.
    ///   4. Hands its `(handle, reactor)` back to main via the ready
    ///      channel — main installs them into the Worker entry.
    ///   5. Blocks on the shutdown receiver. When main drops the
    ///      shutdown sender (or sends `()`), the worker's runtime
    ///      tears down: in-flight listener tasks abort, every
    ///      `VclListener`/`VclStream` drops, the reactor drops, and
    ///      finally the worker thread exits.
    ///
    /// The thread name is `dnsd-vcl-<id>` so `top -H` /
    /// `vppctl show app` shows the right thing.
    ///
    /// `VclApp::init` must already have run on the calling thread —
    /// `vppcom_worker_register` requires the app to exist.
    pub fn spawn(n: usize) -> Result<Self> {
        let mut workers = Vec::with_capacity(n);
        for id in 0..n {
            let (ready_tx, ready_rx) = std_mpsc::sync_channel::<Result<(Handle, ReactorCtx)>>(0);
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            let join = thread::Builder::new()
                .name(format!("dnsd-vcl-{id}"))
                .spawn(move || {
                    worker_thread_main(id, shutdown_rx, ready_tx);
                })
                .with_context(|| format!("spawning dnsd-vcl-{id}"))?;

            let (handle, reactor) = match ready_rx.recv() {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    // Worker failed to register / build runtime. The
                    // thread has already exited on its own; join to
                    // reap it before returning.
                    let _ = join.join();
                    return Err(e.context(format!("worker {id} startup")));
                }
                Err(_) => {
                    let _ = join.join();
                    return Err(anyhow!("worker {id} panicked before reporting ready"));
                }
            };
            workers.push(Worker {
                id,
                handle,
                reactor,
                join: Some(join),
                shutdown_tx: Some(shutdown_tx),
            });
        }
        tracing::info!(workers = n, "VCL frontend worker pool ready");
        Ok(WorkerPool { workers })
    }

    pub fn workers(&self) -> &[Worker] {
        &self.workers
    }

    pub fn len(&self) -> usize {
        self.workers.len()
    }

    /// Initiate clean shutdown: send the shutdown signal to every
    /// worker and join their OS threads. Joins are sequential. Each
    /// worker tears down its tokio runtime (which aborts listener
    /// tasks and drops the reactor) before its thread exits.
    pub fn shutdown(&mut self) {
        for w in &mut self.workers {
            if let Some(tx) = w.shutdown_tx.take() {
                let _ = tx.send(());
            }
        }
        for w in &mut self.workers {
            if let Some(j) = w.join.take() {
                // Bound the join by a few seconds via a side thread;
                // a wedged worker shouldn't block process exit. The
                // VclApp drop after `WorkerPool::drop` returns will
                // run `vppcom_app_destroy` and force-clean anything
                // we left behind.
                let _ = j.join();
            }
        }
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn worker_thread_main(
    id: usize,
    shutdown_rx: oneshot::Receiver<()>,
    ready_tx: std_mpsc::SyncSender<Result<(Handle, ReactorCtx)>>,
) {
    // Step 1: register this OS thread as a VCL app-worker. This is
    // the call that pins this thread to its `__vcl_worker_index` TLS
    // slot — every VCL session op on this thread thereafter resolves
    // via this index. Without it, any vppcom_session_* would GP-fault
    // on `vcm->workers[-1]`.
    vcl_rs::register_worker_thread();
    let widx = unsafe { vcl_rs::ffi::vppcom_worker_index() };
    if widx < 0 {
        let _ = ready_tx.send(Err(anyhow!(
            "worker {id}: VCL worker registration failed (rc={widx}) — \
             likely VPP-side fifo-segment exhaustion; see /Users/.../memory \
             project_libvppcom_threading.md"
        )));
        return;
    }
    tracing::info!(worker.id = id, vcl_worker_idx = widx, "VCL worker registered");

    // Step 2: current_thread tokio runtime. Single-threaded by
    // design — every task scheduled on this runtime runs on this OS
    // thread, which is the only thread with this worker's VCL context.
    //
    // Build the runtime BEFORE the reactor: `VclReactor::new` wraps
    // the MQ eventfd in `tokio::io::unix::AsyncFd`, which panics if
    // called outside a tokio runtime context. Entering the runtime
    // via `Handle::enter()` gives us a guard valid for the rest of
    // setup; the guard drops before we hand off to `block_on` so
    // the runtime can take over.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name(format!("dnsd-vcl-{id}"))
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready_tx.send(Err(anyhow::Error::from(e)
                .context(format!("worker {id} tokio runtime"))));
            return;
        }
    };
    let handle = rt.handle().clone();

    // Step 3: per-worker reactor. Holds the worker's own MQ epoll
    // fd, which is distinct from worker-0's. Tokio AsyncFd wraps it
    // so the reactor wakes when VPP sends an event to THIS app-worker.
    // Must be created with the runtime context active.
    let reactor = {
        let _enter = handle.enter();
        match transport::new_reactor() {
            Ok(r) => r,
            Err(e) => {
                let _ = ready_tx.send(Err(e.context(format!("worker {id} reactor"))));
                return;
            }
        }
    };

    // Hand handle + reactor back to main BEFORE entering the run
    // loop. Main needs both to schedule listener tasks on this
    // worker.
    if ready_tx.send(Ok((handle, reactor.clone()))).is_err() {
        // Main has dropped the ready_rx — pool startup aborted. Just
        // tear down and exit.
        drop(rt);
        return;
    }

    // Step 4: park on shutdown_rx. The runtime stays alive (so any
    // listener tasks main spawns onto it via `worker.handle.spawn`
    // get to run) until shutdown fires. Bounded by 1s wake to allow
    // the runtime to make periodic forward progress on timers / IO
    // even when no shutdown signal arrives — current_thread runtime
    // can't run tasks without `block_on` driving it. (`block_on`
    // doesn't actually need this — it does drive its own poller —
    // but a periodic wake costs nothing and is a defense if some
    // future tokio version changes that assumption.)
    rt.block_on(async move {
        // We're driving the runtime via this block_on; the
        // shutdown_rx await is just a parking primitive. Once it
        // fires (or its sender drops), we return and `rt` drops,
        // which aborts every spawned task and lets every Drop run.
        let _ = shutdown_rx.await;
        // Give in-flight listener tasks a brief window to notice
        // their abort and drop their VclListener / VclStream
        // cleanly. Without this, the runtime tears down mid-poll
        // and the reactor's deregister-on-drop racing with task
        // cancellation can leak waiter entries (harmless but noisy).
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    tracing::info!(worker.id = id, "VCL worker thread exiting");
}
