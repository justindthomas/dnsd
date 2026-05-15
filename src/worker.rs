//! Dedicated VCL I/O thread.
//!
//! Every libvppcom call (`vls_*`, `vppcom_*`) goes through this one
//! std::thread. The thread runs a `current_thread` tokio runtime
//! plus the `VclReactor`. Listener accept-loops, listener serve-
//! loops, and the forwarder's upstream UDP/TCP sockets are spawned
//! onto this thread's runtime via its `Handle`. The recursor
//! itself (cache lookups, iterative walking logic, DNSSEC
//! validation, response building) runs on the **main** multi-
//! thread tokio runtime — listener tasks dispatch
//! `handler.handle_bytes(...)` back to main via
//! [`MainDispatchHandler`], and the forwarder's upstream
//! [`UpstreamClient::query`] dispatches actual session ops back
//! down to vcl-io via its `Handle`.
//!
//! Why this split:
//!
//! libvppcom's `svm_msg_q_timedwait` MQ-drain runs inside every
//! session op and serializes through a per-process VLS lock when
//! multiple threads are involved. If the recursor's tokio worker
//! threads called libvppcom directly, they'd contend on the lock
//! and the runtime's timer driver could be starved for tens of
//! seconds — exactly the failure mode that made the multi_thread
//! tokio + direct-libvppcom experiment wedge dnsd within ~30 s of
//! traffic. Confining libvppcom to one dedicated thread keeps the
//! main multi_thread runtime's threads free of any libvppcom call,
//! so timers, signal handling, and recursor logic run promptly
//! even when vcl-io is deep in a slow MQ drain.

use std::net::IpAddr;
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::runtime::Handle;
use tokio::sync::oneshot;

use crate::handler::{DnsHandler, ListenerContext, SharedHandler};
use crate::io::transport::{self, ReactorCtx};

/// Resolve the effective tokio worker thread count for the **main**
/// multi-thread runtime from config, env, and CPU availability.
/// Order of precedence (highest wins):
///   1. `DNSD_TCP_WORKERS` env var
///   2. `dns.tcp_workers` from router.yaml
///   3. Default `1` (single-worker main runtime — safe rollout
///      default)
///
/// The sentinel value `0` from either source means "auto" — use
/// `std::thread::available_parallelism()`. Result is clamped to
/// `[1, available_parallelism()]`. Note this is *separate* from the
/// vcl-io thread, which is always exactly one std::thread regardless
/// of this setting.
pub fn effective_worker_count(cfg_value: Option<u32>) -> usize {
    let cap = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let raw = std::env::var("DNSD_TCP_WORKERS")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .or(cfg_value);
    let n = match raw {
        Some(0) => cap,
        Some(n) => n as usize,
        None => 1,
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
        std::env::remove_var("DNSD_TCP_WORKERS");
        assert_eq!(effective_worker_count(None), 1);
    }

    #[test]
    fn explicit_value_passes_through_clamped() {
        std::env::remove_var("DNSD_TCP_WORKERS");
        let cap = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        assert_eq!(effective_worker_count(Some(2)), 2usize.min(cap));
        assert_eq!(effective_worker_count(Some(9999)), cap);
    }
}

/// `DnsHandler` shim that dispatches `handle_bytes` to a different
/// tokio runtime than the caller's. The listener tasks running on
/// vcl-io call `handler.handle_bytes(...).await`; the inner handler
/// is the real recursor on the main multi-thread runtime, and we
/// want all of its work (cache lookups, iterative walks, DNSSEC
/// validation, response builds) to run there rather than on vcl-io.
/// vcl-io stays free to drain libvppcom MQ events and service
/// listener I/O while main does the CPU work.
///
/// Implementation: spawn the actual handler invocation on `target`,
/// send the result back through a oneshot, await it on the caller's
/// side. If the target runtime is shutting down (spawned task is
/// dropped before it sends), surface `None` — the listener will
/// silently drop the client connection, same convention as for a
/// malformed query.
pub struct MainDispatchHandler {
    inner: SharedHandler,
    target: Handle,
}

impl MainDispatchHandler {
    pub fn new(inner: SharedHandler, target: Handle) -> Self {
        Self { inner, target }
    }
}

#[async_trait]
impl DnsHandler for MainDispatchHandler {
    async fn handle_bytes(
        &self,
        query: &[u8],
        peer: IpAddr,
        ctx: &ListenerContext,
    ) -> Option<Vec<u8>> {
        let inner = self.inner.clone();
        let query = query.to_vec();
        let ctx = ctx.clone();
        let (tx, rx) = oneshot::channel();
        self.target.spawn(async move {
            let resp = inner.handle_bytes(&query, peer, &ctx).await;
            let _ = tx.send(resp);
        });
        rx.await.ok().flatten()
    }

    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }
}

/// Pool of dedicated VCL I/O threads. Each thread runs a
/// `current_thread` tokio runtime + its own `VclReactor` + its own
/// MQ-epoll AsyncFd registration. Listener and forwarder tasks
/// spread across the pool so a DoH connection saturating one
/// thread's reads doesn't starve another thread's UDP recv_demux.
///
/// Under VLS, sessions are thread-agnostic at the libvppcom level
/// — the lock + auto-register hooks make it safe to touch any
/// session from any thread. The reason we still bind each session
/// to a single pool thread is the reactor: the AsyncFd that wraps
/// the MQ-epoll fd, plus the per-session waiter map, live on the
/// specific runtime that created them. Tasks that spawn from
/// inside another task inherit that runtime, which keeps each
/// session's I/O lifecycle on one thread without needing explicit
/// pinning.
///
/// VLS still serializes the actual libvppcom syscalls process-wide
/// (one thread inside libvppcom at a time), so total libvppcom
/// throughput doesn't scale linearly with pool size. The benefit
/// is *parallelism opportunity*: while pool thread A is parked in
/// `svm_msg_q_timedwait`, pool thread B can be doing Rust work
/// (rustls deframe, HTTP parse, response build) instead of also
/// blocking on libvppcom. That's enough to break the
/// recv_demux-starvation pattern that the single-thread pool
/// suffered under sustained DoH load.
pub struct VclIoExecutor {
    workers: Vec<VclIoWorker>,
    /// Round-robin counter for `pick_handle`. Wraps freely; we
    /// only care about distribution, not exact balance.
    next: std::sync::atomic::AtomicUsize,
}

struct VclIoWorker {
    handle: Handle,
    reactor: ReactorCtx,
    join: Option<thread::JoinHandle<()>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl VclIoExecutor {
    /// Spawn `n` vcl-io threads and wait for each to register a VCL
    /// worker, build a tokio runtime, and create its reactor. Caller
    /// must have run `VclApp::init` first.
    pub fn spawn(n: usize) -> Result<Self> {
        let n = n.max(1);
        let mut workers = Vec::with_capacity(n);
        for id in 0..n {
            let (ready_tx, ready_rx) =
                std_mpsc::sync_channel::<Result<(Handle, ReactorCtx)>>(0);
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            let join = thread::Builder::new()
                .name(format!("dnsd-vcl-io-{id}"))
                .spawn(move || {
                    vcl_io_thread_main(id, shutdown_rx, ready_tx);
                })
                .with_context(|| format!("spawning dnsd-vcl-io-{id}"))?;
            let (handle, reactor) = match ready_rx.recv() {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    let _ = join.join();
                    return Err(e.context(format!("vcl-io-{id} startup")));
                }
                Err(_) => {
                    let _ = join.join();
                    return Err(anyhow!("vcl-io-{id} panicked before reporting ready"));
                }
            };
            workers.push(VclIoWorker {
                handle,
                reactor,
                join: Some(join),
                shutdown_tx: Some(shutdown_tx),
            });
        }
        tracing::info!(threads = n, "vcl-io pool ready");
        Ok(VclIoExecutor {
            workers,
            next: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Workers reserved exclusively for the upstream forwarder
    /// (UDP demux + send, outbound TCP). Worker 0 is reserved; no
    /// listeners are ever bound on it.
    ///
    /// Why isolate: each vcl-io worker is a `current_thread`
    /// runtime that runs tasks to completion. A libvppcom call
    /// drains VPP's per-worker message queue, and under load that
    /// MQ accumulates a backlog large enough that a single
    /// `vppcom_session_read` blocks for *tens of seconds* draining
    /// it — freezing the whole worker runtime. If the upstream
    /// demux / send tasks share a worker with DoH listener TLS
    /// reads, one such freeze on a TLS read takes upstream I/O
    /// down with it, and recursive walks stall for 30s+ while the
    /// thread sits blocked in one FFI call. A worker hosting ONLY
    /// upstream sockets never builds that backlog: its demux drains
    /// continuously in bounded bursts, so no single call faces a
    /// giant MQ. The reserved worker keeps upstream I/O responsive
    /// regardless of what listener workers are doing.
    ///
    /// With a pool of 1 (degenerate), worker 0 serves both roles.
    pub fn upstream_workers(&self) -> Vec<(Handle, ReactorCtx)> {
        let w = &self.workers[0];
        vec![(w.handle.clone(), w.reactor.clone())]
    }

    /// Pick a listener worker by round-robin over workers 1..N
    /// (worker 0 is upstream-reserved — see `upstream_workers`).
    /// With a pool of 1, falls back to worker 0. The accept loop +
    /// every per-connection serve task it spawns inherit that
    /// worker's runtime.
    pub fn pick_listener(&self) -> (Handle, ReactorCtx) {
        let idx = if self.workers.len() > 1 {
            1 + self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                % (self.workers.len() - 1)
        } else {
            0
        };
        let w = &self.workers[idx];
        (w.handle.clone(), w.reactor.clone())
    }

    /// Number of vcl-io threads in the pool.
    pub fn len(&self) -> usize {
        self.workers.len()
    }

    /// Signal all vcl-io threads to shut down and join them.
    /// Idempotent.
    pub fn shutdown(&mut self) {
        for w in &mut self.workers {
            if let Some(tx) = w.shutdown_tx.take() {
                let _ = tx.send(());
            }
        }
        for w in &mut self.workers {
            if let Some(j) = w.join.take() {
                let _ = j.join();
            }
        }
    }
}

impl Drop for VclIoExecutor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn vcl_io_thread_main(
    id: usize,
    shutdown_rx: oneshot::Receiver<()>,
    ready_tx: std_mpsc::SyncSender<Result<(Handle, ReactorCtx)>>,
) {
    // Register with VLS up front. Under VLS this is technically lazy
    // (any vls_* op auto-registers), but we want
    // `vppcom_mq_epoll_fd` (called by `VclReactor::new`) to succeed
    // on the first try.
    vcl_rs::register_worker_thread();

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name(format!("dnsd-vcl-io-{id}"))
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready_tx.send(Err(
                anyhow::Error::from(e).context(format!("vcl-io-{id} tokio runtime"))
            ));
            return;
        }
    };
    let handle = rt.handle().clone();

    // Reactor must be created inside the tokio runtime context —
    // `tokio::io::unix::AsyncFd::with_interest` panics otherwise.
    let reactor = {
        let _enter = handle.enter();
        match transport::new_reactor() {
            Ok(r) => r,
            Err(e) => {
                let _ = ready_tx.send(Err(e.context(format!("vcl-io-{id} reactor"))));
                return;
            }
        }
    };

    if ready_tx.send(Ok((handle, reactor.clone()))).is_err() {
        drop(rt);
        return;
    }

    // Park on shutdown_rx. The runtime stays alive (driving its
    // spawned listener / forwarder tasks) until either the shutdown
    // sender fires or is dropped. On wake, the runtime drops which
    // aborts every spawned task; each task's `Drop` runs (closing
    // sessions, deregistering reactor entries) before the runtime
    // tears down.
    rt.block_on(async move {
        let _ = shutdown_rx.await;
        // Brief grace window: lets in-flight listener tasks notice
        // their abort and drop their VclListener / VclStream
        // cleanly. Without this, the runtime tears down mid-poll and
        // the reactor's deregister-on-drop racing with task
        // cancellation can leak waiter entries (harmless but noisy
        // in logs).
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    tracing::info!(vcl_io_id = id, "vcl-io thread exiting");
}
