//! DNS-over-HTTPS (RFC 8484) listener.
//!
//! `DnsTcpListener` (transport-backend-selected) accepts TCP/443.
//! Each connection is
//! wrapped in rustls and then in hyper via `axum` for the HTTP
//! plumbing. We serve both modes per RFC 8484:
//!
//!   GET  /dns-query?dns=<base64url-wire>
//!   POST /dns-query        body=application/dns-message
//!
//! Response content-type is always `application/dns-message`; the
//! upstream cache's TTL feeds into `Cache-Control: max-age=<ttl>`.
//!
//! ALPN includes `h2` and `http/1.1`. Adding `acme-tls/1` for tls-
//! alpn-01 ACME challenges is done by the `rustls-acme` wrapper
//! when `dns.tls.cert_source` is `acme`.
//!
//! Protocol selection is driven by the **TLS-negotiated ALPN**, not
//! by hyper-util's auto Builder. The auto Builder picks h1 vs h2 by
//! peeking the first ~24 bytes of application data after the TLS
//! handshake; under VCL/libvppcom that peek wedged the connection
//! (no observed bytes through, no error logged). ALPN already
//! carries the protocol selection (`h2` vs `http/1.1`) — read it
//! straight off the rustls ServerConnection and dispatch to the
//! matching hyper builder explicitly. Most DoH clients (Firefox,
//! curl, dns-over-https libs) negotiate h2; kdig / simple shell
//! clients stay on h1.1. If a client connects without ALPN (rare),
//! fall back to http/1.1 — the safest default.
//!
//! Testing note: under LD_PRELOAD'd libvppcom on the router host
//! itself, `curl` hangs after sending the request regardless of
//! HTTP version (h1 or h2). `openssl s_client -quiet -ign_eof` over
//! the same LD_PRELOAD path works fine for h1. Real LAN clients
//! using kernel sockets aren't affected — this is a curl ↔
//! libvppcom recv/select quirk, not a server bug.
//!
//! `acl` / `ctx` are `ArcSwap`-backed for hot-config reload (see
//! tcp.rs and udp.rs for the pattern). The ACL is checked at TCP
//! accept time AND on every HTTP request (since axum routes after
//! the per-connection handshake) so a SIGHUP that drops a CIDR
//! takes effect on the next request even on already-open
//! connections.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::Request;
use hyper::server::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Deserialize;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use crate::handler::{AclSwap, CtxSwap, SharedHandler};
use crate::io::transport::{DnsTcpListener, ReactorCtx};
use crate::metrics::Metrics;

#[derive(Clone)]
struct AppState {
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    ctx: CtxSwap,
    acl: AclSwap,
    peer: std::net::IpAddr,
}

pub struct DohListener;

impl DohListener {
    pub async fn spawn(
        bind: SocketAddr,
        reactor: ReactorCtx,
        handler: SharedHandler,
        metrics: Arc<Metrics>,
        tls_config: Arc<rustls::ServerConfig>,
        acl: AclSwap,
        ctx: CtxSwap,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let listener = DnsTcpListener::bind(bind, reactor.clone())
            .with_context(|| format!("DoH bind {bind}"))?;
        let acceptor = TlsAcceptor::from(tls_config);
        {
            let snap = ctx.load();
            tracing::info!(listener = %snap.name, addr = %bind, dns64 = snap.dns64, "DoH listener up");
        }

        let handle = tokio::spawn(async move {
            accept_loop(listener, acceptor, acl, handler, metrics, ctx).await;
        });
        Ok(handle)
    }
}

async fn accept_loop(
    listener: DnsTcpListener,
    acceptor: TlsAcceptor,
    acl: AclSwap,
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    ctx: CtxSwap,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(listener = %ctx.load().name, "DoH accept: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        if !acl.load().allows(peer.ip()) {
            metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%peer, listener = %ctx.load().name, "DoH: ACL denied pre-handshake");
            drop(stream);
            continue;
        }

        let handler = handler.clone();
        let metrics = metrics.clone();
        let acl = acl.clone();
        let ctx = ctx.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    // Read the TLS-negotiated ALPN before handing the
                    // stream to hyper. `get_ref().1` is the inner
                    // rustls ServerConnection; its `alpn_protocol()`
                    // returns the bytes we advertised in
                    // ServerConfig.alpn_protocols that the client
                    // accepted. None means the client didn't speak
                    // ALPN at all (kdig-style minimal client) — fall
                    // back to http/1.1.
                    let alpn = tls_stream
                        .get_ref()
                        .1
                        .alpn_protocol()
                        .map(|b| b.to_vec());
                    let alpn_display = alpn
                        .as_deref()
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                        .unwrap_or_else(|| "(none)".into());
                    // info-level so it shows up in journalctl by
                    // default; debugging the real-network DoH
                    // hang depends on seeing this per connection.
                    tracing::info!(
                        %peer,
                        alpn = %alpn_display,
                        "DoH TLS handshake complete, dispatching",
                    );

                    let state = AppState {
                        handler,
                        metrics,
                        ctx,
                        acl,
                        peer: peer.ip(),
                    };
                    let app = Router::new()
                        .route("/dns-query", get(handle_get))
                        .route("/dns-query", post(handle_post))
                        .with_state(state);
                    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let mut svc = app.clone();
                        async move { svc.call(req).await }
                    });
                    // Wrap the TLS stream in tokio's BufStream
                    // before handing it to hyper. Two reasons:
                    //
                    // 1. Reads — BufStream coalesces small `poll_read`
                    //    calls (hyper's HTTP/1 parser reads request
                    //    line, then headers, then body in separate
                    //    operations). Under VCL/libvppcom the per-
                    //    poll-read wakeup machinery has only been
                    //    proven for one-shot reads (DoT works with
                    //    `read_exact`); the multi-step pattern hyper
                    //    uses against the bare TlsStream lost the
                    //    request on the real-network path. Buffering
                    //    keeps the wakeup count to one per arriving
                    //    chunk and lets hyper drain a full request
                    //    in one go.
                    // 2. Writes — same coalescing on the way out:
                    //    hyper writes headers then body as separate
                    //    operations, which produces two TLS records
                    //    and (more importantly) two VCL writes; the
                    //    second one was visible-on-the-wire-as-
                    //    missing in pcap before the buffer.
                    //
                    // 8 KiB each way is enough for any sane DoH
                    // request and a typical DNS reply, which run
                    // hundreds of bytes max.
                    let buffered = tokio::io::BufStream::with_capacity(
                        8192, 8192, tls_stream,
                    );
                    let io = TokioIo::new(buffered);

                    let result = match alpn.as_deref() {
                        Some(b"h2") => {
                            http2::Builder::new(TokioExecutor::new())
                                .serve_connection(io, service)
                                .await
                                .map_err(|e| anyhow::anyhow!(e))
                        }
                        // Default to HTTP/1.1: explicit "http/1.1"
                        // ALPN, no ALPN at all (kdig-style), or any
                        // unknown ALPN we shouldn't try to speak h2
                        // on (e.g. acme-tls/1 — the rustls-acme
                        // resolver serves the challenge cert *and*
                        // closes the connection after the
                        // handshake; serve_connection will return
                        // Ok immediately).
                        _ => http1::Builder::new()
                            .serve_connection(io, service)
                            .await
                            .map_err(|e| anyhow::anyhow!(e)),
                    };
                    match &result {
                        Ok(_) => tracing::info!(
                            %peer,
                            alpn = %alpn_display,
                            "DoH conn done",
                        ),
                        Err(e) => {
                            // {:#} on anyhow::Error walks the
                            // source chain — hyper's top-level
                            // Display is often just "connection
                            // error", with the actual io::Error /
                            // parse error one or two `source()`
                            // levels down.
                            tracing::warn!(
                                %peer,
                                alpn = %alpn_display,
                                "DoH serve error: {e:#}",
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(%peer, "DoH TLS handshake: {e}");
                }
            }
        });
    }
}

#[derive(Deserialize)]
struct DnsQuery {
    dns: String,
}

async fn handle_get(
    State(state): State<AppState>,
    Query(q): Query<DnsQuery>,
) -> Response {
    tracing::info!(peer = %state.peer, dns_len = q.dns.len(), "DoH GET /dns-query");
    if !state.acl.load().allows(state.peer) {
        state.metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
        return (StatusCode::FORBIDDEN, "ACL").into_response();
    }
    state.metrics.queries_doh.fetch_add(1, Ordering::Relaxed);
    let wire = match BASE64_URL_SAFE_NO_PAD.decode(q.dns.as_bytes()) {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid dns= parameter").into_response()
        }
    };
    dispatch(state, wire).await
}

async fn handle_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    tracing::info!(peer = %state.peer, body_len = body.len(), "DoH POST /dns-query");
    if !state.acl.load().allows(state.peer) {
        state.metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
        return (StatusCode::FORBIDDEN, "ACL").into_response();
    }
    state.metrics.queries_doh.fetch_add(1, Ordering::Relaxed);
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        != "application/dns-message"
    {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected application/dns-message",
        )
            .into_response();
    }
    dispatch(state, body.to_vec()).await
}

async fn dispatch(state: AppState, wire: Vec<u8>) -> Response {
    let ctx_snap = state.ctx.load_full();
    let Some(response) = state.handler.handle_bytes(&wire, state.peer, &ctx_snap).await else {
        return (StatusCode::BAD_REQUEST, "malformed DNS query").into_response();
    };
    let ttl = min_ttl_from_response(&response).unwrap_or(0);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/dns-message".parse().unwrap(),
    );
    if ttl > 0 {
        headers.insert(
            header::CACHE_CONTROL,
            format!("max-age={ttl}").parse().unwrap(),
        );
    }
    (StatusCode::OK, headers, response).into_response()
}

/// Inspect the answer section just enough to extract the minimum TTL
/// for the Cache-Control header. Re-parsing is cheap at DoH rates;
/// we don't need the parsed response for anything else so drop it.
fn min_ttl_from_response(bytes: &[u8]) -> Option<u32> {
    use hickory_proto::op::Message;
    use hickory_proto::serialize::binary::BinDecodable;
    let msg = Message::from_bytes(bytes).ok()?;
    msg.answers.iter().map(|r| r.ttl).min()
}

#[allow(dead_code)]
fn drop_io_error(e: io::Error) -> anyhow::Error {
    anyhow::anyhow!(e)
}
