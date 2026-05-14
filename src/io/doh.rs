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
//! Protocol selection is driven by ALPN: hyper-util's auto Builder
//! reads the negotiated ALPN off the TLS handshake and dispatches
//! to its http1 or http2 path. Most DoH clients (Firefox, curl,
//! dns-over-https libraries) negotiate h2 by default — h1.1 stays
//! available for kdig, simple shell clients, and anyone behind a
//! middlebox that strips ALPN.
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
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
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
                    let io = TokioIo::new(tls_stream);
                    // ALPN-driven HTTP/1.1 vs HTTP/2 selection. The
                    // auto Builder peeks at the negotiated ALPN and
                    // hands off to the matching hyper protocol path.
                    if let Err(e) = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await
                    {
                        tracing::debug!(%peer, "DoH serve: {e}");
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
