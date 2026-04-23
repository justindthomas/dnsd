//! DNS-over-HTTPS (RFC 8484) listener.
//!
//! `VclListener` accepts TCP/443 through VPP. Each connection is
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
//! Today only HTTP/1.1 is handled (hyper::server::conn::http1). HTTP/2
//! over axum-rustls needs a bit more plumbing (hyper::server::conn::
//! http2::Builder + GracefulShutdown) and will follow up.

use std::io;
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
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use vcl_rs::{VclListener, VclReactor};

use crate::acl::ClientAcl;
use crate::config::Listener;
use crate::handler::{ListenerContext, SharedHandler};
use crate::metrics::Metrics;

#[derive(Clone)]
struct AppState {
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    ctx: Arc<ListenerContext>,
    peer: std::net::IpAddr,
}

pub struct DohListener;

impl DohListener {
    pub async fn spawn(
        listener_cfg: Listener,
        reactor: VclReactor,
        handler: SharedHandler,
        metrics: Arc<Metrics>,
        tls_config: Arc<rustls::ServerConfig>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let bind = std::net::SocketAddr::new(listener_cfg.address, listener_cfg.port);
        let listener = VclListener::bind(bind, reactor.clone())
            .with_context(|| format!("DoH bind {bind}"))?;
        let acl = Arc::new(ClientAcl::new(listener_cfg.allow_from.clone()));
        let ctx = Arc::new(ListenerContext::new(&listener_cfg.name, listener_cfg.dns64));
        let acceptor = TlsAcceptor::from(tls_config);
        tracing::info!(listener = %listener_cfg.name, addr = %bind, dns64 = ctx.dns64, "DoH listener up");

        let handle = tokio::spawn(async move {
            accept_loop(listener, acceptor, acl, handler, metrics, ctx).await;
        });
        Ok(handle)
    }
}

async fn accept_loop(
    listener: VclListener,
    acceptor: TlsAcceptor,
    acl: Arc<ClientAcl>,
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    ctx: Arc<ListenerContext>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(listener = %ctx.name, "DoH accept: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        if !acl.allows(peer.ip()) {
            metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
            drop(stream);
            continue;
        }

        let handler = handler.clone();
        let metrics = metrics.clone();
        let ctx = ctx.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let state = AppState {
                        handler,
                        metrics,
                        ctx: ctx.clone(),
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
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        tracing::debug!(listener = %ctx.name, %peer, "DoH serve: {e}");
                    }
                }
                Err(e) => {
                    tracing::debug!(listener = %ctx.name, %peer, "DoH TLS handshake: {e}");
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
    let Some(response) = state.handler.handle_bytes(&wire, state.peer, &state.ctx).await else {
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
    msg.answers().iter().map(|r| r.ttl()).min()
}

#[allow(dead_code)]
fn drop_io_error(e: io::Error) -> anyhow::Error {
    anyhow::anyhow!(e)
}
