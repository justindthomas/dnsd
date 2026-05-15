//! DNS-over-HTTPS (RFC 8484) listener.
//!
//! TLS via tokio-rustls, then a *minimal* HTTP/1.1 parser written
//! against the same `read_exact` / `write_all` primitives that the
//! DoT listener uses. There's no hyper, no axum. We tried both:
//! under VCL/libvppcom the hyper read pattern wedges (request bytes
//! arrive at TCP, server ACKs them, but `poll_read` returns Pending
//! and never wakes — DoT works on the same substrate because its
//! `read_exact` calls happen to retrieve the buffered plaintext
//! while hyper's multi-step parser does not). Re-implementing a
//! shaped-by-RFC-8484 subset of HTTP/1.1 is ~120 lines and behaves
//! exactly like DoT's framing loop, so we get the same proven
//! wakeup behavior.
//!
//! Supported HTTP shape:
//!
//!   GET  /dns-query?dns=<base64url-wire>
//!   POST /dns-query        body=application/dns-message
//!
//! Response content-type is always `application/dns-message`; the
//! upstream cache's TTL feeds into `Cache-Control: max-age=<ttl>`.
//!
//! ALPN advertises `h2` and `http/1.1`. We only serve HTTP/1.1
//! today — if a client negotiates h2 we close the connection
//! cleanly (clients fall back to h1 on the next attempt). HTTP/2
//! support is a follow-up; it'd require a frame-level parser of
//! similar shape.
//!
//! `acl` / `ctx` are `ArcSwap`-backed for hot-config reload (see
//! tcp.rs and udp.rs for the pattern). The ACL is checked once at
//! TCP accept time AND on every HTTP request, so a SIGHUP that
//! drops a CIDR takes effect on the next request.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use crate::handler::{AclSwap, CtxSwap, SharedHandler};
use crate::io::transport::{DnsTcpListener, ReactorCtx};
use crate::metrics::Metrics;

/// Max bytes we'll consume looking for the end of HTTP headers.
/// DoH requests are tiny (small base64url GET query string, or a
/// few-hundred-byte POST body); cap to avoid a misbehaving client
/// pinning a coroutine on us with a slow header drip.
const MAX_HEADER_BYTES: usize = 8192;
/// Max POST body size we'll accept. DNS message wire format caps
/// at 65535 for TCP-style framing; UDP rarely exceeds 1232 with
/// EDNS. 65535 is the right cap for parity with the DoT
/// MAX_TCP_MESSAGE.
const MAX_BODY_BYTES: usize = 65535;
/// Hard cap on how long we'll wait for the first request line +
/// headers. Clients that haven't sent within this window are
/// probing / leaking sockets / abandoned half-open connections.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(8);

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
                    // Read the TLS-negotiated ALPN. Three early-exit
                    // paths here:
                    //   - `acme-tls/1`: the tls-alpn-01 challenge.
                    //     rustls-acme's resolver already served the
                    //     challenge cert during the handshake; the
                    //     handshake completion IS the challenge
                    //     response. Close the connection — no
                    //     application data follows. Without this
                    //     branch our HTTP/1.1 parser would try to
                    //     read a request, time out, and the LE
                    //     validator would see a quirky log line.
                    //   - `h2`: defensive branch only — we no longer
                    //     advertise h2 in `acme::*::alpn_protocols`,
                    //     so this is unreachable from a well-behaved
                    //     client. If somehow a client gets here
                    //     (e.g. they upgraded the ALPN out-of-band),
                    //     close cleanly. Browsers and curl do NOT
                    //     retry with h1.1 when the server speaks h2
                    //     then closes — Firefox TRR marks the
                    //     resolver broken, curl errors with HTTP/2
                    //     framing layer. Hence the ALPN omission.
                    //   - Anything else: HTTP/1.1 (or absent ALPN,
                    //     treated as h1.1).
                    let alpn = tls_stream
                        .get_ref()
                        .1
                        .alpn_protocol()
                        .map(|b| b.to_vec());
                    if alpn.as_deref() == Some(b"acme-tls/1") {
                        tracing::info!(
                            %peer,
                            "DoH: acme-tls/1 challenge handshake completed",
                        );
                        return;
                    }
                    if alpn.as_deref() == Some(b"h2") {
                        tracing::debug!(
                            %peer,
                            "DoH: h2 ALPN selected but server only speaks h1.1; closing",
                        );
                        return;
                    }
                    if let Err(e) = serve_one(
                        tls_stream, peer, handler, metrics, acl, ctx,
                    )
                    .await
                    {
                        tracing::debug!(%peer, "DoH: {e:#}");
                    }
                }
                Err(e) => {
                    tracing::debug!(%peer, "DoH TLS handshake: {e}");
                }
            }
        });
    }
}

/// Serve one HTTP/1.1 request, then close. RFC 8484 DoH clients
/// open a new TCP+TLS connection per query in practice (browsers
/// pool but reuse only inside one navigation), and skipping
/// keep-alive lets us mirror DoT's "read_exact then write_all"
/// pattern that the VCL substrate is happy with.
async fn serve_one<S>(
    mut stream: tokio_rustls::server::TlsStream<S>,
    peer: SocketAddr,
    handler: SharedHandler,
    metrics: Arc<Metrics>,
    acl: AclSwap,
    ctx: CtxSwap,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // ---- Read headers (request line + headers, up to \r\n\r\n) ----
    let mut header_buf = Vec::with_capacity(1024);
    let body_in_buf = {
        let end = tokio::time::timeout(
            REQUEST_READ_TIMEOUT,
            read_until_double_crlf(&mut stream, &mut header_buf),
        )
        .await
        .map_err(|_| anyhow!("request header timeout"))??;
        // Anything past the header terminator is the start of the
        // body (matters for POST when body fits in the first read).
        header_buf.split_off(end)
    };

    // header_buf currently holds everything up to and including the
    // \r\n\r\n terminator. Strip the trailing 4-byte terminator so
    // the parser sees a clean sequence of lines with no trailing
    // empty.
    let head_end = header_buf
        .len()
        .checked_sub(4)
        .ok_or_else(|| anyhow!("header buffer shorter than CRLF terminator"))?;
    let (method, path, headers) = parse_request_head(&header_buf[..head_end])
        .context("HTTP/1.1 request head")?;

    // RFC 9112 §6 / PortSwigger "HTTP/1 must die" — strict
    // framing-header validation. Reject the constructs that enable
    // request-smuggling desync (TE, duplicate CL, mixed framing).
    // We're a single-implementation origin so the classic smuggling
    // attack chain doesn't apply directly, but accepting these
    // tokens means our parser is part of a future chain that could
    // be vulnerable. Refuse upfront, no response (closing on
    // malformed input minimises information leakage).
    validate_framing(&headers)?;

    if !acl.load().allows(peer.ip()) {
        metrics.acl_denied.fetch_add(1, Ordering::Relaxed);
        return send_simple(&mut stream, 403, "Forbidden", b"ACL\n").await;
    }

    let wire = match method {
        "GET" => match parse_get_dns_param(path) {
            Some(b) => b,
            None => {
                return send_simple(
                    &mut stream,
                    400,
                    "Bad Request",
                    b"missing or malformed dns= parameter\n",
                )
                .await
            }
        },
        "POST" => {
            if !content_type_is_dns_message(&headers) {
                return send_simple(
                    &mut stream,
                    415,
                    "Unsupported Media Type",
                    b"expected application/dns-message\n",
                )
                .await;
            }
            let content_length = content_length(&headers).ok_or_else(|| {
                anyhow!("DoH POST missing Content-Length")
            })?;
            if content_length > MAX_BODY_BYTES {
                return send_simple(
                    &mut stream,
                    413,
                    "Payload Too Large",
                    b"DoH body cap\n",
                )
                .await;
            }
            let mut body = body_in_buf;
            body.reserve(content_length.saturating_sub(body.len()));
            while body.len() < content_length {
                let mut chunk = vec![0u8; content_length - body.len()];
                let n = stream
                    .read(&mut chunk)
                    .await
                    .context("reading POST body")?;
                if n == 0 {
                    return Err(anyhow!("EOF mid-POST-body"));
                }
                chunk.truncate(n);
                body.extend_from_slice(&chunk);
            }
            body
        }
        // Only GET/POST defined for /dns-query in RFC 8484.
        other => {
            tracing::debug!(%peer, method = %other, "DoH: rejecting non-GET/POST");
            return send_simple(
                &mut stream,
                405,
                "Method Not Allowed",
                b"GET or POST\n",
            )
            .await;
        }
    };

    // Only /dns-query is defined. Anything else is 404.
    let path_only = path.split('?').next().unwrap_or("/");
    if path_only != "/dns-query" {
        return send_simple(&mut stream, 404, "Not Found", b"\n").await;
    }

    metrics.queries_doh.fetch_add(1, Ordering::Relaxed);

    // One info log per served DoH request so the journal shows
    // per-query traffic for operators tracking which clients are
    // actually using the resolver (and which aren't).
    tracing::info!(
        %peer,
        method = %method,
        path = %path.split('?').next().unwrap_or(""),
        wire_bytes = wire.len(),
        "DoH request",
    );

    let ctx_snap = ctx.load_full();
    let Some(response) =
        handler.handle_bytes(&wire, peer.ip(), &ctx_snap).await
    else {
        return send_simple(
            &mut stream,
            400,
            "Bad Request",
            b"malformed DNS query\n",
        )
        .await;
    };
    let ttl = min_ttl_from_response(&response).unwrap_or(0);
    send_dns_response(&mut stream, &response, ttl).await
}

/// Drain bytes from `stream` into `buf` until the `\r\n\r\n` end-
/// of-headers marker is seen. Returns the byte offset of the first
/// byte past the marker — i.e., where the body starts.
async fn read_until_double_crlf<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
) -> Result<usize>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let needle = b"\r\n\r\n";
    let mut tmp = [0u8; 1024];
    let mut search_from = 0usize;
    loop {
        if let Some(pos) = find_subsequence(&buf[search_from..], needle) {
            return Ok(search_from + pos + needle.len());
        }
        // Roll the search window so we never miss a needle that
        // straddles a read boundary.
        search_from = buf.len().saturating_sub(needle.len() - 1);
        if buf.len() >= MAX_HEADER_BYTES {
            return Err(anyhow!(
                "HTTP/1.1 request headers exceeded {MAX_HEADER_BYTES} bytes"
            ));
        }
        let n = stream
            .read(&mut tmp)
            .await
            .context("reading request headers")?;
        if n == 0 {
            return Err(anyhow!("EOF before HTTP/1.1 headers terminated"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn find_subsequence(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parse `METHOD PATH HTTP/1.1\r\n<header-lines>\r\n` into the
/// method (uppercased, ASCII), the raw path (including any
/// query-string), and a `Vec<(name, value)>` of headers. Header
/// names are lowercased for case-insensitive matching downstream.
/// RFC 7230 §3.2.6 token chars — set of bytes valid in HTTP/1.1
/// header names and the request-line method field. Anything else is
/// rejected as malformed.
fn is_token_char(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+'
        | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
}

/// Strict HTTP/1.1 request-line + header-block parser. Rejects:
///
/// - non-UTF-8 bytes anywhere
/// - request line not exactly `METHOD SP PATH SP HTTP/1.1\r\n` (no
///   extra whitespace, no extra tokens, no HTTP/1.0 — we don't
///   support it for DoH and accepting it widens the parsing surface
///   for no useful clients)
/// - method containing non-token bytes
/// - path containing CTL bytes (0x00–0x1F, 0x7F), CR, LF, NUL
/// - obsolete line-folded headers (RFC 7230 §3.2.4 deprecated)
/// - mid-block empty lines (header block ends at the first \r\n\r\n
///   which the caller strips; embedded empties are smuggling
///   shapes)
/// - header name containing non-token bytes (catches e.g. trailing
///   OWS in the name, which would otherwise allow attacks like
///   `Transfer-Encoding : chunked` slipping past a TE-check that
///   looks for the canonical name)
/// - header value containing CR, LF, or NUL (header injection)
fn parse_request_head(
    bytes: &[u8],
) -> Result<(&str, &str, Vec<(String, String)>)> {
    let text = std::str::from_utf8(bytes)
        .context("non-UTF-8 HTTP/1.1 request head")?;
    let mut lines = text.split("\r\n");

    let first = lines.next().ok_or_else(|| anyhow!("empty request head"))?;
    let mut parts = first.split(' ');
    let method = parts.next().ok_or_else(|| anyhow!("no method"))?;
    let path = parts.next().ok_or_else(|| anyhow!("no path"))?;
    let version = parts.next().ok_or_else(|| anyhow!("no HTTP version"))?;
    if parts.next().is_some() {
        return Err(anyhow!("malformed request line: extra tokens"));
    }
    // We only accept HTTP/1.1 — HTTP/1.0 lacks Host/keep-alive
    // semantics we'd otherwise have to special-case, and no real
    // DoH client speaks it.
    if version != "HTTP/1.1" {
        return Err(anyhow!("unsupported HTTP version: {version}"));
    }
    if method.is_empty() || method.bytes().any(|b| !is_token_char(b)) {
        return Err(anyhow!("invalid method: {method:?}"));
    }
    if path.is_empty() || path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(anyhow!("invalid path"));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            // The terminator \r\n\r\n is already stripped before we
            // get here; any empty line in the middle is malformed.
            return Err(anyhow!("empty line in header block"));
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(anyhow!("obsolete line-folded header"));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(anyhow!("header missing colon: {line:?}"));
        };
        // RFC 7230 §3.2.4: "No whitespace is allowed between the
        // header field-name and colon." We enforce that by
        // requiring the name pass the token-char check verbatim,
        // not after trim. Catches `Content-Length : 5` which a
        // permissive parser would normalise to `Content-Length`.
        if name.is_empty() || name.bytes().any(|b| !is_token_char(b)) {
            return Err(anyhow!("invalid header name: {name:?}"));
        }
        // Strip OWS around the value (RFC 7230 §3.2.4 allows it),
        // then forbid CTL bytes in what remains. We don't accept
        // \r or \n in values: header injection.
        let value = value
            .trim_start_matches(|c| c == ' ' || c == '\t')
            .trim_end_matches(|c| c == ' ' || c == '\t');
        if value.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            return Err(anyhow!("CTL char in header value"));
        }
        headers.push((name.to_ascii_lowercase(), value.to_string()));
    }
    Ok((method, path, headers))
}

/// Reject header sets that enable HTTP/1.1 request smuggling.
/// Called after parse_request_head, before any dispatch. Returns
/// Err to close the connection without responding.
fn validate_framing(headers: &[(String, String)]) -> Result<()> {
    // Transfer-Encoding implies chunked / compressed framing we
    // don't support; accepting the header at all is a smuggling
    // shape (CL+TE desync). Reject outright.
    if headers.iter().any(|(k, _)| k == "transfer-encoding") {
        return Err(anyhow!("Transfer-Encoding header not allowed"));
    }
    if headers.iter().any(|(k, _)| k == "trailer") {
        return Err(anyhow!("Trailer header not allowed"));
    }
    // RFC 7230 §3.3.2 allows merging multiple Content-Length
    // headers iff their values are identical, but real-world
    // parsers diverge here and an attacker who can inject a
    // second CL has the desync. Reject any duplication.
    let cl_count = headers.iter().filter(|(k, _)| k == "content-length").count();
    if cl_count > 1 {
        return Err(anyhow!("multiple Content-Length headers"));
    }
    Ok(())
}

fn parse_get_dns_param(path: &str) -> Option<Vec<u8>> {
    let qs = path.split_once('?')?.1;
    for kv in qs.split('&') {
        if let Some(val) = kv.strip_prefix("dns=") {
            return BASE64_URL_SAFE_NO_PAD.decode(val.as_bytes()).ok();
        }
    }
    None
}

/// Strict Content-Length lookup. Returns None for missing OR
/// malformed values; the caller treats "no CL" the same as "bad
/// CL" since POSTs without a usable CL are rejected.
fn content_length(headers: &[(String, String)]) -> Option<usize> {
    let (_, v) = headers.iter().find(|(k, _)| k == "content-length")?;
    // Already OWS-trimmed by parse_request_head. Require ASCII
    // digits only — no leading '+', no embedded whitespace, no
    // hex/octal markers. usize::parse already rejects all of
    // those, but the explicit byte-check guards against future
    // refactors that swap parsers.
    if v.is_empty() || v.bytes().any(|b| !b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

fn content_type_is_dns_message(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .any(|(k, v)| k == "content-type" && v == "application/dns-message")
}

async fn send_simple<S>(
    stream: &mut S,
    status: u16,
    reason: &str,
    body: &[u8],
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(128 + body.len());
    out.extend_from_slice(
        format!(
            "HTTP/1.1 {status} {reason}\r\n\
             content-type: text/plain\r\n\
             content-length: {len}\r\n\
             connection: close\r\n\
             \r\n",
            len = body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(body);
    stream.write_all(&out).await.context("HTTP error write")?;
    stream.flush().await.ok();
    Ok(())
}

async fn send_dns_response<S>(
    stream: &mut S,
    body: &[u8],
    ttl: u32,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let cache_line = if ttl > 0 {
        format!("cache-control: max-age={ttl}\r\n")
    } else {
        String::new()
    };
    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         content-type: application/dns-message\r\n\
         content-length: {len}\r\n\
         {cache_line}\
         connection: close\r\n\
         \r\n",
        len = body.len()
    );
    // Single write_all coalesces headers + body into one VCL
    // write — the same pattern DoT uses on the response side.
    let mut out = Vec::with_capacity(header.len() + body.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(body);
    stream.write_all(&out).await.context("DoH response write")?;
    stream.flush().await.ok();
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// All these tests call `parse_request_head` with the bytes the
    /// caller would pass after stripping the trailing \r\n\r\n
    /// terminator — i.e., no trailing empty line.
    #[test]
    fn parse_basic_get() {
        let raw = b"GET /dns-query?dns=abc HTTP/1.1\r\n\
                    Host: dns.example.com\r\n\
                    Accept: application/dns-message";
        let (method, path, headers) = parse_request_head(raw).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(path, "/dns-query?dns=abc");
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "host");
        assert_eq!(headers[0].1, "dns.example.com");
    }

    #[test]
    fn parse_dns_param_finds_value() {
        // example.com A, base64url
        let path = "/dns-query?dns=q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE";
        let wire = parse_get_dns_param(path).expect("decoded");
        assert!(wire.len() >= 12, "DNS wire too short: {wire:?}");
        // first 2 bytes are txid 0xabcd
        assert_eq!(wire[0], 0xab);
        assert_eq!(wire[1], 0xcd);
    }

    #[test]
    fn parse_dns_param_missing_returns_none() {
        assert!(parse_get_dns_param("/dns-query").is_none());
        assert!(parse_get_dns_param("/dns-query?other=1").is_none());
    }

    #[test]
    fn content_length_lookup() {
        let h = vec![
            ("host".into(), "x".into()),
            ("content-length".into(), "42".into()),
        ];
        assert_eq!(content_length(&h), Some(42));
    }

    // ---- hardening: each of these should be rejected ----

    #[test]
    fn rejects_http_1_0() {
        let raw = b"GET / HTTP/1.0\r\nHost: x";
        assert!(parse_request_head(raw).is_err());
    }

    #[test]
    fn rejects_request_line_extra_tokens() {
        let raw = b"GET / HTTP/1.1 extra\r\nHost: x";
        assert!(parse_request_head(raw).is_err());
    }

    #[test]
    fn rejects_double_space_in_request_line() {
        let raw = b"GET  / HTTP/1.1\r\nHost: x";
        assert!(parse_request_head(raw).is_err());
    }

    #[test]
    fn rejects_obsolete_line_fold() {
        // Header continuation via leading SP — RFC 7230 §3.2.4 deprecated.
        let raw = b"GET / HTTP/1.1\r\nX-Test: a\r\n  b";
        assert!(parse_request_head(raw).is_err());
    }

    #[test]
    fn rejects_whitespace_before_colon() {
        // `Content-Length : 5` — the token-char check on the
        // unmodified name catches the trailing space before the
        // colon.
        let raw = b"GET / HTTP/1.1\r\nContent-Length : 5";
        assert!(parse_request_head(raw).is_err());
    }

    #[test]
    fn rejects_nul_in_header_value() {
        let raw = b"GET / HTTP/1.1\r\nX-Test: a\x00b";
        assert!(parse_request_head(raw).is_err());
    }

    #[test]
    fn rejects_invalid_method_token() {
        let raw = b"GE T / HTTP/1.1\r\nHost: x";
        assert!(parse_request_head(raw).is_err());
    }

    #[test]
    fn validate_framing_rejects_transfer_encoding() {
        let h = vec![
            ("host".into(), "x".into()),
            ("transfer-encoding".into(), "chunked".into()),
        ];
        assert!(validate_framing(&h).is_err());
    }

    #[test]
    fn validate_framing_rejects_trailer() {
        let h = vec![
            ("host".into(), "x".into()),
            ("trailer".into(), "x-checksum".into()),
        ];
        assert!(validate_framing(&h).is_err());
    }

    #[test]
    fn validate_framing_rejects_duplicate_content_length() {
        let h = vec![
            ("host".into(), "x".into()),
            ("content-length".into(), "5".into()),
            ("content-length".into(), "5".into()),
        ];
        assert!(validate_framing(&h).is_err());
    }

    #[test]
    fn validate_framing_accepts_normal_headers() {
        let h = vec![
            ("host".into(), "dns.example.com".into()),
            ("content-length".into(), "42".into()),
            ("content-type".into(), "application/dns-message".into()),
        ];
        assert!(validate_framing(&h).is_ok());
    }

    #[test]
    fn content_length_rejects_garbage() {
        let cases = ["", "+5", "-1", "5x", " 5", "5 ", "0x10", "FF"];
        for c in cases {
            let h = vec![("content-length".into(), c.to_string())];
            assert!(
                content_length(&h).is_none(),
                "should reject Content-Length={c:?}"
            );
        }
    }
}
