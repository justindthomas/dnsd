//! Minimal SOCKS5 client (RFC 1928) — the dnsd→tord half of the
//! `via: tor` forwarder path.
//!
//! Given a stream already connected to a SOCKS5 proxy (tord),
//! `connect()` runs the handshake and issues a `CONNECT` to the
//! target; on `Ok` the stream is the tunnel to that target.
//!
//! `CONNECT` only — DoT-over-Tor needs nothing else. Auth: `NO AUTH`,
//! or username/password (RFC 1929) when a username is given. tord
//! treats the username as a circuit-isolation token, not a
//! credential, so the password is always sent empty.
//!
//! Wired into the forwarder by phase 4 (see DESIGN-tor-forwarder.md).
#![allow(dead_code)] // `connect` is exercised by tests; phase 4 wires it for real.

use std::net::{IpAddr, SocketAddr};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VER: u8 = 0x05;
const M_NOAUTH: u8 = 0x00;
const M_USERPASS: u8 = 0x02;
const M_NONE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// Run a SOCKS5 `CONNECT` handshake over `stream` to `target`.
///
/// When `username` is `Some`, RFC 1929 username/password auth is
/// offered (password empty — tord uses the username as a circuit-
/// isolation token). On `Ok` the stream carries the tunnelled
/// connection to `target`.
pub async fn connect<S>(stream: &mut S, target: SocketAddr, username: Option<&str>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // --- method negotiation (RFC 1928 §3) ---
    if let Some(user) = username {
        stream
            .write_all(&[VER, 2, M_NOAUTH, M_USERPASS])
            .await
            .context("socks5: send greeting")?;
        let mut sel = [0u8; 2];
        stream
            .read_exact(&mut sel)
            .await
            .context("socks5: read method selection")?;
        if sel[0] != VER {
            bail!("socks5: bad version {:#04x} in method reply", sel[0]);
        }
        match sel[1] {
            M_NOAUTH => {}
            M_USERPASS => userpass_auth(stream, user).await?,
            M_NONE => bail!("socks5: proxy rejected all offered auth methods"),
            other => bail!("socks5: proxy selected unknown auth method {other:#04x}"),
        }
    } else {
        stream
            .write_all(&[VER, 1, M_NOAUTH])
            .await
            .context("socks5: send greeting")?;
        let mut sel = [0u8; 2];
        stream
            .read_exact(&mut sel)
            .await
            .context("socks5: read method selection")?;
        if sel[0] != VER || sel[1] != M_NOAUTH {
            bail!(
                "socks5: proxy did not accept NO-AUTH (got {:#04x} {:#04x})",
                sel[0],
                sel[1]
            );
        }
    }

    // --- CONNECT request (RFC 1928 §4) ---
    let mut req = vec![VER, CMD_CONNECT, 0x00];
    match target.ip() {
        IpAddr::V4(v4) => {
            req.push(ATYP_V4);
            req.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            req.push(ATYP_V6);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&req)
        .await
        .context("socks5: send CONNECT request")?;

    // --- CONNECT reply ---
    let mut head = [0u8; 4]; // VER, REP, RSV, ATYP
    stream
        .read_exact(&mut head)
        .await
        .context("socks5: read CONNECT reply")?;
    if head[0] != VER {
        bail!("socks5: bad version {:#04x} in CONNECT reply", head[0]);
    }
    if head[1] != 0x00 {
        bail!(
            "socks5: CONNECT to {target} failed — {}",
            reply_error(head[1])
        );
    }
    // Drain BND.ADDR + BND.PORT so the stream is positioned exactly
    // at the start of the tunnelled data.
    let bnd_len = match head[3] {
        ATYP_V4 => 4,
        ATYP_V6 => 16,
        ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            stream
                .read_exact(&mut l)
                .await
                .context("socks5: read BND.ADDR length")?;
            l[0] as usize
        }
        other => bail!("socks5: CONNECT reply has unknown ATYP {other:#04x}"),
    };
    let mut drain = vec![0u8; bnd_len + 2];
    stream
        .read_exact(&mut drain)
        .await
        .context("socks5: drain BND.ADDR")?;
    Ok(())
}

/// RFC 1929 username/password sub-negotiation. The password is sent
/// empty — tord accepts any credentials and keys circuit isolation on
/// the username alone.
async fn userpass_auth<S>(stream: &mut S, username: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let user = username.as_bytes();
    if user.len() > 255 {
        bail!("socks5: username too long ({} bytes, max 255)", user.len());
    }
    let mut msg = vec![0x01, user.len() as u8];
    msg.extend_from_slice(user);
    msg.push(0); // PLEN = 0 — empty password
    stream
        .write_all(&msg)
        .await
        .context("socks5: send username/password")?;
    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .await
        .context("socks5: read auth reply")?;
    if reply[0] != 0x01 {
        bail!("socks5: bad username/password auth version {:#04x}", reply[0]);
    }
    if reply[1] != 0x00 {
        bail!("socks5: proxy rejected username/password auth");
    }
    Ok(())
}

fn reply_error(rep: u8) -> &'static str {
    match rep {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown SOCKS error code",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A `tokio::io::duplex` pair stands in for the dnsd↔tord stream:
    // one half is driven as a stub SOCKS5 server, the other is handed
    // to `connect()`.

    #[tokio::test]
    async fn noauth_connect_ok() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let srv = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [VER, 1, M_NOAUTH]);
            server.write_all(&[VER, M_NOAUTH]).await.unwrap();

            let mut req = [0u8; 10]; // VER CMD RSV ATYP + v4(4) + port(2)
            server.read_exact(&mut req).await.unwrap();
            assert_eq!(&req[..4], &[VER, CMD_CONNECT, 0x00, ATYP_V4]);
            assert_eq!(&req[8..], &[0x03, 0x55]); // port 853

            // success, BND 0.0.0.0:0
            server
                .write_all(&[VER, 0x00, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        connect(&mut client, "9.9.9.9:853".parse().unwrap(), None)
            .await
            .unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn userpass_connect_ok() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let srv = tokio::spawn(async move {
            let mut greeting = [0u8; 4];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [VER, 2, M_NOAUTH, M_USERPASS]);
            server.write_all(&[VER, M_USERPASS]).await.unwrap();

            // RFC 1929: VER ULEN UNAME PLEN PASSWD
            let mut hdr = [0u8; 2];
            server.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], 0x01);
            let mut uname = vec![0u8; hdr[1] as usize];
            server.read_exact(&mut uname).await.unwrap();
            assert_eq!(&uname, b"cust-a");
            let mut plen = [0u8; 1];
            server.read_exact(&mut plen).await.unwrap();
            assert_eq!(plen[0], 0);
            server.write_all(&[0x01, 0x00]).await.unwrap();

            let mut req = [0u8; 10];
            server.read_exact(&mut req).await.unwrap();
            server
                .write_all(&[VER, 0x00, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        connect(&mut client, "9.9.9.9:853".parse().unwrap(), Some("cust-a"))
            .await
            .unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn connect_failure_is_an_error() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let srv = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[VER, M_NOAUTH]).await.unwrap();
            let mut req = [0u8; 10];
            server.read_exact(&mut req).await.unwrap();
            // REP 0x05 — connection refused.
            server
                .write_all(&[VER, 0x05, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let err = connect(&mut client, "9.9.9.9:853".parse().unwrap(), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("connection refused"), "got: {err}");
        srv.await.unwrap();
    }
}
