//! Thin CLI wrapper around the control socket. Mirrors
//! `imp-bgpd query ...` / `imp-ospfd query ...`.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use dnsd::control::{send_request, ControlRequest, DEFAULT_SOCKET};

#[derive(Parser, Debug)]
#[command(name = "imp-dnsd-query", about = "Query the running imp-dnsd daemon")]
struct Args {
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Counter snapshot.
    Stats,
    /// Configured forwarders + live RTT (once health checks land).
    Forwarders,
    /// Currently-bound listeners (post-reload diff).
    Listeners,
    /// TLS materials in effect for DoT/DoH (cert source, subject,
    /// not-after, SAN, ALPN).
    Tls,
    /// SIGHUP-equivalent reconfigure.
    Reload,
    /// Cache stats / flush / dump.
    Cache {
        #[arg(long)]
        op: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        rrtype: Option<String>,
    },
    /// Trace the resolver's path for a name.
    Upstream { name: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Rust's default startup sets SIGPIPE to SIG_IGN so that writes
    // to a closed pipe return EPIPE rather than killing the process.
    // For a CLI, that turns `imp-dnsd-query stats | head` into a
    // noisy panic ("failed printing to stdout: Broken pipe") — the
    // panic backtrace clobbers the JSON the user actually saw.
    // Restore SIG_DFL so we exit silently on EPIPE, matching standard
    // Unix CLI behavior.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let args = Args::parse();
    let req = match args.cmd {
        Cmd::Stats => ControlRequest::Stats,
        Cmd::Forwarders => ControlRequest::Forwarders,
        Cmd::Listeners => ControlRequest::Listeners,
        Cmd::Tls => ControlRequest::Tls,
        Cmd::Reload => ControlRequest::Reload,
        Cmd::Cache { op, name, rrtype } => ControlRequest::Cache { op, name, rrtype },
        Cmd::Upstream { name } => ControlRequest::Upstream { name },
    };
    let resp = send_request(&args.socket, &req).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}
