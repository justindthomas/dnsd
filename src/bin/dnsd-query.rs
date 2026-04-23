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
    let args = Args::parse();
    let req = match args.cmd {
        Cmd::Stats => ControlRequest::Stats,
        Cmd::Forwarders => ControlRequest::Forwarders,
        Cmd::Reload => ControlRequest::Reload,
        Cmd::Cache { op, name, rrtype } => ControlRequest::Cache { op, name, rrtype },
        Cmd::Upstream { name } => ControlRequest::Upstream { name },
    };
    let resp = send_request(&args.socket, &req).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}
