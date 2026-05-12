mod tunnel;
mod proxy;
mod protocol;
mod config;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "mini-cloudflared", version = "0.1.0", about = "Minimal Cloudflare Tunnel client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a tunnel to expose a local service
    Tunnel {
        #[arg(short, long)]
        url: String,
        #[arg(short, long, env = "TUNNEL_TOKEN")]
        token: Option<String>,
        #[arg(long, default_value = "false")]
        quick: bool,
        #[arg(long)]
        hostname: Option<String>,
    },
    /// Start a local HTTP reverse proxy
    Proxy {
        #[arg(short, long, default_value = "8080")]
        port: u16,
        #[arg(short, long)]
        target: String,
    },
    /// Show version and info
    Info,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Tunnel { url, token, quick, hostname } => {
            let cfg = config::TunnelConfig { local_url: url, token, quick_tunnel: quick, hostname };
            tunnel::run_tunnel(cfg).await?;
        }
        Commands::Proxy { port, target } => {
            proxy::run_proxy(port, target).await?;
        }
        Commands::Info => {
            println!("mini-cloudflared v0.1.0");
            println!("A minimal Cloudflare Tunnel client written in Rust\n");
            println!("Supported modes:");
            println!("  tunnel --quick --url http://localhost:8080");
            println!("  tunnel --url http://localhost:8080 --token <TOKEN>");
            println!("  proxy  --port 8080 --target http://localhost:3000");
        }
    }
    Ok(())
}
