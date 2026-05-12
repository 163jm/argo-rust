mod config;
mod edge;
mod ingress;
mod origin;
mod proxy;
mod rpc;
mod tunnel;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "mini-cloudflared",
    version = "0.3.0",
    about = "Minimal Cloudflare Tunnel client – routes configured in Cloudflare dashboard"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to Cloudflare using a tunnel token (routes from dashboard)
    Tunnel {
        /// Tunnel token from Cloudflare dashboard → Networks → Tunnels → your tunnel → Token
        #[arg(short, long, env = "TUNNEL_TOKEN")]
        token: String,
    },

    /// Start a local TCP reverse proxy (optional helper)
    Proxy {
        #[arg(short, long, default_value = "8080")]
        port: u16,
        #[arg(short, long)]
        target: String,
    },

    /// Show version and protocol info
    Info,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("mini_cloudflared=debug,info")),
        )
        .init();

    match Cli::parse().command {
        Commands::Tunnel { token } => {
            tunnel::run_tunnel(config::TunnelConfig {
                token,
                quick_tunnel: false,
            })
            .await?;
        }
        Commands::Proxy { port, target } => {
            proxy::run_proxy(port, target).await?;
        }
        Commands::Info => {
            println!("mini-cloudflared v0.3.0");
            println!("Protocol : HTTP/2 over TLS (port 7844)");
            println!("Edge SNI : h2.cftunnel.com");
            println!("Edge DNS : region1.v2.argotunnel.com");
            println!("Routes   : fetched from Cloudflare API, refreshed every 30s");
            println!();
            println!("Usage:");
            println!("  mini-cloudflared tunnel --token <TOKEN>");
            println!("  TUNNEL_TOKEN=<TOKEN> mini-cloudflared tunnel");
            println!();
            println!("Routes are configured in:");
            println!("  Cloudflare dashboard → Zero Trust → Networks → Tunnels");
            println!("  → your tunnel → Public Hostname tab");
        }
    }

    Ok(())
}
