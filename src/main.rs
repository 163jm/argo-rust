mod config;
mod edge;
mod origin;
mod protocol;
mod proxy;
mod rpc;
mod tunnel;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "mini-cloudflared",
    version = "0.2.0",
    about = "Minimal Cloudflare Tunnel client (HTTP/2 protocol)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Expose a local service through Cloudflare Tunnel
    Tunnel {
        /// Local service URL (e.g. http://localhost:8080)
        #[arg(short, long)]
        url: String,

        /// Cloudflare Tunnel token (from dashboard → Tunnels → your tunnel → Token)
        #[arg(short, long, env = "TUNNEL_TOKEN")]
        token: Option<String>,

        /// Quick tunnel – no account needed, gets a *.trycloudflare.com URL
        #[arg(long)]
        quick: bool,
    },

    /// Start a local TCP reverse proxy
    Proxy {
        #[arg(short, long, default_value = "8080")]
        port: u16,
        #[arg(short, long)]
        target: String,
    },

    /// Print version and protocol info
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

    let cli = Cli::parse();

    match cli.command {
        Commands::Tunnel { url, token, quick } => {
            tunnel::run_tunnel(config::TunnelConfig {
                local_url: url,
                token,
                quick_tunnel: quick,
                hostname: None,
            })
            .await?;
        }
        Commands::Proxy { port, target } => {
            proxy::run_proxy(port, target).await?;
        }
        Commands::Info => {
            println!("mini-cloudflared v0.2.0");
            println!("Protocol : HTTP/2 over TLS (port 7844)");
            println!("Edge SNI : h2.cftunnel.com");
            println!("Edge DNS : region1.v2.argotunnel.com");
            println!();
            println!("Usage:");
            println!("  # Named tunnel (token from Cloudflare dashboard)");
            println!("  mini-cloudflared tunnel --token <TOKEN> --url http://localhost:8080");
            println!();
            println!("  # Quick tunnel (temporary *.trycloudflare.com hostname)");
            println!("  mini-cloudflared tunnel --quick --url http://localhost:8080");
            println!();
            println!("  # Local reverse proxy");
            println!("  mini-cloudflared proxy --port 8080 --target http://localhost:3000");
        }
    }

    Ok(())
}
