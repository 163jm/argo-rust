mod config;
mod edge;
mod ingress;
mod origin;
mod proxy;
mod rpc;
mod tunnel;

use std::path::PathBuf;
use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "mini-cloudflared", version = "0.4.0",
    about = "Minimal Cloudflare Tunnel client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to Cloudflare using a tunnel token
    Tunnel {
        /// Tunnel token (from Cloudflare dashboard → Networks → Tunnels → Token)
        #[arg(short, long, env = "TUNNEL_TOKEN")]
        token: String,

        /// Path to ingress config file (default: ~/.cloudflared/config.yaml)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Start a local TCP reverse proxy
    Proxy {
        #[arg(short, long, default_value = "8080")]
        port: u16,
        #[arg(short, long)]
        target: String,
    },

    /// Show version and usage info
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
        Commands::Tunnel { token, config } => {
            tunnel::run_tunnel(config::TunnelConfig {
                token,
                quick_tunnel: false,
                config_file: config,
            }).await?;
        }
        Commands::Proxy { port, target } => {
            proxy::run_proxy(port, target).await?;
        }
        Commands::Info => {
            println!("mini-cloudflared v0.4.0\n");
            println!("Usage:");
            println!("  mini-cloudflared tunnel --token <TOKEN>");
            println!("  mini-cloudflared tunnel --token <TOKEN> --config /path/to/config.yaml");
            println!("  TUNNEL_TOKEN=<TOKEN> mini-cloudflared tunnel\n");
            println!("Config file (~/.cloudflared/config.yaml):");
            println!("  ingress:");
            println!("    - hostname: example.com");
            println!("      service: http://localhost:8080");
            println!("    - hostname: api.example.com");
            println!("      service: http://localhost:3000");
            println!("    - service: http_status:404   # catch-all required");
        }
    }
    Ok(())
}
