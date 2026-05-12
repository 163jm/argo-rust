//! Edge discovery – resolve Cloudflare edge IPs via DNS SRV + A records

use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};
use tokio::net::lookup_host;
use tracing::debug;

/// Cloudflare edge hostnames for region1
const EDGE_HOSTS: &[&str] = &[
    "region1.v2.argotunnel.com",
    "region2.v2.argotunnel.com",
];
/// Port used by HTTP/2 tunnel transport
pub const EDGE_PORT: u16 = 7844;
/// TLS SNI for the edge (HTTP/2 protocol)
pub const EDGE_SNI: &str = "h2.cftunnel.com";

/// Resolve edge IPs via DNS A record lookup
pub async fn resolve_edge_addrs() -> Result<Vec<SocketAddr>> {
    let mut addrs = Vec::new();

    for host in EDGE_HOSTS {
        match lookup_host(format!("{}:{}", host, EDGE_PORT)).await {
            Ok(resolved) => {
                for addr in resolved {
                    debug!("Edge addr: {}", addr);
                    addrs.push(addr);
                }
                if !addrs.is_empty() {
                    break; // got enough from first region
                }
            }
            Err(e) => {
                debug!("DNS lookup failed for {}: {}", host, e);
            }
        }
    }

    if addrs.is_empty() {
        // Fallback to known stable Cloudflare edge IPs
        let fallback: &[&str] = &[
            "198.41.192.167",
            "198.41.192.67",
            "198.41.192.57",
            "198.41.200.13",
        ];
        for ip in fallback {
            let ip: IpAddr = ip.parse()?;
            addrs.push(SocketAddr::new(ip, EDGE_PORT));
        }
    }

    // Shuffle for load distribution
    use rand::seq::SliceRandom;
    addrs.shuffle(&mut rand::thread_rng());

    Ok(addrs)
}
