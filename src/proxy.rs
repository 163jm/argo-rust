//! Standalone local HTTP reverse proxy
//!
//! Listens on a local port and forwards all traffic to a target URL.
//! Useful for local development and testing without a tunnel.

use std::convert::Infallible;
use std::net::SocketAddr;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

pub async fn run_proxy(port: u16, target: String) -> Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let listener = TcpListener::bind(addr).await?;

    info!("Local proxy listening on http://0.0.0.0:{}", port);
    info!("Forwarding → {}", target);
    info!("Press Ctrl+C to stop\n");

    loop {
        let (stream, peer) = listener.accept().await?;
        let target = target.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer, &target).await {
                error!("Proxy error from {}: {}", peer, e);
            }
        });
    }
}

async fn handle_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    target: &str,
) -> Result<()> {
    // Read the incoming HTTP request
    let mut buf = vec![0u8; 65536];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let raw_request = &buf[..n];

    // Parse the first line for logging
    let first_line = String::from_utf8_lossy(raw_request)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    tracing::debug!("{} → {}", peer, first_line);

    // Connect to target
    let (target_host, target_port) = parse_target(target)?;
    let mut upstream = TcpStream::connect(format!("{}:{}", target_host, target_port)).await?;

    // Rewrite the Host header
    let rewritten = rewrite_host(raw_request, &target_host, target_port);
    upstream.write_all(&rewritten).await?;

    // Bidirectional copy
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = upstream.split();

    let client_to_upstream = tokio::io::copy(&mut cr, &mut uw);
    let upstream_to_client = tokio::io::copy(&mut ur, &mut cw);

    tokio::select! {
        res = client_to_upstream => { res?; }
        res = upstream_to_client => { res?; }
    }

    Ok(())
}

/// Rewrite the Host header in a raw HTTP request
fn rewrite_host(request: &[u8], new_host: &str, port: u16) -> Vec<u8> {
    let s = String::from_utf8_lossy(request);
    let new_host_header = if port == 80 || port == 443 {
        format!("Host: {}", new_host)
    } else {
        format!("Host: {}:{}", new_host, port)
    };

    let rewritten = s
        .lines()
        .map(|line| {
            if line.to_ascii_lowercase().starts_with("host:") {
                new_host_header.clone()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n");

    // Ensure proper CRLF line endings
    rewritten.into_bytes()
}

/// Parse "http://host:port" → (host, port)
fn parse_target(target: &str) -> Result<(String, u16)> {
    let parsed = url::Url::parse(target)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("No host in target URL"))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine port for target URL"))?;
    Ok((host, port))
}
