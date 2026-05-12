//! Standalone local reverse proxy (optional helper mode)

use anyhow::Result;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

pub async fn run_proxy(port: u16, target: String) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Proxy listening on http://0.0.0.0:{} → {}", port, target);
    info!("Press Ctrl+C to stop\n");

    loop {
        let (client, peer) = listener.accept().await?;
        let target = target.clone();
        tokio::spawn(async move {
            if let Err(e) = proxy_conn(client, &target).await {
                error!("Proxy error from {}: {}", peer, e);
            }
        });
    }
}

async fn proxy_conn(client: TcpStream, target: &str) -> Result<()> {
    let parsed = url::Url::parse(target)?;
    let host = parsed.host_str().unwrap_or("127.0.0.1");
    let port = parsed.port_or_known_default().unwrap_or(80);
    let upstream = TcpStream::connect(format!("{}:{}", host, port)).await?;

    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();

    tokio::select! {
        _ = io::copy(&mut cr, &mut uw) => {}
        _ = io::copy(&mut ur, &mut cw) => {}
    }
    Ok(())
}
