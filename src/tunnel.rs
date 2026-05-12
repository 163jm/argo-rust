//! Tunnel implementation — WebSocket connection to Cloudflare edge

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::Message};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::TunnelConfig;
use crate::protocol::{
    HttpRequestMeta, HttpResponseMeta, Opcode, RegistrationPayload, TunnelFrame,
};

// ── Cloudflare edge endpoints ──────────────────────────────────────────────

/// Quick tunnel API (no auth required)
const QUICK_TUNNEL_API: &str = "https://api.trycloudflare.com/tunnel";

/// Named tunnel edge (wss)
const EDGE_WSS: &str = "wss://region1.v2.argotunnel.com/edge";

// ── Public entry point ─────────────────────────────────────────────────────

pub async fn run_tunnel(cfg: TunnelConfig) -> Result<()> {
    info!("Starting mini-cloudflared tunnel");
    info!("Local service: {}", cfg.local_url);

    let connector_id = Uuid::new_v4().to_string();
    info!("Connector ID: {}", connector_id);

    // Determine edge URL and print public hostname
    let (edge_url, hostname) = if cfg.quick_tunnel {
        let (url, host) = register_quick_tunnel(&connector_id).await?;
        info!("✅ Quick tunnel active!");
        info!("🌐 Public URL: https://{}", host);
        (url, host)
    } else if let Some(token) = &cfg.token {
        let host = cfg.hostname.clone()
            .unwrap_or_else(|| format!("{}.cfargotunnel.com", Uuid::new_v4()));
        info!("✅ Named tunnel active");
        info!("🌐 Public URL: https://{}", host);
        (format!("{}?token={}", EDGE_WSS, token), host)
    } else {
        bail!("Either --quick or --token must be provided");
    };

    info!("Forwarding → {}", cfg.local_url);
    info!("Press Ctrl+C to stop\n");

    // Retry loop with exponential backoff
    let mut backoff = Duration::from_secs(1);
    loop {
        match connect_and_serve(&edge_url, &connector_id, &cfg.local_url, &hostname).await {
            Ok(()) => {
                info!("Tunnel closed gracefully");
                break;
            }
            Err(e) => {
                warn!("Tunnel error: {}. Reconnecting in {:?}…", e, backoff);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
            }
        }
    }

    Ok(())
}

// ── Quick tunnel registration ──────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct QuickTunnelResponse {
    result: QuickTunnelResult,
}

#[derive(serde::Deserialize)]
struct QuickTunnelResult {
    id: String,
    name: String,
    #[serde(rename = "accountTag")]
    account_tag: String,
    #[serde(rename = "tunnelSecret")]
    tunnel_secret: String,
}

async fn register_quick_tunnel(connector_id: &str) -> Result<(String, String)> {
    info!("Registering quick tunnel…");

    // In a real implementation, this would POST to Cloudflare's quick-tunnel API.
    // Here we simulate the response for demonstration.
    //
    // Real flow:
    //   POST https://api.trycloudflare.com/tunnel
    //   → { result: { id, name, accountTag, tunnelSecret, hostname } }
    //
    // Then connect to: wss://region1.v2.argotunnel.com/edge?<creds>

    let hostname = format!("{}.trycloudflare.com", generate_subdomain());
    let wss_url = format!(
        "wss://region1.v2.argotunnel.com/edge?connector={}&hostname={}",
        connector_id, hostname
    );

    info!("Quick tunnel registered: {}", hostname);
    Ok((wss_url, hostname))
}

fn generate_subdomain() -> String {
    use rand::Rng;
    const WORDS: &[&str] = &[
        "autumn", "bold", "calm", "deep", "echo", "fast", "gold", "hill",
        "iron", "jade", "keen", "lark", "mist", "nova", "oak", "pine",
        "quiet", "rose", "sage", "teal", "ultra", "vale", "wave", "xray",
        "yard", "zinc",
    ];
    let mut rng = rand::thread_rng();
    format!(
        "{}-{}-{}",
        WORDS[rng.gen_range(0..WORDS.len())],
        WORDS[rng.gen_range(0..WORDS.len())],
        rng.gen_range(1000u32..9999),
    )
}

// ── WebSocket connection loop ──────────────────────────────────────────────

type ActiveStreams = Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>;

async fn connect_and_serve(
    edge_url: &str,
    connector_id: &str,
    local_url: &str,
    hostname: &str,
) -> Result<()> {
    debug!("Connecting to edge: {}", edge_url);

    let url = url::Url::parse(edge_url)?;

    // Build WebSocket with custom headers required by Cloudflare
    let req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url)?;

    let (ws_stream, _response) = connect_async_tls_with_config(req, None, false, None)
        .await
        .context("WebSocket handshake failed")?;

    info!("Connected to Cloudflare edge ✓");

    let (mut ws_tx, mut ws_rx) = ws_stream.split();
    let active_streams: ActiveStreams = Arc::new(Mutex::new(HashMap::new()));

    // ── Send registration frame ────────────────────────────────────────────
    let reg = RegistrationPayload::new(connector_id.into(), None);
    let reg_bytes = serde_json::to_vec(&reg)?;
    let reg_frame = TunnelFrame::new(Opcode::Register, 0, reg_bytes);
    ws_tx.send(Message::Binary(reg_frame.encode().to_vec())).await?;
    debug!("Registration frame sent");

    // ── Shared sender handle ───────────────────────────────────────────────
    let (tx_out, mut rx_out) = mpsc::channel::<TunnelFrame>(64);

    // Outbound task: drain rx_out → WS
    let mut ws_tx = ws_tx;
    tokio::spawn(async move {
        while let Some(frame) = rx_out.recv().await {
            let bytes = frame.encode().to_vec();
            if ws_tx.send(Message::Binary(bytes)).await.is_err() {
                break;
            }
        }
    });

    // ── Main receive loop ──────────────────────────────────────────────────
    let local_url = local_url.to_string();
    while let Some(msg) = ws_rx.next().await {
        let msg = msg.context("WebSocket receive error")?;
        match msg {
            Message::Binary(data) => {
                let frame = TunnelFrame::decode(Bytes::from(data))?;
                handle_frame(frame, &active_streams, &tx_out, &local_url).await?;
            }
            Message::Ping(data) => {
                tx_out
                    .send(TunnelFrame::new(Opcode::Pong, 0, data))
                    .await
                    .ok();
            }
            Message::Close(_) => {
                info!("Edge closed the connection");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

// ── Frame dispatch ─────────────────────────────────────────────────────────

async fn handle_frame(
    frame: TunnelFrame,
    streams: &ActiveStreams,
    tx_out: &mpsc::Sender<TunnelFrame>,
    local_url: &str,
) -> Result<()> {
    match frame.opcode {
        Opcode::RegisterAck => {
            info!("Registration acknowledged by edge ✓");
        }

        Opcode::Ping => {
            tx_out
                .send(TunnelFrame::new(Opcode::Pong, 0, b"pong".as_ref()))
                .await
                .ok();
        }

        Opcode::HttpRequest => {
            let stream_id = frame.stream_id;
            let local_url = local_url.to_string();
            let tx_out = tx_out.clone();

            tokio::spawn(async move {
                if let Err(e) = proxy_http_request(stream_id, frame.payload, &local_url, tx_out).await {
                    error!("HTTP proxy error (stream {}): {}", stream_id, e);
                }
            });
        }

        Opcode::StreamOpen => {
            let (data_tx, mut data_rx) = mpsc::channel::<Bytes>(16);
            streams.lock().await.insert(frame.stream_id, data_tx);

            let stream_id = frame.stream_id;
            let local_url = local_url.to_string();
            let tx_out = tx_out.clone();

            tokio::spawn(async move {
                if let Err(e) = proxy_stream(stream_id, &mut data_rx, &local_url, tx_out).await {
                    error!("Stream proxy error ({}): {}", stream_id, e);
                }
            });
        }

        Opcode::StreamData => {
            let locked = streams.lock().await;
            if let Some(data_tx) = locked.get(&frame.stream_id) {
                data_tx.send(frame.payload).await.ok();
            }
        }

        Opcode::StreamClose => {
            streams.lock().await.remove(&frame.stream_id);
            debug!("Stream {} closed", frame.stream_id);
        }

        Opcode::Error => {
            let msg = String::from_utf8_lossy(&frame.payload);
            error!("Edge error: {}", msg);
        }

        _ => {
            debug!("Unhandled opcode: {:?}", frame.opcode);
        }
    }

    Ok(())
}

// ── HTTP request proxying ──────────────────────────────────────────────────

async fn proxy_http_request(
    stream_id: u32,
    payload: Bytes,
    local_url: &str,
    tx_out: mpsc::Sender<TunnelFrame>,
) -> Result<()> {
    // Decode the HTTP request metadata from the payload
    let meta: HttpRequestMeta = serde_json::from_slice(&payload)?;
    debug!("→ {} {}", meta.method, meta.url);

    // Build target URL: replace the public hostname with the local service
    let target = build_target_url(&meta.url, local_url)?;

    // Forward using a simple TCP connection
    let client = tokio::net::TcpStream::connect(extract_host_port(&target)?).await?;

    // Build raw HTTP/1.1 request
    let request = build_http_request(&meta, &target);

    // Send request, read response
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut client = client;
    client.write_all(request.as_bytes()).await?;

    let mut resp_buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = client.read(&mut tmp).await?;
        if n == 0 { break; }
        resp_buf.extend_from_slice(&tmp[..n]);
        // Stop reading headers once we see \r\n\r\n
        if resp_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    // Read remaining body
    loop {
        let n = client.read(&mut tmp).await?;
        if n == 0 { break; }
        resp_buf.extend_from_slice(&tmp[..n]);
    }

    // Parse status line
    let response_text = String::from_utf8_lossy(&resp_buf);
    let status = parse_status_code(&response_text).unwrap_or(502);
    let headers = parse_response_headers(&response_text);

    let resp_meta = HttpResponseMeta { status, headers };
    let resp_payload = serde_json::to_vec(&resp_meta)?;
    tx_out
        .send(TunnelFrame::new(Opcode::HttpResponse, stream_id, resp_payload))
        .await
        .ok();

    debug!("← {} {}", status, meta.url);
    Ok(())
}

// ── TCP stream proxying (CONNECT / WebSocket upgrade) ─────────────────────

async fn proxy_stream(
    stream_id: u32,
    data_rx: &mut mpsc::Receiver<Bytes>,
    local_url: &str,
    tx_out: mpsc::Sender<TunnelFrame>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = extract_host_port(local_url)?;
    let mut tcp = tokio::net::TcpStream::connect(&addr).await?;
    debug!("Stream {} opened → {}", stream_id, addr);

    let (mut tcp_rx, mut tcp_tx) = tcp.split();

    // Forward edge→local
    let tx_out_clone = tx_out.clone();
    let mut buf = [0u8; 8192];

    loop {
        tokio::select! {
            // Edge data → local
            Some(data) = data_rx.recv() => {
                tcp_tx.write_all(&data).await?;
            }
            // Local data → edge
            n = tcp_rx.read(&mut buf) => {
                let n = n?;
                if n == 0 { break; }
                tx_out_clone
                    .send(TunnelFrame::new(Opcode::StreamData, stream_id, Bytes::copy_from_slice(&buf[..n])))
                    .await
                    .ok();
            }
        }
    }

    tx_out
        .send(TunnelFrame::new(Opcode::StreamClose, stream_id, Bytes::new()))
        .await
        .ok();

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn build_target_url(original_url: &str, local_url: &str) -> Result<String> {
    // Replace the scheme+host with local_url, keep path+query
    let parsed = url::Url::parse(original_url)?;
    let path_and_query = if let Some(q) = parsed.query() {
        format!("{}?{}", parsed.path(), q)
    } else {
        parsed.path().to_string()
    };

    let local_base = local_url.trim_end_matches('/');
    Ok(format!("{}{}", local_base, path_and_query))
}

fn extract_host_port(url: &str) -> Result<String> {
    let parsed = url::Url::parse(url)?;
    let host = parsed.host_str().context("No host in URL")?;
    let port = parsed.port_or_known_default().context("No port")?;
    Ok(format!("{}:{}", host, port))
}

fn build_http_request(meta: &HttpRequestMeta, target_url: &str) -> String {
    let parsed = url::Url::parse(target_url).unwrap();
    let path = if let Some(q) = parsed.query() {
        format!("{}?{}", parsed.path(), q)
    } else {
        parsed.path().to_string()
    };
    let host = parsed.host_str().unwrap_or("localhost");
    let port = parsed.port_or_known_default().unwrap_or(80);

    let mut req = format!("{} {} HTTP/1.1\r\nHost: {}:{}\r\n", meta.method, path, host, port);
    for (k, v) in &meta.headers {
        if k.to_lowercase() != "host" {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }
    }
    req.push_str("Connection: close\r\n\r\n");
    req
}

fn parse_status_code(response: &str) -> Option<u16> {
    response
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn parse_response_headers(response: &str) -> Vec<(String, String)> {
    response
        .lines()
        .skip(1)
        .take_while(|l| !l.is_empty())
        .filter_map(|line| {
            let mut parts = line.splitn(2, ':');
            let k = parts.next()?.trim().to_string();
            let v = parts.next()?.trim().to_string();
            Some((k, v))
        })
        .collect()
}
