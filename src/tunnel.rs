//! Cloudflare Tunnel HTTP/2 transport implementation
//!
//! Protocol summary (HTTP/2 over TLS on port 7844):
//!
//! 1. TLS connect to edge IP:7844 with SNI "h2.cftunnel.com"
//! 2. Upgrade to HTTP/2 (h2 crate client mode, but acting as server)
//! 3. Open a "control stream" to register the tunnel:
//!      POST /<tunnel-id> HTTP/2
//!      Cf-Cloudflared-Proxy-Connection-Upgrade: control-stream
//!      Body: JSON RegisterConnectionRequest
//! 4. Edge pushes requests as HTTP/2 streams to us (we are the HTTP/2 "server")
//!      Each incoming stream is a proxied request from the Internet
//!      We forward to origin and write response back on the same stream

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use h2::server::SendResponse;
use h2::RecvStream;
use http::{HeaderMap, Request, Response, Uri, Version};
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::{TokenCreds, TunnelConfig};
use crate::edge::{resolve_edge_addrs, EDGE_SNI};
use crate::origin::{bad_gateway, forward_http};
use crate::rpc::{ClientInfo, ConnectionOptions, RegisterConnectionRequest};

// ── Headers used by cloudflared protocol ──────────────────────────────────
const HDR_UPGRADE: &str = "cf-cloudflared-proxy-connection-upgrade";
const HDR_RESP_HEADERS: &str = "cf-cloudflared-proxy-response-headers";
const CONTROL_STREAM: &str = "control-stream";

// ── Public entry point ─────────────────────────────────────────────────────

pub async fn run_tunnel(cfg: TunnelConfig) -> Result<()> {
    if cfg.quick_tunnel {
        run_quick_tunnel(&cfg).await
    } else if let Some(token) = &cfg.token {
        let creds = TokenCreds::from_token(token)
            .context("Failed to decode tunnel token")?;
        info!("Tunnel ID  : {}", creds.t);
        info!("Account Tag: {}", creds.a);
        run_named_tunnel(cfg, creds).await
    } else {
        bail!("Provide --token <TOKEN> or --quick");
    }
}

// ── Quick tunnel (trycloudflare.com) ───────────────────────────────────────

async fn run_quick_tunnel(cfg: &TunnelConfig) -> Result<()> {
    info!("Starting quick tunnel for {}", cfg.local_url);

    // POST to Cloudflare quick-tunnel API
    let addrs = resolve_edge_addrs().await?;
    let connector_id = Uuid::new_v4();

    let tls = make_tls_config()?;
    let connector = TlsConnector::from(Arc::new(tls));

    let mut last_err: Option<anyhow::Error> = None;
    for addr in &addrs {
        match try_quick_connect(*addr, connector_id, cfg, &connector).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                warn!("Quick tunnel attempt to {} failed: {}", addr, e);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("No edge addresses available")))
}

async fn try_quick_connect(
    addr: SocketAddr,
    connector_id: Uuid,
    cfg: &TunnelConfig,
    connector: &TlsConnector,
) -> Result<()> {
    debug!("Connecting to edge {} (quick tunnel)", addr);
    let tcp = TcpStream::connect(addr).await?;
    let domain = rustls::ServerName::try_from(EDGE_SNI)?;
    let tls = connector.connect(domain, tcp).await?;

    // h2 handshake – we act as HTTP/2 server (edge calls us)
    let mut h2 = h2::server::handshake(tls).await?;
    info!("HTTP/2 connected to edge {}", addr);

    // First, open the control stream to register
    // Actually in h2 server mode, the edge opens streams to us.
    // We need to handle incoming streams and identify the control stream.
    // But for quick tunnels, the edge first asks us to register via an
    // HTTP POST to our "server" handle.

    // Wait for the edge to send the control stream request
    serve_h2(&mut h2, connector_id, None, &cfg.local_url, addr).await
}

// ── Named tunnel ───────────────────────────────────────────────────────────

async fn run_named_tunnel(cfg: TunnelConfig, creds: TokenCreds) -> Result<()> {
    info!("Starting named tunnel → {}", cfg.local_url);

    let addrs = resolve_edge_addrs().await?;
    if addrs.is_empty() {
        bail!("Could not resolve any Cloudflare edge addresses");
    }

    let tls = make_tls_config()?;
    let connector = TlsConnector::from(Arc::new(tls));
    let connector_id = Uuid::new_v4();
    info!("Connector ID: {}", connector_id);

    // Exponential backoff reconnect loop
    let mut backoff = Duration::from_secs(1);
    let mut addr_idx = 0usize;

    loop {
        let addr = addrs[addr_idx % addrs.len()];
        addr_idx += 1;

        info!("Connecting to edge {} …", addr);
        match named_connect(addr, connector_id, &creds, &cfg.local_url, &connector).await {
            Ok(()) => {
                info!("Tunnel session ended cleanly");
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                warn!("Tunnel error: {}. Reconnecting in {:?} …", e, backoff);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(64));
            }
        }
    }
}

async fn named_connect(
    addr: SocketAddr,
    connector_id: Uuid,
    creds: &TokenCreds,
    local_url: &str,
    connector: &TlsConnector,
) -> Result<()> {
    let tcp = TcpStream::connect(addr).await
        .with_context(|| format!("TCP connect to {}", addr))?;

    let domain = rustls::ServerName::try_from(EDGE_SNI)?;
    let tls = connector.connect(domain, tcp).await
        .context("TLS handshake")?;

    debug!("TLS connected, starting HTTP/2 handshake");
    let mut h2 = h2::server::handshake(tls).await
        .context("HTTP/2 handshake")?;

    info!("Connected to edge {} ✓", addr);

    serve_h2(&mut h2, connector_id, Some(creds), local_url, addr).await
}

// ── HTTP/2 server loop ─────────────────────────────────────────────────────

async fn serve_h2<S>(
    h2: &mut h2::server::Connection<S, Bytes>,
    connector_id: Uuid,
    creds: Option<&TokenCreds>,
    local_url: &str,
    edge_addr: SocketAddr,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut registered = false;

    loop {
        match h2.accept().await {
            Some(Ok((req, mut respond))) => {
                let upgrade_hdr = req
                    .headers()
                    .get(HDR_UPGRADE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                if upgrade_hdr == CONTROL_STREAM {
                    // Handle control stream – register the tunnel
                    debug!("Received control stream from edge");
                    handle_control_stream(
                        req,
                        respond,
                        connector_id,
                        creds,
                        edge_addr,
                    )
                    .await?;
                    registered = true;
                    info!("Tunnel registered with edge ✓");
                } else {
                    // Proxy request to origin
                    let local_url = local_url.to_string();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_proxy_stream(req, respond, &local_url).await
                        {
                            error!("Proxy error: {}", e);
                        }
                    });
                }
            }
            Some(Err(e)) => {
                // Connection-level errors
                if e.is_go_away() {
                    info!("Edge sent GOAWAY, reconnecting…");
                    break;
                }
                return Err(e.into());
            }
            None => {
                // Connection closed
                break;
            }
        }
    }

    Ok(())
}

// ── Control stream handler ─────────────────────────────────────────────────

async fn handle_control_stream(
    mut req: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    connector_id: Uuid,
    creds: Option<&TokenCreds>,
    edge_addr: SocketAddr,
) -> Result<()> {
    // Read request body (edge sends nothing for control stream open)
    let _ = drain_body(req.body_mut()).await;

    // Build registration payload
    let rpc = RegisterConnectionRequest {
        account_tag: creds.map(|c| c.a.clone()).unwrap_or_default(),
        tunnel_secret: creds
            .and_then(|c| c.secret_bytes().ok())
            .unwrap_or_default(),
        conn_index: 0,
        options: ConnectionOptions {
            client: ClientInfo::new(connector_id),
            num_previous_attempts: 0,
            unregister_pause: 0,
            features: vec!["ha-origin".into()],
        },
        tunnel_id: creds.map(|c| c.t.clone()).unwrap_or_default(),
        edge_addr: edge_addr.to_string(),
    };

    let body_bytes = Bytes::from(serde_json::to_vec(&rpc)?);

    // Respond 200 OK with registration payload
    let resp = Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(())?;

    let mut send = respond.send_response(resp, false)?;
    send.send_data(body_bytes, true)?;

    Ok(())
}

// ── Proxy stream handler ───────────────────────────────────────────────────

async fn handle_proxy_stream(
    mut req: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    local_url: &str,
) -> Result<()> {
    debug!("← {} {}", req.method(), req.uri());

    // Read request body
    let body = drain_body(req.body_mut()).await;

    // Build http::Request for origin
    let uri = req.uri().clone();
    let method = req.method().clone();

    // Deserialize extra response headers from the serialized-headers field
    let mut origin_req = Request::builder()
        .method(method)
        .uri(rewrite_uri(&uri, local_url)?)
        .version(Version::HTTP_11)
        .body(body)?;

    // Copy headers
    for (k, v) in req.headers() {
        if k == http::header::HOST || k == HDR_UPGRADE {
            continue;
        }
        origin_req.headers_mut().insert(k, v.clone());
    }

    // Forward to origin
    let origin_resp = forward_http(local_url, origin_req)
        .await
        .unwrap_or_else(|e| {
            warn!("Origin error: {}", e);
            bad_gateway()
        });

    let status = origin_resp.status();
    debug!("→ {}", status);

    // Serialize response headers as required by cloudflared protocol
    let (parts, body) = origin_resp.into_parts();
    let serialized_headers = serialize_headers(&parts.headers);

    let mut resp_builder = Response::builder().status(status);
    // Pass through content-length if present
    if let Some(cl) = parts.headers.get(http::header::CONTENT_LENGTH) {
        resp_builder = resp_builder.header(http::header::CONTENT_LENGTH, cl);
    }
    // Serialized user headers
    resp_builder = resp_builder.header(HDR_RESP_HEADERS, serialized_headers);

    let resp = resp_builder.body(())?;
    let mut send = respond.send_response(resp, body.is_empty())?;

    if !body.is_empty() {
        send.send_data(body, true)?;
    }

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn make_tls_config() -> Result<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let mut cfg = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // MUST advertise h2 for HTTP/2
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

async fn drain_body(body: &mut RecvStream) -> Bytes {
    let mut buf = bytes::BytesMut::new();
    while let Some(chunk) = body.data().await {
        match chunk {
            Ok(data) => {
                let _ = body.flow_control().release_capacity(data.len());
                buf.extend_from_slice(&data);
            }
            Err(_) => break,
        }
    }
    buf.freeze()
}

fn rewrite_uri(original: &Uri, local_url: &str) -> Result<Uri> {
    let local = url::Url::parse(local_url)?;
    let path = original
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");

    let new_uri = format!(
        "{}://{}:{}{}",
        local.scheme(),
        local.host_str().unwrap_or("127.0.0.1"),
        local.port_or_known_default().unwrap_or(80),
        path
    );
    Ok(new_uri.parse()?)
}

/// Serialize response headers into a single header value
/// (cloudflared protocol: "Key: Value\r\nKey2: Value2")
fn serialize_headers(headers: &HeaderMap) -> String {
    headers
        .iter()
        .filter(|(k, _)| {
            *k != http::header::CONTENT_LENGTH
        })
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
        .collect::<Vec<_>>()
        .join("\r\n")
}
