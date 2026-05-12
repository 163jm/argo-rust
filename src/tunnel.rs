//! Cloudflare Tunnel HTTP/2 transport
//!
//! Flow:
//!  1. Decode token → account_tag, tunnel_secret, tunnel_id
//!  2. Fetch ingress rules from Cloudflare REST API
//!  3. Resolve edge IPs via DNS (region1.v2.argotunnel.com:7844)
//!  4. TLS connect with SNI "h2.cftunnel.com", ALPN "h2"
//!  5. HTTP/2 handshake (we act as h2 server; edge is the client)
//!  6. First stream from edge = control stream → reply with RegisterConnection JSON
//!  7. Subsequent streams = proxied requests → match ingress, forward to origin

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
use crate::ingress::{fetch_ingress, start_refresh_task, resolve, IngressTable};
use crate::origin::{bad_gateway, dispatch, not_found};
use crate::rpc::{ClientInfo, ConnectionOptions, RegisterConnectionRequest};

const HDR_UPGRADE: &str = "cf-cloudflared-proxy-connection-upgrade";
const HDR_RESP_HEADERS: &str = "cf-cloudflared-proxy-response-headers";
const CONTROL_STREAM: &str = "control-stream";
/// Ingress rules are refreshed from Cloudflare API every 30 seconds
const REFRESH_INTERVAL: u64 = 30;

// ── Entry point ────────────────────────────────────────────────────────────

pub async fn run_tunnel(cfg: TunnelConfig) -> Result<()> {
    let creds = TokenCreds::from_token(&cfg.token)
        .context("Failed to decode tunnel token – is it the token from the Cloudflare dashboard?")?;

    info!("Tunnel ID  : {}", creds.t);
    info!("Account    : {}", creds.a);

    // Fetch ingress rules from Cloudflare API
    info!("Fetching ingress rules from Cloudflare API…");
    let rules = fetch_ingress(&creds, &cfg.token).await
        .context("Failed to fetch tunnel configuration from Cloudflare API")?;

    let table: IngressTable = Arc::new(tokio::sync::RwLock::new(rules));

    // Start background refresh task
    start_refresh_task(creds.clone(), cfg.token.clone(), Arc::clone(&table), REFRESH_INTERVAL);

    // Resolve edge addresses
    let addrs = resolve_edge_addrs().await?;
    if addrs.is_empty() {
        bail!("Could not resolve any Cloudflare edge addresses");
    }
    info!("Resolved {} edge address(es)", addrs.len());

    let tls = make_tls_config()?;
    let connector = TlsConnector::from(Arc::new(tls));
    let connector_id = Uuid::new_v4();
    info!("Connector  : {}", connector_id);
    info!("Ready – waiting for connections via Cloudflare edge\n");

    // Reconnect loop with exponential backoff
    let mut backoff = Duration::from_secs(1);
    let mut addr_idx = 0usize;

    loop {
        let addr = addrs[addr_idx % addrs.len()];
        addr_idx += 1;

        info!("Connecting to edge {} …", addr);
        match connect_and_serve(addr, connector_id, &creds, &cfg.token, &table, &connector).await {
            Ok(()) => {
                info!("Connection closed cleanly, reconnecting…");
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                warn!("Connection error: {}. Reconnecting in {:?}…", e, backoff);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(64));
            }
        }
    }
}

// ── Connect + HTTP/2 serve loop ────────────────────────────────────────────

async fn connect_and_serve(
    addr: SocketAddr,
    connector_id: Uuid,
    creds: &TokenCreds,
    raw_token: &str,
    table: &IngressTable,
    connector: &TlsConnector,
) -> Result<()> {
    let tcp = TcpStream::connect(addr).await
        .with_context(|| format!("TCP connect to {}", addr))?;
    tcp.set_nodelay(true)?;

    let domain = rustls::ServerName::try_from(EDGE_SNI)
        .map_err(|_| anyhow::anyhow!("Invalid edge SNI"))?;
    let tls = connector.connect(domain, tcp).await
        .context("TLS handshake failed")?;

    // Verify that h2 was negotiated
    {
        let (_, session) = tls.get_ref();
        match session.alpn_protocol() {
            Some(b"h2") => debug!("ALPN: h2 ✓"),
            other => warn!("ALPN: {:?} (expected h2)", other.map(|b| String::from_utf8_lossy(b))),
        }
    }

    let mut h2 = h2::server::handshake(tls).await
        .context("HTTP/2 handshake failed")?;

    info!("Connected to edge {} ✓", addr);

    // Accept streams from the edge
    loop {
        match h2.accept().await {
            Some(Ok((req, respond))) => {
                let is_control = req
                    .headers()
                    .get(HDR_UPGRADE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("") == CONTROL_STREAM;

                if is_control {
                    handle_control_stream(req, respond, connector_id, creds, addr).await?;
                    info!("Tunnel registered with Cloudflare edge ✓");
                } else {
                    let table = Arc::clone(table);
                    tokio::spawn(async move {
                        if let Err(e) = handle_proxy_stream(req, respond, &table).await {
                            error!("Proxy stream error: {}", e);
                        }
                    });
                }
            }
            Some(Err(e)) if e.is_go_away() => {
                info!("Edge sent GOAWAY, reconnecting…");
                break;
            }
            Some(Err(e)) => return Err(e.into()),
            None => break,
        }
    }

    Ok(())
}

// ── Control stream ─────────────────────────────────────────────────────────

async fn handle_control_stream(
    mut req: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    connector_id: Uuid,
    creds: &TokenCreds,
    edge_addr: SocketAddr,
) -> Result<()> {
    let _ = drain_body(req.body_mut()).await;

    let rpc = RegisterConnectionRequest {
        account_tag: creds.a.clone(),
        tunnel_secret: creds.secret_bytes().unwrap_or_default(),
        conn_index: 0,
        options: ConnectionOptions {
            client: ClientInfo::new(connector_id),
            num_previous_attempts: 0,
            unregister_pause: 0,
            features: vec!["ha-origin".into(), "serialized-headers".into()],
        },
        tunnel_id: creds.t.clone(),
        edge_addr: edge_addr.to_string(),
    };

    let body_bytes = Bytes::from(serde_json::to_vec(&rpc)?);
    let resp = Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(())?;

    let mut send = respond.send_response(resp, false)?;
    send.send_data(body_bytes, true)?;
    Ok(())
}

// ── Proxy stream ───────────────────────────────────────────────────────────

async fn handle_proxy_stream(
    mut req: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    table: &IngressTable,
) -> Result<()> {
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let path = req.uri().path().to_string();

    debug!("← {} {} (host: {})", req.method(), path, host);

    // Match ingress rule
    let rule = resolve(table, &host, &path).await;
    let origin_resp = match rule {
        None => {
            warn!("No ingress rule matched host={} path={}", host, path);
            not_found()
        }
        Some(rule) => {
            let body = drain_body(req.body_mut()).await;

            // Build origin request
            let mut origin_req = Request::builder()
                .method(req.method())
                .uri(rewrite_uri(req.uri(), &rule.service)?)
                .version(Version::HTTP_11)
                .body(body)?;

            // Copy headers (skip h2 pseudo-headers and hop-by-hop)
            for (k, v) in req.headers() {
                let ks = k.as_str();
                if ks.starts_with(':') || ks == "host" || ks == HDR_UPGRADE {
                    continue;
                }
                origin_req.headers_mut().insert(k, v.clone());
            }

            dispatch(&rule, origin_req).await.unwrap_or_else(|e| {
                warn!("Origin error: {}", e);
                bad_gateway()
            })
        }
    };

    let status = origin_resp.status();
    debug!("→ {}", status);

    let (parts, body) = origin_resp.into_parts();
    let serialized_hdrs = serialize_headers(&parts.headers);

    let mut resp_builder = Response::builder().status(status);
    if let Some(cl) = parts.headers.get(http::header::CONTENT_LENGTH) {
        resp_builder = resp_builder.header(http::header::CONTENT_LENGTH, cl);
    }
    resp_builder = resp_builder.header(HDR_RESP_HEADERS, serialized_hdrs);

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

/// Rewrite URI: replace scheme+host with origin service URL, keep path+query
fn rewrite_uri(original: &Uri, service_url: &str) -> Result<Uri> {
    let base = url::Url::parse(service_url)?;
    let path = original
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");

    let new_uri = format!(
        "{}://{}:{}{}",
        base.scheme(),
        base.host_str().unwrap_or("127.0.0.1"),
        base.port_or_known_default().unwrap_or(80),
        path
    );
    Ok(new_uri.parse()?)
}

/// Serialize response headers into a single header value for cloudflared protocol
fn serialize_headers(headers: &HeaderMap) -> String {
    headers
        .iter()
        .filter(|(k, _)| *k != http::header::CONTENT_LENGTH)
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
        .collect::<Vec<_>>()
        .join("\r\n")
}
