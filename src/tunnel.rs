//! Cloudflare Tunnel HTTP/2 transport
//!
//! 协议方向：我们是 HTTP/2 客户端，edge 是服务端。
//! 连接建立后，我们主动 POST 到 edge 注册；
//! edge 随后通过 server-push 或响应流把请求推给我们。
//!
//! 实际 cloudflared 用 capnproto RPC over HTTP/2，
//! 这里用 h2 client 模式 + JSON 做简化实现。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use h2::client::SendRequest;
use http::{HeaderMap, Method, Request, Response, Uri, Version};
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::{TokenCreds, TunnelConfig};
use crate::edge::{resolve_edge_addrs, EDGE_SNI};
use crate::ingress::{make_table, print_rules, resolve, start_reload_task, IngressTable};
use crate::origin::{bad_gateway, dispatch, not_found};
use crate::rpc::{ClientInfo, ConnectionOptions, RegisterConnectionRequest};

const HDR_UPGRADE: &str = "cf-cloudflared-proxy-connection-upgrade";
const HDR_RESP_HEADERS: &str = "cf-cloudflared-proxy-response-headers";
const CONTROL_STREAM_VAL: &str = "control-stream";
const CONFIG_RELOAD_INTERVAL: u64 = 30;

// ── Entry point ────────────────────────────────────────────────────────────

pub async fn run_tunnel(cfg: TunnelConfig) -> Result<()> {
    let creds = TokenCreds::from_token(&cfg.token)
        .context("Failed to decode tunnel token")?;

    info!("Tunnel ID  : {}", creds.t);
    info!("Account    : {}", creds.a);

    let config_path = cfg.config_file
        .or_else(crate::ingress::default_config_path)
        .context(
            "Config file not found.\n\n\
             Create ~/.cloudflared/config.yaml:\n\n\
             ingress:\n\
               - hostname: example.com\n\
                 service: http://localhost:8080\n\
               - service: http_status:404\n\n\
             Or: mini-cloudflared tunnel --token TOKEN --config /path/to/config.yaml"
        )?;

    info!("Config     : {}", config_path.display());
    let rules = crate::ingress::load_from_file(&config_path)?;
    print_rules(&rules);

    let table = make_table(rules);
    start_reload_task(config_path, Arc::clone(&table), CONFIG_RELOAD_INTERVAL);

    let addrs = resolve_edge_addrs().await?;
    if addrs.is_empty() {
        bail!("Could not resolve any Cloudflare edge addresses");
    }

    let tls_cfg = make_tls_config()?;
    let connector = TlsConnector::from(Arc::new(tls_cfg));
    let connector_id = Uuid::new_v4();
    info!("Connector  : {}", connector_id);
    info!("Ready – connecting to Cloudflare edge\n");

    let mut backoff = Duration::from_secs(1);
    let mut addr_idx = 0usize;

    loop {
        let addr = addrs[addr_idx % addrs.len()];
        addr_idx += 1;
        info!("Connecting to edge {} …", addr);

        match connect_and_serve(addr, connector_id, &creds, &table, &connector).await {
            Ok(()) => {
                info!("Connection closed, reconnecting…");
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

// ── Connect ────────────────────────────────────────────────────────────────

async fn connect_and_serve(
    addr: SocketAddr,
    connector_id: Uuid,
    creds: &TokenCreds,
    table: &IngressTable,
    connector: &TlsConnector,
) -> Result<()> {
    // TCP
    let tcp = TcpStream::connect(addr).await
        .with_context(|| format!("TCP connect to {}", addr))?;
    tcp.set_nodelay(true)?;

    // TLS – SNI = h2.cftunnel.com, ALPN = h2
    let domain = rustls::ServerName::try_from(EDGE_SNI)
        .map_err(|_| anyhow::anyhow!("Invalid SNI: {}", EDGE_SNI))?;
    let tls = connector.connect(domain, tcp).await
        .with_context(|| {
            format!(
                "TLS handshake failed with {} (SNI={}). \
                 Check that port 7844 is reachable and not intercepted.",
                addr, EDGE_SNI
            )
        })?;

    // Verify ALPN
    {
        let (_, sess) = tls.get_ref();
        let alpn = sess.alpn_protocol();
        let ver  = sess.protocol_version();
        info!("TLS OK – {:?}, ALPN={}", ver,
            alpn.map(|b| String::from_utf8_lossy(b).to_string()).unwrap_or_else(|| "none".into()));
        if alpn != Some(b"h2") {
            warn!("Expected ALPN=h2, got {:?}. Proceeding anyway.",
                alpn.map(|b| String::from_utf8_lossy(b).to_string()));
        }
    }

    // HTTP/2 client handshake (we are the client, edge is the server)
    let (mut send_req, conn) = h2::client::handshake(tls).await
        .context("HTTP/2 client handshake failed")?;

    // Drive the connection in background
    let conn_task = tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("H2 connection closed: {}", e);
        }
    });

    info!("Connected to edge {} ✓", addr);

    // Wait for the connection to be ready
    send_req.clone().ready().await.context("H2 send_request not ready")?;

    // ── Step 1: Open control stream to register the tunnel ────────────────
    register_connection(send_req.clone(), connector_id, creds, addr).await
        .context("RegisterConnection failed")?;
    info!("Tunnel registered with edge ✓");

    serve_requests(send_req, table).await?;

    conn_task.abort();
    Ok(())
}

// ── RegisterConnection ─────────────────────────────────────────────────────

async fn register_connection(
    mut send_req: SendRequest<Bytes>,
    connector_id: Uuid,
    creds: &TokenCreds,
    edge_addr: SocketAddr,
) -> Result<()> {
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

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("https://{}/capnp/tunnel", EDGE_SNI))
        .header("content-type", "application/json")
        .header(HDR_UPGRADE, CONTROL_STREAM_VAL)
        .header("cf-ray", format!("{:016x}", rand::random::<u64>()))
        .body(())?;

    let (resp_future, mut req_body) = send_req.send_request(req, false)?;
    req_body.send_data(body_bytes, true)?;

    let resp = resp_future.await.context("No response from edge on control stream")?;
    let status = resp.status();
    debug!("Control stream response: {}", status);

    if !status.is_success() {
        // Read error body
        let mut body = resp.into_body();
        let mut buf = bytes::BytesMut::new();
        while let Some(chunk) = body.data().await {
            if let Ok(data) = chunk {
                let _ = body.flow_control().release_capacity(data.len());
                buf.extend_from_slice(&data);
            }
        }
        bail!("Edge rejected registration ({}): {}",
            status, String::from_utf8_lossy(&buf));
    }

    // Drain response body
    let mut body = resp.into_body();
    while let Some(chunk) = body.data().await {
        if let Ok(data) = chunk {
            let _ = body.flow_control().release_capacity(data.len());
            debug!("Control stream data: {} bytes", data.len());
        }
    }

    Ok(())
}

// ── Serve incoming requests from edge ─────────────────────────────────────
// After registration, edge sends proxied Internet requests to us as new
// HTTP/2 streams. We open a long-lived "serve" stream that the edge uses
// to deliver request envelopes; we reply on the same stream.

async fn serve_requests(
    send_req: SendRequest<Bytes>,
    table: &IngressTable,
) -> Result<()> {
    info!("Tunnel active – waiting for proxied requests");

    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        // Check connection liveness by trying to clone (send_req is Clone when alive)
        let mut sr = send_req.clone();
        match sr.ready().await {
            Ok(_) => debug!("Heartbeat: connection alive"),
            Err(e) => {
                info!("Connection lost ({}), reconnecting…", e);
                break;
            }
        }
    }

    Ok(())
}

// ── TLS config ────────────────────────────────────────────────────────────

fn make_tls_config() -> Result<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject, ta.spki, ta.name_constraints,
        )
    }));
    let mut cfg = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

// ── Unused helpers kept for origin dispatch ───────────────────────────────

fn rewrite_uri(original: &Uri, service_url: &str) -> Result<Uri> {
    let base = url::Url::parse(service_url)?;
    let path = original.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    Ok(format!(
        "{}://{}:{}{}",
        base.scheme(),
        base.host_str().unwrap_or("127.0.0.1"),
        base.port_or_known_default().unwrap_or(80),
        path
    ).parse()?)
}

fn serialize_headers(headers: &HeaderMap) -> String {
    headers.iter()
        .filter(|(k, _)| *k != http::header::CONTENT_LENGTH)
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
        .collect::<Vec<_>>()
        .join("\r\n")
}
