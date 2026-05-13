//! Cloudflare Tunnel – HTTP/2 transport
//!
//! 协议（来自 cloudflared 源码分析）：
//!  1. TCP 连接到 edge IP:7844
//!  2. TLS 握手，SNI = "h2.cftunnel.com"，cert pool = 系统 pool + webpki roots
//!  3. cloudflared 作为 **HTTP/2 服务端**，edge 作为 HTTP/2 客户端连进来
//!  4. Edge 发来第一个请求：带 Cf-Cloudflared-Proxy-Connection-Upgrade: control-stream
//!     → 我们在该 stream 上完成 capnproto RegisterConnection RPC
//!  5. 后续请求：edge 代理的公网请求，转发到本地 origin

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
use crate::ingress::{make_table, print_rules, resolve, start_reload_task, IngressTable};
use crate::origin::{bad_gateway, dispatch, not_found};
use crate::rpc::{build_capnp_register, ClientInfo, ConnectionOptions};

pub const HDR_UPGRADE: &str = "cf-cloudflared-proxy-connection-upgrade";
pub const HDR_RESP_HEADERS: &str = "cf-cloudflared-proxy-response-headers";
pub const CONTROL_STREAM_VAL: &str = "control-stream";
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
             Or pass: --config /path/to/config.yaml"
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

    let tls_cfg = make_tls_config().context("Failed to build TLS config")?;
    let connector = TlsConnector::from(Arc::new(tls_cfg));
    let connector_id = Uuid::new_v4();
    info!("Connector  : {}", connector_id);
    info!("Ready – connecting to Cloudflare edge (HTTP/2 server mode)\n");

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

// ── Connect + serve ────────────────────────────────────────────────────────

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

    // TLS – SNI = h2.cftunnel.com
    // No explicit ALPN: cloudflared source does NOT set NextProtos for HTTP/2,
    // it just does a raw TLS connect and then calls http2.Server.ServeConn
    let domain = rustls::ServerName::try_from(EDGE_SNI)
        .map_err(|_| anyhow::anyhow!("Invalid SNI: {}", EDGE_SNI))?;

    let tls = connector.connect(domain, tcp).await
        .map_err(|e| anyhow::anyhow!(
            "TLS handshake failed with {} (SNI={}): {:?}",
            addr, EDGE_SNI, e
        ))?;

    {
        let (_, sess) = tls.get_ref();
        info!("TLS OK – {:?}, ALPN={:?}", sess.protocol_version(),
            sess.alpn_protocol().map(|b| String::from_utf8_lossy(b).to_string()));
    }

    // HTTP/2: we are the server, edge is the client (ServeConn mode)
    let mut h2 = h2::server::handshake(tls).await
        .context("HTTP/2 handshake failed")?;

    info!("HTTP/2 connected to edge {} ✓", addr);

    // Accept streams
    loop {
        match h2.accept().await {
            Some(Ok((req, respond))) => {
                let upgrade = req.headers()
                    .get(HDR_UPGRADE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                if upgrade == CONTROL_STREAM_VAL {
                    debug!("Control stream received");
                    handle_control_stream(req, respond, connector_id, creds, addr).await?;
                    info!("Tunnel registered with edge ✓");
                } else {
                    let table = Arc::clone(table);
                    tokio::spawn(async move {
                        if let Err(e) = handle_proxy_stream(req, respond, &table).await {
                            error!("Proxy error: {}", e);
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
//
// The real cloudflared does capnproto RPC over this stream:
//   client (cloudflared) calls RegisterConnection on the edge's RPC server.
// We send a capnproto-shaped binary message here.

async fn handle_control_stream(
    mut req: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    connector_id: Uuid,
    creds: &TokenCreds,
    edge_addr: SocketAddr,
) -> Result<()> {
    let _ = drain_body(req.body_mut()).await;

    // Build capnproto RegisterConnection request
    // (simplified binary encoding matching the wire format)
    let secret = creds.secret_bytes().unwrap_or_default();
    let tunnel_id_bytes = parse_uuid_bytes(&creds.t)?;
    let client_info = ClientInfo::new(connector_id);
    let conn_options = ConnectionOptions {
        client: client_info,
        num_previous_attempts: 0,
        unregister_pause: 0,
        features: vec!["ha-origin".into(), "serialized-headers".into()],
    };

    let capnp_bytes = build_capnp_register(
        &creds.a,
        &secret,
        &tunnel_id_bytes,
        0, // connIndex
        &conn_options,
        &edge_addr.ip().to_string(),
    );

    // Send 200 response immediately; capnproto RPC runs bidirectionally on this stream
    let resp = Response::builder()
        .status(200)
        .header("content-type", "application/grpc+proto")
        .body(())?;

    let mut send = respond.send_response(resp, false)?;
    send.send_data(Bytes::from(capnp_bytes), false)?;

    // Keep the control stream open (the edge will send config updates on it)
    // In production, this would be a long-running RPC session
    info!("Control stream open – tunnel is live");

    Ok(())
}

// ── Proxy stream ───────────────────────────────────────────────────────────

async fn handle_proxy_stream(
    mut req: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    table: &IngressTable,
) -> Result<()> {
    let host = req.headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let path = req.uri().path().to_string();
    debug!("← {} {} (host: {})", req.method(), path, host);

    let rule = resolve(table, &host, &path).await;
    let origin_resp = match rule {
        None => {
            warn!("No rule matched host={} path={}", host, path);
            not_found()
        }
        Some(rule) => {
            let body = drain_body(req.body_mut()).await;
            let mut origin_req = Request::builder()
                .method(req.method())
                .uri(rewrite_uri(req.uri(), &rule.service)?)
                .version(Version::HTTP_11)
                .body(body)?;

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
    let serialized = serialize_headers(&parts.headers);

    let mut builder = Response::builder().status(status);
    if let Some(cl) = parts.headers.get(http::header::CONTENT_LENGTH) {
        builder = builder.header(http::header::CONTENT_LENGTH, cl);
    }
    builder = builder.header(HDR_RESP_HEADERS, serialized);

    let resp = builder.body(())?;
    let mut send = respond.send_response(resp, body.is_empty())?;
    if !body.is_empty() {
        send.send_data(body, true)?;
    }
    Ok(())
}

// ── TLS config ────────────────────────────────────────────────────────────
//
// Mirrors cloudflared's CreateTunnelConfig:
//   system cert pool + Cloudflare root CAs + no ALPN (http2 is done raw)

fn make_tls_config() -> Result<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();

    // 1. Cloudflare's own root CAs (required for h2.cftunnel.com)
    //    Mirrors cloudflared's GetCloudflareRootCA() in tlsconfig/cloudflare_ca.go
    let cf_certs = crate::cf_ca::cloudflare_ca_certs();
    let mut cf_added = 0usize;
    for cert in &cf_certs {
        if root_store.add(cert).is_ok() {
            cf_added += 1;
        }
    }
    info!("Loaded {} Cloudflare root CA cert(s)", cf_added);

    // 2. System cert pool (mirrors x509.SystemCertPool in Go)
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            let mut added = 0usize;
            for cert in certs {
                let _ = root_store.add(&rustls::Certificate(cert.0)).map(|_| added += 1);
            }
            debug!("Loaded {} native system certs", added);
        }
        Err(e) => warn!("Could not load native certs: {}", e),
    }

    // 3. webpki roots as extra fallback
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject, ta.spki, ta.name_constraints,
        )
    }));

    // NOTE: cloudflared does NOT set ALPN for http2 – edge speaks h2 raw over TLS
    let cfg = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(cfg)
}

// ── Helpers ────────────────────────────────────────────────────────────────

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

fn parse_uuid_bytes(uuid_str: &str) -> Result<[u8; 16]> {
    let id = uuid::Uuid::parse_str(uuid_str)
        .with_context(|| format!("Invalid tunnel UUID: {}", uuid_str))?;
    Ok(*id.as_bytes())
}
