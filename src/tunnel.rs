//! Cloudflare Tunnel HTTP/2 + capnp-rpc transport

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use capnp::message::ReaderOptions;
use capnp_rpc::{rpc_twoparty_capnp::Side, twoparty, RpcSystem};
use futures_util::FutureExt;
use h2::server::SendResponse;
use h2::RecvStream;
use http::{HeaderMap, Request, Response, Uri, Version};
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::capnp_rpc::{encode_register_connection, REGISTRATION_SERVER_ID};
use crate::config::{TokenCreds, TunnelConfig};
use crate::edge::{resolve_edge_addrs, EDGE_SNI};
use crate::h2_stream::{H2Reader, H2Writer};
use crate::ingress::{make_table, print_rules, resolve, start_reload_task, IngressTable};
use crate::origin::{bad_gateway, dispatch, not_found};

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
            "Config file not found. Create ~/.cloudflared/config.yaml:\n\n\
             ingress:\n  - hostname: example.com\n    service: http://localhost:8080\n\
             \n  - service: http_status:404\n"
        )?;

    info!("Config     : {}", config_path.display());
    let rules = crate::ingress::load_from_file(&config_path)?;
    print_rules(&rules);
    let table = make_table(rules);
    start_reload_task(config_path, Arc::clone(&table), CONFIG_RELOAD_INTERVAL);

    let addrs = resolve_edge_addrs().await?;
    if addrs.is_empty() { bail!("No edge addresses"); }

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
            Ok(()) => { info!("Reconnecting…"); backoff = Duration::from_secs(1); }
            Err(e) => {
                warn!("Error: {}. Retry in {:?}…", e, backoff);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(64));
            }
        }
    }
}

// ── Connect + HTTP/2 ──────────────────────────────────────────────────────

async fn connect_and_serve(
    addr: SocketAddr,
    connector_id: Uuid,
    creds: &TokenCreds,
    table: &IngressTable,
    connector: &TlsConnector,
) -> Result<()> {
    let tcp = TcpStream::connect(addr).await
        .with_context(|| format!("TCP {}", addr))?;
    tcp.set_nodelay(true)?;

    let domain = rustls::ServerName::try_from(EDGE_SNI)
        .map_err(|_| anyhow::anyhow!("bad SNI"))?;
    let tls = connector.connect(domain, tcp).await
        .map_err(|e| anyhow::anyhow!("TLS {}: {:?}", addr, e))?;
    {
        let (_, s) = tls.get_ref();
        info!("TLS OK – {:?}", s.protocol_version());
    }

    let mut h2 = h2::server::handshake(tls).await.context("h2 handshake")?;
    info!("HTTP/2 connected to {} ✓", addr);

    loop {
        match h2.accept().await {
            Some(Ok((req, respond))) => {
                let upg = req.headers().get(HDR_UPGRADE)
                    .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                if upg == CONTROL_STREAM_VAL {
                    info!("Control stream received");
                    handle_control_stream(req, respond, connector_id, creds, addr).await?;
                } else {
                    let table = Arc::clone(table);
                    tokio::spawn(async move {
                        if let Err(e) = handle_proxy_stream(req, respond, &table).await {
                            error!("Proxy: {}", e);
                        }
                    });
                }
            }
            Some(Err(e)) if e.is_go_away() => { info!("GOAWAY"); break; }
            Some(Err(e)) => return Err(e.into()),
            None => break,
        }
    }
    Ok(())
}

// ── Control stream ─────────────────────────────────────────────────────────

async fn handle_control_stream(
    req: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    connector_id: Uuid,
    creds: &TokenCreds,
    edge_addr: SocketAddr,
) -> Result<()> {
    // Send 200, get the send stream handle
    let resp = Response::builder().status(200)
        .header("content-type", "application/grpc+proto")
        .body(())?;
    let send_stream = respond.send_response(resp, false)?;

    let recv_stream = req.into_body();
    let reader = H2Reader::new(recv_stream);
    let writer = H2Writer::new(send_stream);

    // capnp-rpc uses Rc<RefCell> – must run on a LocalSet
    let secret    = creds.secret_bytes().unwrap_or_default();
    let tunnel_id = parse_uuid_bytes(&creds.t)?;
    let client_id = *connector_id.as_bytes();
    let account   = creds.a.clone();
    let tunnel_str = creds.t.clone();

    let local = tokio::task::LocalSet::new();
    local.run_until(async move {
        match rpc_register(reader, writer, account, secret, tunnel_id, client_id, edge_addr).await {
            Ok(location) => {
                info!("✅ Tunnel registered! Location: {}", location);
                info!("   Tunnel ID: {}", tunnel_str);
                // Keep alive forever (until GOAWAY)
                futures_util::future::pending::<()>().await;
            }
            Err(e) => {
                warn!("Registration failed: {}", e);
            }
        }
    }).await;

    Ok(())
}

// ── capnp-rpc registration ─────────────────────────────────────────────────

async fn rpc_register(
    reader: H2Reader,
    writer: H2Writer,
    account_tag: String,
    tunnel_secret: Vec<u8>,
    tunnel_id: [u8; 16],
    client_id: [u8; 16],
    edge_addr: SocketAddr,
) -> Result<String> {
    use crate::tunnelrpc_capnp::registration_server;

    // Build twoparty network: we are the Client, edge is the Server
    let network = twoparty::VatNetwork::new(
        reader, writer, Side::Client, ReaderOptions::new(),
    );
    let mut rpc_system = RpcSystem::new(Box::new(network), None);

    // Bootstrap: get the RegistrationServer capability from edge
    // registration_server::Client implements FromClientHook (generated code)
    let reg_server: registration_server::Client = rpc_system.bootstrap(Side::Server);

    // Build a typed RegisterConnection request
    let mut request = reg_server.register_connection_request();

    // Fill params using generated typed builders
    {
        let mut p = request.get();

        // auth: TunnelAuth { accountTag, tunnelSecret }
        let mut auth = p.reborrow().init_auth();
        auth.set_account_tag(account_tag.as_str().into());
        auth.set_tunnel_secret(&tunnel_secret);

        // tunnelId: 16-byte UUID
        p.reborrow().set_tunnel_id(&tunnel_id);

        // connIndex
        p.reborrow().set_conn_index(0);

        // options: ConnectionOptions
        let mut opts = p.init_options();
        opts.set_num_previous_attempts(0);

        // client: ClientInfo
        let mut client = opts.init_client();
        client.set_client_id(&client_id);

        let os_arch = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        let features = ["ha-origin", "serialized-headers"];

        // features: List(Text)
        let mut feat_list = client.reborrow().init_features(features.len() as u32);
        for (i, &f) in features.iter().enumerate() {
            feat_list.set(i as u32, f.into());
        }

        client.set_version("2024.11.1".into());
        client.set_arch(os_arch.as_str().into());
    }

    info!("Sending RegisterConnection to edge...");

    // Drive RPC + call concurrently (rpc_system must be polled for messages to flow)
    let rpc_future  = rpc_system.map(|r| debug!("RPC done: {:?}", r.map_err(|e| e.to_string())));
    let call_future = request.send().promise;

    let response = tokio::select! {
        _ = rpc_future => bail!("RPC system exited before response"),
        resp = call_future => resp.map_err(|e| anyhow::anyhow!("RegisterConnection: {}", e))?,
    };

    info!("Got response from edge");

    // Parse ConnectionResponse using generated types
    let results = response.get()
        .map_err(|e| anyhow::anyhow!("response.get: {}", e))?;

    // results is register_connection_results::Reader
    // It has get_result() → connection_response::Reader
    // which has get_result() → connection_response::result::Reader (the union)
    let conn_resp = results.get_result()
        .map_err(|e| anyhow::anyhow!("get_result: {}", e))?;
    let result_reader = conn_resp.get_result();

    use crate::tunnelrpc_capnp::connection_response::result::Which;
    match result_reader.which().map_err(|e| anyhow::anyhow!("which: {}", e))? {
        Which::Error(e) => {
            let err = e.map_err(|e| anyhow::anyhow!("error read: {}", e))?;
            let cause = err.get_cause()
                .map(|c| c.to_str().unwrap_or("").to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            bail!("Edge rejected registration: {}", cause);
        }
        Which::ConnectionDetails(d) => {
            let details = d.map_err(|e| anyhow::anyhow!("details read: {}", e))?;
            let location = details.get_location_name()
                .map(|l| l.to_str().unwrap_or("").to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            Ok(location)
        }
    }
}

// ── Proxy stream ───────────────────────────────────────────────────────────

async fn handle_proxy_stream(
    mut req: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    table: &IngressTable,
) -> Result<()> {
    let host = req.headers().get(http::header::HOST)
        .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let path = req.uri().path().to_string();
    debug!("← {} {} host={}", req.method(), path, host);

    let rule = resolve(table, &host, &path).await;
    let origin_resp = match rule {
        None => { warn!("No rule: host={}", host); not_found() }
        Some(rule) => {
            let body = drain_body(req.body_mut()).await;
            let mut origin_req = Request::builder()
                .method(req.method()).uri(rewrite_uri(req.uri(), &rule.service)?)
                .version(Version::HTTP_11).body(body)?;
            for (k, v) in req.headers() {
                let ks = k.as_str();
                if ks.starts_with(':') || ks == "host" || ks == HDR_UPGRADE { continue; }
                origin_req.headers_mut().insert(k, v.clone());
            }
            dispatch(&rule, origin_req).await.unwrap_or_else(|e| {
                warn!("Origin: {}", e); bad_gateway()
            })
        }
    };

    let (parts, body) = origin_resp.into_parts();
    let serialized = serialize_headers(&parts.headers);
    let mut builder = Response::builder().status(parts.status);
    if let Some(cl) = parts.headers.get(http::header::CONTENT_LENGTH) {
        builder = builder.header(http::header::CONTENT_LENGTH, cl);
    }
    builder = builder.header(HDR_RESP_HEADERS, serialized);
    let resp = builder.body(())?;
    let mut send = respond.send_response(resp, body.is_empty())?;
    if !body.is_empty() { send.send_data(body, true)?; }
    Ok(())
}

// ── TLS config ─────────────────────────────────────────────────────────────

fn make_tls_config() -> Result<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in crate::cf_ca::cloudflare_ca_certs() { let _ = root_store.add(&cert); }
    if let Ok(certs) = rustls_native_certs::load_native_certs() {
        for c in certs { let _ = root_store.add(&rustls::Certificate(c.0)); }
    }
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
    }));
    Ok(ClientConfig::builder().with_safe_defaults()
        .with_root_certificates(root_store).with_no_client_auth())
}

// ── Helpers ────────────────────────────────────────────────────────────────

async fn drain_body(body: &mut RecvStream) -> Bytes {
    let mut buf = bytes::BytesMut::new();
    while let Some(chunk) = body.data().await {
        if let Ok(data) = chunk {
            let _ = body.flow_control().release_capacity(data.len());
            buf.extend_from_slice(&data);
        }
    }
    buf.freeze()
}

fn rewrite_uri(original: &Uri, service_url: &str) -> Result<Uri> {
    let base = url::Url::parse(service_url)?;
    let path = original.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    Ok(format!("{}://{}:{}{}", base.scheme(), base.host_str().unwrap_or("127.0.0.1"),
        base.port_or_known_default().unwrap_or(80), path).parse()?)
}

fn serialize_headers(headers: &HeaderMap) -> String {
    headers.iter()
        .filter(|(k, _)| *k != http::header::CONTENT_LENGTH)
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
        .collect::<Vec<_>>().join("\r\n")
}

fn parse_uuid_bytes(s: &str) -> Result<[u8; 16]> {
    Ok(*uuid::Uuid::parse_str(s)?.as_bytes())
}
