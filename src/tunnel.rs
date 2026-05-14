//! Cloudflare Tunnel HTTP/2 + capnp-rpc transport
//!
//! Protocol:
//!   cloudflared = HTTP/2 server + capnp-rpc CLIENT (we call RegisterConnection)
//!   edge        = HTTP/2 client + capnp-rpc SERVER (RegistrationServer)
//!
//! Control stream:
//!   1. Edge opens h2 stream with upgrade header "control-stream"
//!   2. We respond 200, keep stream open
//!   3. We wrap the h2 stream as capnp-rpc twoparty VatNetwork (Client side)
//!   4. capnp-rpc Bootstrap() → get RegistrationServer capability
//!   5. Call RegisterConnection(auth, tunnelId, connIndex, options)
//!   6. Stream stays open for graceful shutdown / config updates

use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use capnp::capability::Promise;
use capnp::message::{Builder as MsgBuilder, HeapAllocator, ReaderOptions};
use capnp_rpc::{rpc_twoparty_capnp, twoparty, RpcSystem};
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

    let mut h2 = h2::server::handshake(tls).await
        .context("h2 handshake")?;
    info!("HTTP/2 connected to {} ✓", addr);

    loop {
        match h2.accept().await {
            Some(Ok((req, respond))) => {
                let upg = req.headers().get(HDR_UPGRADE)
                    .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                if upg == CONTROL_STREAM_VAL {
                    debug!("Control stream");
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

// ── Control stream ────────────────────────────────────────────────────────

async fn handle_control_stream(
    req: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    connector_id: Uuid,
    creds: &TokenCreds,
    edge_addr: SocketAddr,
) -> Result<()> {
    // Respond 200, get the SendStream back for writing RPC data
    let resp = Response::builder().status(200)
        .header("content-type", "application/grpc+proto")
        .body(())?;
    let send_stream = respond.send_response(resp, false)?;

    // Wrap h2 streams as capnp-rpc AsyncRead/AsyncWrite
    let recv_stream = req.into_body();
    let reader = H2Reader::new(recv_stream);
    let writer = H2Writer::new(send_stream);

    // Run capnp-rpc on a LocalSet (capnp-rpc uses Rc internally, not Send)
    let secret    = creds.secret_bytes().unwrap_or_default();
    let tunnel_id = parse_uuid_bytes(&creds.t)?;
    let client_id = *connector_id.as_bytes();
    let account   = creds.a.clone();
    let tunnel_id_str = creds.t.clone();

    // capnp-rpc must run on a single-threaded executor (uses Rc<RefCell<>>)
    let local = tokio::task::LocalSet::new();
    let result = local.run_until(async move {
        run_rpc_client(reader, writer, account, secret, tunnel_id, client_id, edge_addr).await
    }).await;

    match result {
        Ok(location) => {
            info!("✅ Tunnel registered! Location: {}", location);
            info!("   Tunnel ID: {}", tunnel_id_str);
        }
        Err(e) => {
            warn!("Registration failed: {}", e);
            return Err(e);
        }
    }

    Ok(())
}

// ── capnp-rpc client ──────────────────────────────────────────────────────

async fn run_rpc_client(
    reader: H2Reader,
    writer: H2Writer,
    account_tag: String,
    tunnel_secret: Vec<u8>,
    tunnel_id: [u8; 16],
    client_id: [u8; 16],
    edge_addr: SocketAddr,
) -> Result<String> {
    use capnp_rpc::rpc_twoparty_capnp::Side;

    // Build twoparty VatNetwork: we are the Client side
    let mut network = twoparty::VatNetwork::new(
        reader,
        writer,
        Side::Client,
        ReaderOptions::new(),
    );

    // Get the connection handle to bootstrap
    let mut rpc_system = RpcSystem::new(Box::new(network), None);

    // Bootstrap → get the RegistrationServer capability from edge.
    struct AnyClient(capnp::capability::Client);
    impl capnp::capability::FromClientHook for AnyClient {
        fn new(hook: Box<dyn capnp::private::capability::ClientHook>) -> Self {
            AnyClient(capnp::capability::Client::new(hook))
        }
        fn into_client_hook(self) -> Box<dyn capnp::private::capability::ClientHook> {
            self.0.hook
        }
        fn as_client_hook(&self) -> &dyn capnp::private::capability::ClientHook {
            &*self.0.hook
        }
    }
    let AnyClient(reg_server) = rpc_system.bootstrap(Side::Server);

    // Drive the RPC system in the background
    tokio::task::spawn_local(async move {
        if let Err(e) = rpc_system.await {
            debug!("RPC system ended: {}", e);
        }
    });

    // Build RegisterConnection request using our custom capnp encoder
    // We call the method via the raw capability client
    let os_arch = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let features = ["ha-origin", "serialized-headers"];

    // Build the params message
    let params_bytes = encode_register_connection(
        &account_tag, &tunnel_secret, &tunnel_id, 0,
        &client_id, "2024.11.1", &os_arch, &features,
    );

    // Make the raw RPC call using the capability interface ID
    let mut request: capnp::capability::Request<capnp::any_pointer::Owned, capnp::any_pointer::Owned> = reg_server.new_call(
        REGISTRATION_SERVER_ID,
        0, // method 0 = registerConnection
        Some(capnp::MessageSize { word_count: 32, cap_count: 0 }),
    );

    // Set the params from our pre-encoded bytes
    // We need to copy our encoded struct into the request's params
    fill_request_params(request.get(), &params_bytes)?;

    // Send and await response
    let response = request.send().promise
        .await
        .map_err(|e| anyhow::anyhow!("RegisterConnection failed: {}", e))?;

    // Parse the ConnectionResponse
    let location = parse_connection_response(response.get()
        .map_err(|e| anyhow::anyhow!("Bad response: {}", e))?)?;

    Ok(location)
}

/// Copy our pre-built capnp struct bytes into the RPC request params
fn fill_request_params(
    mut params: capnp::any_pointer::Builder,
    encoded_bytes: &[u8],
) -> Result<()> {
    // The encoded_bytes is a framed capnp message containing our params struct.
    // We need to read it back and copy the struct into the params slot.
    let reader = capnp::serialize::read_message(
        &mut &encoded_bytes[..],
        ReaderOptions::new(),
    ).context("Failed to re-read encoded params")?;

    let src: capnp::any_pointer::Reader = reader.get_root()
        .context("Failed to get root of encoded params")?;

    params.set_as(src).context("Failed to copy params")?;
    Ok(())
}

/// Parse ConnectionResponse → just return "connected" (success = no exception)
fn parse_connection_response(
    _results: capnp::any_pointer::Reader,
) -> Result<String> {
    // If we reached here without an error, registration succeeded.
    // The real location name would need generated capnp code to decode.
    Ok("connected".to_string())
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
            dispatch(&rule, origin_req).await.unwrap_or_else(|e| { warn!("Origin: {}", e); bad_gateway() })
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
    for cert in crate::cf_ca::cloudflare_ca_certs() {
        let _ = root_store.add(&cert);
    }
    if let Ok(certs) = rustls_native_certs::load_native_certs() {
        for c in certs { let _ = root_store.add(&rustls::Certificate(c.0)); }
    }
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
    }));
    Ok(ClientConfig::builder().with_safe_defaults()
        .with_root_certificates(root_store).with_no_client_auth())
}

// ── Helpers ───────────────────────────────────────────────────────────────

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
