//! Forward requests to local origin services based on ingress rules

use anyhow::Result;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::warn;

use crate::config::IngressRule;

/// Dispatch a request to the appropriate origin based on the matched ingress rule
pub async fn dispatch(rule: &IngressRule, req: Request<Bytes>) -> Result<Response<Bytes>> {
    // Handle status-only rules
    if let Some(code) = rule.status_code() {
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::NOT_FOUND);
        return Ok(Response::builder()
            .status(status)
            .body(Bytes::from(format!("{}", status)))
            .unwrap());
    }

    // hello_world test server
    if rule.service == "hello_world" {
        return Ok(hello_world_response());
    }

    forward_http(&rule.service, req).await
}

/// Forward HTTP/1.1 request to the local service and return response
pub async fn forward_http(origin_url: &str, req: Request<Bytes>) -> Result<Response<Bytes>> {
    let origin = url::Url::parse(origin_url)?;
    let host = origin.host_str().unwrap_or("127.0.0.1");
    let port = origin.port_or_known_default().unwrap_or(80);

    let mut stream = tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await?;

    // Build HTTP/1.1 request
    let method = req.method().as_str();
    let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let mut raw = format!("{} {} HTTP/1.1\r\nHost: {}:{}\r\n", method, path, host, port);

    for (k, v) in req.headers() {
        // Skip hop-by-hop headers
        match k.as_str() {
            "host" | "connection" | "proxy-connection" |
            "transfer-encoding" | "upgrade" => continue,
            _ => {}
        }
        if let Ok(v) = v.to_str() {
            raw.push_str(&format!("{}: {}\r\n", k, v));
        }
    }

    let body = req.body();
    if !body.is_empty() {
        raw.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    raw.push_str("Connection: close\r\n\r\n");

    stream.write_all(raw.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }

    // Read full response
    let mut buf = Vec::with_capacity(32768);
    stream.read_to_end(&mut buf).await?;

    parse_http1_response(buf)
}

fn parse_http1_response(raw: Vec<u8>) -> Result<Response<Bytes>> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let status = resp.parse(&raw)?;

    let header_len = match status {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => {
            warn!("Partial HTTP response from origin");
            return Ok(bad_gateway());
        }
    };

    let code = resp.code.unwrap_or(502);
    let mut builder = Response::builder().status(code);
    for h in resp.headers.iter() {
        builder = builder.header(h.name, h.value);
    }

    let body = Bytes::copy_from_slice(&raw[header_len..]);
    Ok(builder.body(body)?)
}

pub fn bad_gateway() -> Response<Bytes> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Bytes::from_static(b"502 Bad Gateway\n"))
        .unwrap()
}

pub fn not_found() -> Response<Bytes> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Bytes::from_static(b"404 No matching ingress rule\n"))
        .unwrap()
}

fn hello_world_response() -> Response<Bytes> {
    let body = Bytes::from_static(b"<!DOCTYPE html><html><body>\
        <h1>mini-cloudflared</h1>\
        <p>Hello World! The tunnel is working.</p>\
        </body></html>");
    Response::builder()
        .status(200)
        .header("content-type", "text/html")
        .body(body)
        .unwrap()
}
