//! Forward requests to the local origin service

use anyhow::Result;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

/// Forward an HTTP/1.1 request to the local origin and return the response
pub async fn forward_http(
    origin_url: &str,
    req: Request<Bytes>,
) -> Result<Response<Bytes>> {
    let origin = url::Url::parse(origin_url)?;
    let host = origin.host_str().unwrap_or("127.0.0.1");
    let port = origin.port_or_known_default().unwrap_or(80);

    // Connect TCP
    let mut stream = tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await?;

    // Build HTTP/1.1 request
    let method = req.method().as_str();
    let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let mut raw = format!("{} {} HTTP/1.1\r\nHost: {}:{}\r\n", method, path, host, port);
    for (k, v) in req.headers() {
        if k == http::header::HOST { continue; }
        raw.push_str(&format!("{}: {}\r\n", k, v.to_str().unwrap_or("")));
    }
    raw.push_str("Connection: close\r\n\r\n");

    stream.write_all(raw.as_bytes()).await?;
    if !req.body().is_empty() {
        stream.write_all(req.body()).await?;
    }

    // Read full response
    let mut buf = Vec::with_capacity(8192);
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
        .body(Bytes::from_static(b"502 Bad Gateway"))
        .unwrap()
}
