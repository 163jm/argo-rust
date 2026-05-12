//! Minimal RPC layer for tunnel registration over the HTTP/2 control stream.
//!
//! Real cloudflared uses Cap'n Proto RPC. We implement a JSON-over-HTTP/2
//! shim that is wire-compatible with the edge's expectations for the
//! RegisterConnection call.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Sent by cloudflared → edge to register a connection
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterConnectionRequest {
    pub account_tag: String,
    pub tunnel_secret: Vec<u8>,
    pub conn_index: u8,
    pub options: ConnectionOptions,
    pub tunnel_id: String,
    pub edge_addr: String,
}

/// Options negotiated with the edge
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionOptions {
    pub client: ClientInfo,
    pub num_previous_attempts: u8,
    pub unregister_pause: u64,
    pub features: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ClientInfo {
    pub client_id: String,
    pub features: Vec<String>,
    pub version: String,
    pub arch: String,
}

impl ClientInfo {
    pub fn new(connector_id: Uuid) -> Self {
        Self {
            client_id: connector_id.to_string(),
            features: vec!["ha-origin".into(), "serialized-headers".into()],
            version: "2024.11.1".into(),
            arch: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        }
    }
}

/// Response from edge on successful registration
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterConnectionResponse {
    pub location: Option<String>,
    pub error: Option<String>,
}
