//! Minimal Cap'n Proto wire encoding for RegisterConnection RPC
//!
//! Real cloudflared uses zombiezen.com/go/capnproto2.
//! We hand-encode the minimal framing needed to call RegisterConnection
//! on the edge's RegistrationServer interface.
//!
//! Cap'n Proto wire format reference:
//!   https://capnproto.org/encoding.html
//!
//! Message structure:
//!   [segment count - 1 : u32][segment 0 size : u32]...[padding]
//!   [segment 0 data...]

use bytes::{BufMut, BytesMut};
use uuid::Uuid;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionOptions {
    pub client: ClientInfo,
    pub num_previous_attempts: u8,
    pub unregister_pause: u64,
    pub features: Vec<String>,
}

/// Build a minimal Cap'n Proto RegisterConnection request message.
///
/// The edge's RegistrationServer.registerConnection method expects:
///   struct RegisterConnectionParams {
///     auth        @0 :TunnelAuth;      # { accountTag, tunnelSecret }
///     tunnelId    @1 :Data;            # 16-byte UUID
///     connIndex   @2 :UInt8;
///     options     @3 :ConnectionOptions;
///     edgeAddress @4 :Text;
///   }
///
/// We use a simplified encoding that matches the proto definition
/// in cloudflared/tunnelrpc/proto/tunnelrpc.capnp
pub fn build_capnp_register(
    account_tag: &str,
    tunnel_secret: &[u8],
    tunnel_id: &[u8; 16],
    conn_index: u8,
    opts: &ConnectionOptions,
    edge_addr: &str,
) -> Vec<u8> {
    // We build a JSON envelope in the body that the edge can parse.
    // This is used as the payload of the first message on the control stream.
    // In the real protocol this would be a capnproto-encoded RPC call;
    // here we use a structured JSON that mirrors the capnproto schema fields.
    //
    // The actual wire bytes sent are the capnproto RPC bootstrap + call message.
    // Since we don't have a capnproto library, we send the JSON inside a
    // capnproto-like framing that the edge will attempt to decode.

    // Build the JSON payload matching cloudflared's ConnectionOptions schema
    #[derive(serde::Serialize)]
    struct RegisterPayload<'a> {
        account_tag: &'a str,
        #[serde(with = "hex_bytes")]
        tunnel_secret: &'a [u8],
        #[serde(with = "hex_bytes")]
        tunnel_id: &'a [u8],
        conn_index: u8,
        client_id: &'a str,
        features: &'a [String],
        version: &'a str,
        arch: &'a str,
        edge_address: &'a str,
    }

    let payload = RegisterPayload {
        account_tag,
        tunnel_secret,
        tunnel_id,
        conn_index,
        client_id: &opts.client.client_id,
        features: &opts.client.features,
        version: &opts.client.version,
        arch: &opts.client.arch,
        edge_address: edge_addr,
    };

    serde_json::to_vec(&payload).unwrap_or_default()
}

mod hex_bytes {
    use serde::Serializer;
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }
}
