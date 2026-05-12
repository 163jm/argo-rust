use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use anyhow::{Result, bail};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    HttpRequest  = 0x01,
    HttpResponse = 0x02,
    StreamOpen   = 0x03,
    StreamData   = 0x04,
    StreamClose  = 0x05,
    Ping         = 0x06,
    Pong         = 0x07,
    Register     = 0x08,
    RegisterAck  = 0x09,
    Error        = 0xFF,
}

impl TryFrom<u8> for Opcode {
    type Error = anyhow::Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::HttpRequest),
            0x02 => Ok(Self::HttpResponse),
            0x03 => Ok(Self::StreamOpen),
            0x04 => Ok(Self::StreamData),
            0x05 => Ok(Self::StreamClose),
            0x06 => Ok(Self::Ping),
            0x07 => Ok(Self::Pong),
            0x08 => Ok(Self::Register),
            0x09 => Ok(Self::RegisterAck),
            0xFF => Ok(Self::Error),
            other => bail!("Unknown opcode: 0x{:02x}", other),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TunnelFrame {
    pub opcode: Opcode,
    pub stream_id: u32,
    pub payload: Bytes,
}

impl TunnelFrame {
    pub fn new(opcode: Opcode, stream_id: u32, payload: impl Into<Bytes>) -> Self {
        Self { opcode, stream_id, payload: payload.into() }
    }

    /// 编码: [opcode:1][stream_id:4][payload_len:4][payload]
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(9 + self.payload.len());
        buf.put_u8(self.opcode as u8);
        buf.put_u32(self.stream_id);
        buf.put_u32(self.payload.len() as u32);
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.len() < 9 {
            bail!("Frame too short: {} bytes", data.len());
        }
        let opcode = Opcode::try_from(data.get_u8())?;
        let stream_id = data.get_u32();
        let payload_len = data.get_u32() as usize;
        if data.remaining() < payload_len {
            bail!("Truncated payload: expected {}, got {}", payload_len, data.remaining());
        }
        let payload = data.copy_to_bytes(payload_len);
        Ok(Self { opcode, stream_id, payload })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestMeta {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseMeta {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationPayload {
    pub connector_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_token: Option<String>,
    pub version: String,
    pub arch: String,
    pub features: Vec<String>,
}

impl RegistrationPayload {
    pub fn new(connector_id: String, tunnel_token: Option<String>) -> Self {
        Self {
            connector_id,
            tunnel_token,
            version: "mini-cloudflared/0.1.0".into(),
            arch: std::env::consts::ARCH.into(),
            features: vec!["http2".into(), "quic".into()],
        }
    }
}
