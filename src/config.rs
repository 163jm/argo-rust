#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub local_url: String,
    pub token: Option<String>,
    pub quick_tunnel: bool,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TokenInfo {
    pub a: String,
    pub s: String,
    pub t: String,
}

impl TokenInfo {
    pub fn from_token(token: &str) -> anyhow::Result<Self> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let decoded = URL_SAFE_NO_PAD.decode(token)?;
        let info: TokenInfo = serde_json::from_slice(&decoded)?;
        Ok(info)
    }
}
