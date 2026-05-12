use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;

/// Configuration for a tunnel session
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub local_url: String,
    pub token: Option<String>,
    pub quick_tunnel: bool,
    pub hostname: Option<String>,
}

/// Decoded tunnel token – {"a":"accountTag","s":"tunnelSecret","t":"tunnelID"}
#[derive(Debug, Clone, Deserialize)]
pub struct TokenCreds {
    /// Account tag
    pub a: String,
    /// Tunnel secret (base64-encoded 32-byte secret)
    pub s: String,
    /// Tunnel UUID
    pub t: String,
}

impl TokenCreds {
    pub fn from_token(token: &str) -> Result<Self> {
        // Token is standard base64 (may have padding)
        let decoded = STANDARD
            .decode(token.trim())
            .or_else(|_| {
                use base64::engine::general_purpose::URL_SAFE;
                URL_SAFE.decode(token.trim())
            })
            .or_else(|_| {
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                URL_SAFE_NO_PAD.decode(token.trim())
            })?;

        let creds: TokenCreds = serde_json::from_slice(&decoded)?;
        Ok(creds)
    }

    /// The tunnel secret as raw bytes (base64-decoded)
    pub fn secret_bytes(&self) -> Result<Vec<u8>> {
        let bytes = STANDARD
            .decode(&self.s)
            .or_else(|_| {
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                URL_SAFE_NO_PAD.decode(&self.s)
            })?;
        if bytes.len() < 32 {
            bail!("Tunnel secret too short: {} bytes", bytes.len());
        }
        Ok(bytes)
    }
}
