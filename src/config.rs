use std::path::PathBuf;
use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;

/// CLI-level tunnel configuration
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub token: String,
    pub quick_tunnel: bool,
    /// Path to config.yaml with ingress rules
    pub config_file: Option<PathBuf>,
}

/// Decoded tunnel token – {"a":"accountTag","s":"tunnelSecret","t":"tunnelID"}
#[derive(Debug, Clone, Deserialize)]
pub struct TokenCreds {
    pub a: String,   // account tag
    pub s: String,   // tunnel secret (base64)
    pub t: String,   // tunnel UUID
}

impl TokenCreds {
    pub fn from_token(token: &str) -> Result<Self> {
        let decoded = STANDARD.decode(token.trim())
            .or_else(|_| { use base64::engine::general_purpose::URL_SAFE; URL_SAFE.decode(token.trim()) })
            .or_else(|_| { use base64::engine::general_purpose::URL_SAFE_NO_PAD; URL_SAFE_NO_PAD.decode(token.trim()) })?;
        Ok(serde_json::from_slice(&decoded)?)
    }

    pub fn secret_bytes(&self) -> Result<Vec<u8>> {
        let bytes = STANDARD.decode(&self.s)
            .or_else(|_| { use base64::engine::general_purpose::URL_SAFE_NO_PAD; URL_SAFE_NO_PAD.decode(&self.s) })?;
        if bytes.len() < 32 { bail!("Tunnel secret too short"); }
        Ok(bytes)
    }
}

/// A single ingress rule from config.yaml
#[derive(Debug, Clone, Deserialize)]
pub struct IngressRule {
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub path: String,
    pub service: String,
}

impl IngressRule {
    pub fn matches(&self, host: &str, path: &str) -> bool {
        if self.hostname.is_empty() { return true; }
        let rule_host = self.hostname.to_lowercase();
        let req_host = host.split(':').next().unwrap_or(host).to_lowercase();
        let host_ok = if rule_host.starts_with("*.") {
            req_host.ends_with(&rule_host[1..])
        } else {
            rule_host == req_host
        };
        if !host_ok { return false; }
        self.path.is_empty() || path.starts_with(&self.path)
    }

    pub fn status_code(&self) -> Option<u16> {
        self.service.strip_prefix("http_status:").and_then(|s| s.parse().ok())
    }
}
