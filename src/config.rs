use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;

/// CLI-level configuration
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub token: String,
    pub quick_tunnel: bool,
}

/// Decoded tunnel token – {"a":"accountTag","s":"tunnelSecret","t":"tunnelID"}
#[derive(Debug, Clone, Deserialize)]
pub struct TokenCreds {
    /// Account tag (= account_id)
    pub a: String,
    /// Tunnel secret (base64-encoded 32 bytes)
    pub s: String,
    /// Tunnel UUID
    pub t: String,
}

impl TokenCreds {
    pub fn from_token(token: &str) -> Result<Self> {
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

// ── Remote ingress config (from Cloudflare API) ───────────────────────────

/// Full configuration returned by the Cloudflare tunnel config API
#[derive(Debug, Clone, Deserialize)]
pub struct TunnelConfiguration {
    pub config: IngressConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IngressConfig {
    pub ingress: Vec<IngressRule>,
}

/// A single ingress rule: maps a hostname+path to a local service
#[derive(Debug, Clone, Deserialize)]
pub struct IngressRule {
    /// Hostname to match (empty = catch-all)
    #[serde(default)]
    pub hostname: String,
    /// Path prefix/regex (empty = match all paths)
    #[serde(default)]
    pub path: String,
    /// Local service URL, e.g. "http://localhost:8080" or "http_status:404"
    pub service: String,
}

impl IngressRule {
    /// Returns true if this rule matches the given host and path
    pub fn matches(&self, host: &str, path: &str) -> bool {
        // Catch-all rule
        if self.hostname.is_empty() {
            return true;
        }
        // Hostname match (case-insensitive, strip port)
        let rule_host = self.hostname.to_lowercase();
        let req_host = host.split(':').next().unwrap_or(host).to_lowercase();
        let host_matches = if rule_host.starts_with("*.") {
            // Wildcard: *.example.com matches foo.example.com
            let suffix = &rule_host[1..]; // ".example.com"
            req_host.ends_with(suffix)
        } else {
            rule_host == req_host
        };
        if !host_matches {
            return false;
        }
        // Path match
        if self.path.is_empty() {
            return true;
        }
        path.starts_with(&self.path)
    }

    /// Is this a status-only rule like "http_status:404"?
    pub fn status_code(&self) -> Option<u16> {
        self.service
            .strip_prefix("http_status:")
            .and_then(|s| s.parse().ok())
    }
}
