//! Fetch and manage ingress rules from Cloudflare API
//!
//! GET https://api.cloudflare.com/client/v4/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Context, Result};
use tracing::{info, warn, debug};

use crate::config::{IngressRule, TokenCreds, TunnelConfiguration};

const CF_API: &str = "https://api.cloudflare.com/client/v4";

/// Shared, hot-reloadable ingress table
pub type IngressTable = Arc<RwLock<Vec<IngressRule>>>;

/// Fetch ingress rules from Cloudflare API using the tunnel token as Bearer auth.
/// The token inside the decoded credentials acts as the API credential.
pub async fn fetch_ingress(creds: &TokenCreds, raw_token: &str) -> Result<Vec<IngressRule>> {
    let url = format!(
        "{}/accounts/{}/cfd_tunnel/{}/configurations",
        CF_API, creds.a, creds.t
    );
    debug!("Fetching tunnel config from: {}", url);

    // Use the original raw token as Bearer (Cloudflare accepts it for tunnel auth)
    let client = build_http_client()?;
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", raw_token))
        .header("Content-Type", "application/json")
        .send()
        .await
        .context("Failed to call Cloudflare API")?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        anyhow::bail!("Cloudflare API error {}: {}", status, body);
    }

    debug!("Config API response: {}", &body[..body.len().min(500)]);

    // Response: { "result": { "config": { "ingress": [...] } }, "success": true }
    #[derive(serde::Deserialize)]
    struct ApiResponse {
        result: Option<TunnelConfiguration>,
        success: bool,
        errors: Option<Vec<serde_json::Value>>,
    }

    let parsed: ApiResponse = serde_json::from_str(&body)
        .context("Failed to parse Cloudflare API response")?;

    if !parsed.success {
        anyhow::bail!("Cloudflare API returned success=false: {:?}", parsed.errors);
    }

    let rules = parsed
        .result
        .map(|r| r.config.ingress)
        .unwrap_or_default();

    info!("Loaded {} ingress rule(s) from Cloudflare", rules.len());
    for (i, rule) in rules.iter().enumerate() {
        if rule.hostname.is_empty() {
            info!("  Rule {}: (catch-all) → {}", i + 1, rule.service);
        } else {
            info!(
                "  Rule {}: {}{}  → {}",
                i + 1,
                rule.hostname,
                if rule.path.is_empty() { String::new() } else { format!("/{}", rule.path) },
                rule.service
            );
        }
    }

    Ok(rules)
}

/// Spawn a background task that refreshes ingress rules every `interval` seconds
pub fn start_refresh_task(
    creds: TokenCreds,
    raw_token: String,
    table: IngressTable,
    interval_secs: u64,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
            match fetch_ingress(&creds, &raw_token).await {
                Ok(rules) => {
                    *table.write().await = rules;
                    info!("Ingress rules refreshed");
                }
                Err(e) => {
                    warn!("Failed to refresh ingress rules: {}", e);
                }
            }
        }
    });
}

/// Match a request (host + path) against the ingress table, return the winning rule
pub async fn resolve(table: &IngressTable, host: &str, path: &str) -> Option<IngressRule> {
    let rules = table.read().await;
    rules.iter().find(|r| r.matches(host, path)).cloned()
}

fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("Failed to build HTTP client")
}
