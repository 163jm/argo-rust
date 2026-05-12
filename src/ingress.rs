//! Ingress rule management
//!
//! Rules are loaded from a local config file (YAML/JSON), same format as
//! official cloudflared. No Cloudflare API call needed.
//!
//! Example config.yaml:
//!   ingress:
//!     - hostname: example.com
//!       service: http://localhost:8080
//!     - hostname: api.example.com
//!       service: http://localhost:3000
//!     - service: http_status:404   # catch-all (required)

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{info, warn};

use crate::config::IngressRule;

pub type IngressTable = Arc<RwLock<Vec<IngressRule>>>;

// ── Config file format ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ConfigFile {
    ingress: Vec<IngressRule>,
}

/// Load ingress rules from a YAML or JSON config file
pub fn load_from_file(path: &Path) -> Result<Vec<IngressRule>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read config file: {}", path.display()))?;

    // Try YAML first, then JSON
    let cfg: ConfigFile = if path.extension().and_then(|e| e.to_str()) == Some("json") {
        serde_json::from_str(&content)
            .with_context(|| format!("Invalid JSON in {}", path.display()))?
    } else {
        serde_yaml::from_str(&content)
            .with_context(|| format!("Invalid YAML in {}", path.display()))?
    };

    validate_rules(&cfg.ingress)?;
    Ok(cfg.ingress)
}

fn validate_rules(rules: &[IngressRule]) -> Result<()> {
    if rules.is_empty() {
        anyhow::bail!("Config file has no ingress rules");
    }
    // Last rule must be a catch-all (no hostname)
    let last = rules.last().unwrap();
    if !last.hostname.is_empty() {
        anyhow::bail!(
            "Last ingress rule must be a catch-all (no hostname). Add:\n  - service: http_status:404"
        );
    }
    Ok(())
}

/// Find default config file location:
///   1. ~/.cloudflared/config.yaml
///   2. /etc/cloudflared/config.yaml
pub fn default_config_path() -> Option<PathBuf> {
    if let Some(home) = dirs_next::home_dir() {
        let p = home.join(".cloudflared").join("config.yaml");
        if p.exists() { return Some(p); }
        let p = home.join(".cloudflared").join("config.json");
        if p.exists() { return Some(p); }
    }
    let p = PathBuf::from("/etc/cloudflared/config.yaml");
    if p.exists() { return Some(p); }
    None
}

/// Build an IngressTable from rules
pub fn make_table(rules: Vec<IngressRule>) -> IngressTable {
    Arc::new(RwLock::new(rules))
}

/// Spawn a background task that reloads config file every `interval` seconds
pub fn start_reload_task(path: PathBuf, table: IngressTable, interval_secs: u64) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
            match load_from_file(&path) {
                Ok(rules) => {
                    *table.write().await = rules;
                    info!("Ingress rules reloaded from {}", path.display());
                }
                Err(e) => {
                    warn!("Failed to reload config: {}", e);
                }
            }
        }
    });
}

/// Match a request against the ingress table → first matching rule wins
pub async fn resolve(table: &IngressTable, host: &str, path: &str) -> Option<IngressRule> {
    let rules = table.read().await;
    rules.iter().find(|r| r.matches(host, path)).cloned()
}

/// Print loaded rules to stdout
pub fn print_rules(rules: &[IngressRule]) {
    info!("Loaded {} ingress rule(s):", rules.len());
    for (i, rule) in rules.iter().enumerate() {
        if rule.hostname.is_empty() {
            info!("  Rule {}: (catch-all) → {}", i + 1, rule.service);
        } else {
            info!(
                "  Rule {}: {}{}  →  {}",
                i + 1,
                rule.hostname,
                if rule.path.is_empty() { String::new() } else { format!("/{}", rule.path) },
                rule.service
            );
        }
    }
}
