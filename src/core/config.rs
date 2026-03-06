//! Configuration for OmniClaw

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration for OmniClaw scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// GitHub token for API access
    #[serde(default)]
    pub token: Option<String>,
    
    /// Output format (text, json, sarif, html)
    #[serde(default = "default_format")]
    pub format: String,
    
    /// Output directory for reports
    #[serde(default)]
    pub output: Option<PathBuf>,
    
    /// Minimum severity to report
    #[serde(default = "default_severity")]
    pub min_severity: String,
    
    /// Enable workflow security checks
    #[serde(default = "default_true")]
    pub workflow_security_checks: bool,
    
    /// Enable general CI/CD checks
    #[serde(default = "default_true")]
    pub cicd_checks: bool,
    
    /// Enable PR Guard checks
    #[serde(default = "default_true")]
    pub pr_guard: bool,
    
    /// Concurrency for org scans
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    
    /// Enable deep scan (recursive directory walking)
    #[serde(default)]
    pub deep_scan: bool,
    
    /// Custom rules directory
    #[serde(default)]
    pub rules_dir: Option<PathBuf>,
    
    /// Repository owner (for reports)
    #[serde(default)]
    pub repo: Option<String>,
    
    /// Feedback repository for reports
    #[serde(default)]
    pub feedback_repo: Option<String>,
}

fn default_format() -> String {
    "text".to_string()
}

fn default_severity() -> String {
    "info".to_string()
}

fn default_true() -> bool {
    true
}

fn default_concurrency() -> usize {
    4
}

impl Default for Config {
    fn default() -> Self {
        Self {
            token: std::env::var("GITHUB_TOKEN")
                .or_else(|_| std::env::var("GH_TOKEN"))
                .ok(),
            format: default_format(),
            output: None,
            min_severity: default_severity(),
            workflow_security_checks: true,
            cicd_checks: true,
            pr_guard: true,
            concurrency: default_concurrency(),
            deep_scan: false,
            rules_dir: None,
            repo: None,
            feedback_repo: None,
        }
    }
}

impl Config {
    /// Create a new config from CLI arguments
    pub fn from_args(
        token: Option<String>,
        format: String,
        output: Option<PathBuf>,
        min_severity: String,
        repo: Option<String>,
    ) -> Self {
        Self {
            token,
            format,
            output,
            min_severity,
            ..Default::default()
        }
    }
}

