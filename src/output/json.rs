//! JSON output formatter

use crate::core::{Finding, ScanSummary};

/// JSON formatter for structured output
pub struct JsonFormatter {
    pub pretty: bool,
}

impl JsonFormatter {
    pub fn new() -> Self {
        Self {
            pretty: true,
        }
    }
    
    pub fn with_pretty(mut self, pretty: bool) -> Self {
        self.pretty = pretty;
        self
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Formatter for JsonFormatter {
    fn format(&self, findings: &[Finding], summary: &ScanSummary) -> String {
        #[derive(serde::Serialize)]
        struct Report {
            scanner: String,
            version: String,
            summary: ScanSummary,
            findings: Vec<Finding>,
        }
        
        let report = Report {
            scanner: "OmniClaw".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            summary: summary.clone(),
            findings: findings.to_vec(),
        };
        
        if self.pretty {
            serde_json::to_string_pretty(&report).unwrap_or_default()
        } else {
            serde_json::to_string(&report).unwrap_or_default()
        }
    }
    
    fn format_name(&self) -> &str {
        "json"
    }
}

