//! Output formatters for OmniClaw

pub mod text;
pub mod json;
pub mod sarif;

pub use text::TextFormatter;
pub use json::JsonFormatter;
pub use sarif::SarifFormatter;

/// Output format enumeration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    Html,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "text" | "txt" => Some(OutputFormat::Text),
            "json" => Some(OutputFormat::Json),
            "sarif" => Some(OutputFormat::Sarif),
            "html" => Some(OutputFormat::Html),
            _ => None,
        }
    }
}

/// Trait for output formatters
pub trait Formatter {
    /// Format findings for output
    fn format(&self, findings: &[crate::core::Finding], summary: &crate::core::ScanSummary) -> String;
    
    /// Get the format name
    fn format_name(&self) -> &str;
}

