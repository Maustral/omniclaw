//! Text output formatter

use crate::core::{Finding, ScanSummary, Severity};

/// Text formatter for console output
pub struct TextFormatter {
    pub color: bool,
    pub verbose: bool,
}

impl TextFormatter {
    pub fn new() -> Self {
        Self {
            color: true,
            verbose: false,
        }
    }
    
    pub fn with_color(mut self, color: bool) -> Self {
        self.color = color;
        self
    }
    
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }
}

impl Default for TextFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Formatter for TextFormatter {
    fn format(&self, findings: &[Finding], summary: &ScanSummary) -> String {
        let mut output = String::new();
        
        // Header
        output.push_str("OmniClaw Scan Report\n");
        output.push_str(&"=".repeat(60));
        output.push_str("\n\n");
        
        // Summary
        output.push_str("Summary:\n");
        output.push_str(&format!("  Total findings: {}\n", summary.total));
        
        for severity in &[Severity::Critical, Severity::High, Severity::Medium, Severity::Low] {
            let count = summary.by_severity.get(&severity.to_string()).unwrap_or(&0);
            if *count > 0 {
                output.push_str(&format!("  {}: {}\n", severity, count));
            }
        }
        
        if summary.privileged_pattern_count > 0 {
            output.push_str(&format!(
                "  Privileged workflow patterns: {}\n",
                summary.privileged_pattern_count
            ));
        }
        
        output.push_str(&format!(
            "  Files scanned: {}\n",
            summary.files_scanned
        ));
        output.push_str(&format!(
            "  Duration: {}ms\n\n",
            summary.duration_ms
        ));
        
        // Findings
        if findings.is_empty() {
            output.push_str("No vulnerabilities found.\n");
        } else {
            output.push_str("Findings:\n");
            output.push_str(&"-".repeat(60));
            output.push_str("\n");
            
            // Sort by severity
            let mut sorted_findings = findings.to_vec();
            sorted_findings.sort_by(|a, b| {
                b.severity.to_numeric().cmp(&a.severity.to_numeric())
            });
            
            for finding in &sorted_findings {
                let severity_str = format!("[{}]", finding.severity);
                let severity_str = if self.color {
                    match finding.severity {
                        Severity::Critical => colorize(&severity_str, "red"),
                        Severity::High => colorize(&severity_str, "red"),
                        Severity::Medium => colorize(&severity_str, "yellow"),
                        Severity::Low => colorize(&severity_str, "cyan"),
                        Severity::Info => colorize(&severity_str, "blue"),
                    }
                } else {
                    severity_str
                };
                
                output.push_str(&format!("\n{} {}\n", severity_str, finding.id));
                output.push_str(&format!("  Title: {}\n", finding.title));
                
                if let Some(file) = &finding.file {
                    output.push_str(&format!("  File: {}\n", file.display()));
                }
                
                if let Some(line) = finding.line {
                    output.push_str(&format!("  Line: {}\n", line));
                }
                
                if let Some(evidence) = &finding.evidence {
                    output.push_str(&format!("  Evidence: {}\n", evidence));
                }
                
                output.push_str(&format!("  Description: {}\n", finding.description));
                
                if let Some(remediation) = &finding.remediation {
                    output.push_str(&format!("  Remediation: {}\n", remediation));
                }
                
                if !finding.cwe_ids.is_empty() {
                    output.push_str(&format!(
                        "  CWE: {}\n",
                        finding.cwe_ids.iter()
                            .map(|id| format!("CWE-{}", id))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                
                if finding.is_privileged_pattern {
                    let warning = if self.color { "!" } else { "!" };
                    let label = if self.color { 
                        colorize(" (Privileged Pattern)", "red") 
                    } else { 
                        " (Privileged Pattern)".to_string() 
                    };
                    output.push_str(&format!("  {} {}\n", warning, label));
                }
            }
        }
        
        output
    }
    
    fn format_name(&self) -> &str {
        "text"
    }
}

/// Simple colorize function (ANSI codes)
fn colorize(text: &str, color: &str) -> String {
    let code = match color {
        "red" => "31",
        "yellow" => "33",
        "green" => "32",
        "blue" => "34",
        "cyan" => "36",
        "magenta" => "35",
        _ => "0",
    };
    
    format!("\x1b[{}m{}\x1b[0m", code, text)
}

