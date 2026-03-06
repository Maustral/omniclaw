//! SARIF output formatter for GitHub Code Scanning

use crate::core::{Finding, ScanSummary, Severity};
use serde::Serialize;

/// SARIF v2.1.0 formatter
pub struct SarifFormatter {
    pub repo_uri: Option<String>,
}

impl SarifFormatter {
    pub fn new() -> Self {
        Self {
            repo_uri: None,
        }
    }
    
    pub fn with_repo_uri(mut self, uri: String) -> Self {
        self.repo_uri = Some(uri);
        self
    }
}

impl Default for SarifFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Formatter for SarifFormatter {
    fn format(&self, findings: &[Finding], summary: &ScanSummary) -> String {
        let sarif = SarifReport::from_findings(findings, summary, self.repo_uri.as_deref());
        serde_json::to_string_pretty(&sarif).unwrap_or_default()
    }
    
    fn format_name(&self) -> &str {
        "sarif"
    }
}

/// SARIF report structure
#[derive(Debug, Serialize)]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

impl SarifReport {
    fn from_findings(findings: &[Finding], summary: &ScanSummary, repo_uri: Option<&str>) -> Self {
        let mut rules = Vec::new();
        let mut results = Vec::new();
        
        // Collect unique rules
        for finding in findings {
            if !rules.iter().any(|r: &SarifRule| r.id == finding.id) {
                rules.push(SarifRule {
                    id: finding.id.clone(),
                    name: finding.title.clone(),
                    short_description: SarifMessage {
                        text: finding.title.clone(),
                    },
                    full_description: SarifMessage {
                        text: finding.description.clone(),
                    },
                    default_configuration: SarifConfiguration {
                        level: severity_to_sarif_level(&finding.severity),
                    },
                    help: SarifMessage {
                        text: finding.remediation.clone().unwrap_or_default(),
                    },
                    properties: SarifRuleProperties {
                        cwe_ids: finding.cwe_ids.iter()
                            .map(|id| format!("CWE-{}", id))
                            .collect(),
                        security_severity: Some(severity_to_numeric(&finding.severity)),
                        ..Default::default()
                    },
                });
            }
            
            // Create result
            results.push(SarifResult {
                rule_id: finding.id.clone(),
                level: severity_to_sarif_level(&finding.severity),
                message: SarifMessage {
                    text: finding.description.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: finding.file.as_ref()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default(),
                        },
                        region: finding.line.map(|line| SarifRegion {
                            start_line: line,
                            ..Default::default()
                        }),
                    },
                }],
            });
        }
        
        Self {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            version: "2.1.0".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifToolDriver {
                        name: "OmniClaw".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        rules,
                    },
                },
                results,
                properties: Some(SarifRunProperties {
                    metrics: Some(SarifMetrics {
                        security: Some(SarifMetric {
                            value: summary.total as f64,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                }),
            }],
        }
    }
}

#[derive(Debug, Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifRunProperties>,
}

#[derive(Debug, Serialize)]
struct SarifTool {
    driver: SarifToolDriver,
}

#[derive(Debug, Serialize)]
struct SarifToolDriver {
    name: String,
    version: String,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    full_description: SarifMessage,
    default_configuration: SarifConfiguration,
    help: SarifMessage,
    properties: SarifRuleProperties,
}

#[derive(Debug, Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Serialize)]
struct SarifConfiguration {
    level: String,
}

#[derive(Debug, Serialize, Default)]
struct SarifRuleProperties {
    cwe_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_severity: Option<f64>,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize)]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Debug, Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Serialize)]
#[serde(default)]
struct SarifRegion {
    start_line: u32,
}

impl Default for SarifRegion {
    fn default() -> Self {
        Self { start_line: 1 }
    }
}

#[derive(Debug, Serialize, Default)]
#[serde(default)]
struct SarifRunProperties {
    metrics: Option<SarifMetrics>,
}

#[derive(Debug, Serialize, Default)]
#[serde(default)]
struct SarifMetrics {
    security: Option<SarifMetric>,
}

#[derive(Debug, Serialize, Default)]
#[serde(default)]
struct SarifMetric {
    value: f64,
}

fn severity_to_sarif_level(severity: &Severity) -> String {
    match severity {
        Severity::Critical | Severity::High => "error".to_string(),
        Severity::Medium => "warning".to_string(),
        Severity::Low | Severity::Info => "note".to_string(),
    }
}

fn severity_to_numeric(severity: &Severity) -> f64 {
    match severity {
        Severity::Critical => 9.0,
        Severity::High => 7.0,
        Severity::Medium => 5.0,
        Severity::Low => 3.0,
        Severity::Info => 1.0,
    }
}

