//! Finding structure for security vulnerabilities

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use super::Severity;

/// A security finding/vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique rule identifier (e.g., "OC-001", "WS-001")
    pub id: String,
    
    /// Human-readable title
    pub title: String,
    
    /// Detailed description
    pub description: String,
    
    /// Severity level
    pub severity: Severity,
    
    /// CWE IDs related to this finding
    #[serde(default)]
    pub cwe_ids: Vec<u32>,
    
    /// File path where finding was detected
    #[serde(default)]
    pub file: Option<PathBuf>,
    
    /// Line number in the file
    #[serde(default)]
    pub line: Option<u32>,
    
    /// Code snippet/evidence
    #[serde(default)]
    pub evidence: Option<String>,
    
    /// Remediation guidance
    #[serde(default)]
    pub remediation: Option<String>,
    
    /// Source of the finding (github_actions, gitlab_ci, jenkins, pr_guard)
    #[serde(default)]
    pub source: String,
    
    /// Whether this is a privileged workflow pattern
    #[serde(default)]
    pub is_privileged_pattern: bool,
}

impl Finding {
    /// Create a new finding
    pub fn new(id: impl Into<String>, title: impl Into<String>, severity: Severity) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: String::new(),
            severity,
            cwe_ids: Vec::new(),
            file: None,
            line: None,
            evidence: None,
            remediation: None,
            source: String::new(),
            is_privileged_pattern: false,
        }
    }

    /// Create from a rule ID and finding data
    pub fn from_rule(
        id: &str,
        title: &str,
        description: &str,
        severity: Severity,
        cwe_ids: &[u32],
        remediation: &str,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: description.into(),
            severity,
            cwe_ids: cwe_ids.iter().copied().collect(),
            file: None,
            line: None,
            evidence: None,
            remediation: Some(remediation.into()),
            source: String::new(),
            is_privileged_pattern: id.starts_with("WS-00") && id.chars().nth(3).map_or(false, |c| c.is_ascii_digit()),
        }
    }

    /// Set the file path
    pub fn with_file(mut self, path: PathBuf) -> Self {
        self.file = Some(path);
        self
    }

    /// Set the line number
    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    /// Set the evidence/snippet
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    /// Set the description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set the remediation
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Set CWE IDs
    pub fn with_cwe_ids(mut self, ids: &[u32]) -> Self {
        self.cwe_ids = ids.to_vec();
        self
    }

    /// Set the source platform
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }

    /// Mark as privileged workflow pattern
    pub fn mark_privileged(mut self) -> Self {
        self.is_privileged_pattern = true;
        self
    }
}

/// Summary of scan results
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanSummary {
    /// Total findings count
    pub total: usize,
    
    /// Count by severity
    #[serde(default)]
    pub by_severity: std::collections::HashMap<String, usize>,
    
    /// Count by rule
    #[serde(default)]
    pub by_rule: std::collections::HashMap<String, usize>,
    
    /// Privileged workflow pattern findings count
    #[serde(default)]
    pub privileged_pattern_count: usize,
    
    /// Files scanned
    #[serde(default)]
    pub files_scanned: usize,
    
    /// Scan duration in milliseconds
    #[serde(default)]
    pub duration_ms: u64,
}

impl ScanSummary {
    /// Create from findings
    pub fn from_findings(findings: &[Finding], duration_ms: u64, files_scanned: usize) -> Self {
        let mut by_severity = std::collections::HashMap::new();
        let mut by_rule = std::collections::HashMap::new();
        let mut privileged_pattern_count = 0;

        for f in findings {
            let severity_key = f.severity.to_string();
            *by_severity.entry(severity_key).or_insert(0) += 1;
            *by_rule.entry(f.id.clone()).or_insert(0) += 1;
            if f.is_privileged_pattern {
                privileged_pattern_count += 1;
            }
        }

        Self {
            total: findings.len(),
            by_severity,
            by_rule,
            privileged_pattern_count,
            files_scanned,
            duration_ms,
        }
    }
}

