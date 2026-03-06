//! Local file scanner for OmniClaw

use crate::core::{Finding, ScanSummary, Severity};
use crate::rules::workflow_security;
use crate::rules::cicd;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

/// Scanner configuration
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Enable workflow security checks
    pub workflow_security_checks: bool,
    /// Enable general CI/CD checks
    pub cicd_checks: bool,
    /// Deep scan (recursive)
    pub deep_scan: bool,
    /// Minimum severity to report
    pub min_severity: Severity,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            workflow_security_checks: true,
            cicd_checks: true,
            deep_scan: false,
            min_severity: Severity::Info,
        }
    }
}

/// Main scanner for local files
pub struct LocalScanner {
    config: ScannerConfig,
}

impl LocalScanner {
    /// Create a new scanner with default config
    pub fn new() -> Self {
        Self {
            config: ScannerConfig::default(),
        }
    }
    
    /// Create with custom config
    pub fn with_config(config: ScannerConfig) -> Self {
        Self { config }
    }
    
    /// Scan a directory for workflow files
    pub fn scan(&self, path: &Path) -> ScanResult {
        let start = Instant::now();
        let mut findings = Vec::new();
        let mut files_scanned = 0;
        
        // Find workflow files
        let workflow_files = self.find_workflow_files(path);
        files_scanned = workflow_files.len();
        
        for file_path in &workflow_files {
            if let Ok(content) = std::fs::read_to_string(file_path) {
                // Run workflow security checks
                if self.config.workflow_security_checks {
                    workflow_security::scan_workflow_security(file_path, &content, &mut findings);
                }
                
                // Run general CI/CD checks
                if self.config.cicd_checks {
                    cicd::apply_generic_rules(file_path, &content, &mut findings);
                }
            }
        }
        
        // Filter by severity
        let min_severity = self.config.min_severity.to_numeric();
        findings.retain(|f| f.severity.to_numeric() >= min_severity);
        
        let duration_ms = start.elapsed().as_millis() as u64;
        let summary = ScanSummary::from_findings(&findings, duration_ms, files_scanned);
        
        ScanResult {
            findings,
            summary,
        }
    }
    
    /// Find all workflow files in a directory
    fn find_workflow_files(&self, path: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        
        // Check if path is a direct workflow file
        if path.is_file() && is_workflow_file(path) {
            return vec![path.to_path_buf()];
        }
        
        // Walk directory
        let walker = if self.config.deep_scan {
            WalkDir::new(path)
        } else {
            WalkDir::new(path).max_depth(3)
        };
        
        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() && is_workflow_file(path) {
                files.push(path.to_path_buf());
            }
        }
        
        files
    }
}

impl Default for LocalScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a file is a CI/CD workflow file
fn is_workflow_file(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    let ext = path.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    
    // GitHub Actions
    if path_str.contains(".github/workflows") && (ext == "yml" || ext == "yaml") {
        return true;
    }
    
    // GitLab CI
    if path_str.ends_with(".gitlab-ci.yml") || path_str.ends_with(".gitlab-ci.yaml") {
        return true;
    }
    
    // Jenkins
    if path_str.contains("jenkinsfile") {
        return true;
    }
    
    // CircleCI
    if path_str.contains(".circleci/") && (ext == "yml" || ext == "yaml") {
        return true;
    }
    
    // Azure Pipelines
    if path_str.contains("azure-pipelines") && (ext == "yml" || ext == "yaml") {
        return true;
    }
    
    // Travis CI
    if path_str.ends_with(".travis.yml") || path_str.ends_with(".travis.yaml") {
        return true;
    }
    
    false
}

/// Result of a scan
#[derive(Debug)]
pub struct ScanResult {
    /// All findings
    pub findings: Vec<Finding>,
    /// Summary statistics
    pub summary: ScanSummary,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    
    #[test]
    fn test_workflow_detection() {
        assert!(is_workflow_file(Path::new("/repo/.github/workflows/ci.yml")));
        assert!(is_workflow_file(Path::new("/repo/.gitlab-ci.yml")));
        assert!(!is_workflow_file(Path::new("/repo/README.md")));
    }
}

