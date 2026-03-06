// ========================================================================
// DEFENSIVE SECURITY TOOLS MODULE
// ========================================================================
// This module provides defensive security tools for protecting CI/CD
// pipelines and detecting vulnerabilities.
// ========================================================================

use serde::{Deserialize, Serialize};

/// Security recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRecommendation {
    pub category: String,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub priority: Priority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

/// Hardening check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningCheck {
    pub check_name: String,
    pub passed: bool,
    pub details: String,
    pub recommendations: Vec<SecurityRecommendation>,
}

/// CI/CD Pipeline Hardener
pub struct PipelineHardener;

impl PipelineHardener {
    /// Analyze workflow and provide hardening recommendations
    pub fn analyze(workflow_content: &str) -> Vec<HardeningCheck> {
        let mut checks = Vec::new();
        
        // Check for secrets usage
        if workflow_content.contains("secrets.") {
            checks.push(HardeningCheck {
                check_name: "Secret Usage".to_string(),
                passed: true,
                details: "Workflow uses secrets".to_string(),
                recommendations: vec![
                    SecurityRecommendation {
                        category: "Secrets Management".to_string(),
                        title: "Mask Secret Outputs".to_string(),
                        description: "Ensure secrets are not logged".to_string(),
                        remediation: "Use ::add-mask:: in GitHub Actions".to_string(),
                        priority: Priority::High,
                    },
                ],
            });
        }
        
        // Check for input validation
        if workflow_content.contains("github.event.inputs") {
            checks.push(HardeningCheck {
                check_name: "Input Validation".to_string(),
                passed: false,
                details: "Workflow uses untrusted inputs".to_string(),
                recommendations: vec![
                    SecurityRecommendation {
                        category: "Input Validation".to_string(),
                        title: "Validate Workflow Inputs".to_string(),
                        description: "Untrusted inputs should be validated".to_string(),
                        remediation: "Add input validation steps".to_string(),
                        priority: Priority::Critical,
                    },
                ],
            });
        }
        
        // Check for action pinning
        if workflow_content.contains("uses:") && !workflow_content.contains("@sha256") && !workflow_content.contains("@v") {
            checks.push(HardeningCheck {
                check_name: "Action Pinning".to_string(),
                passed: false,
                details: "Actions not pinned to specific versions".to_string(),
                recommendations: vec![
                    SecurityRecommendation {
                        category: "Supply Chain Security".to_string(),
                        title: "Pin Action Versions".to_string(),
                        description: "Unpinned actions can be compromised".to_string(),
                        remediation: "Use @sha256 or exact version tags".to_string(),
                        priority: Priority::High,
                    },
                ],
            });
        }
        
        checks
    }
}

/// Vulnerability mitigator
pub struct VulnerabilityMitigator;

impl VulnerabilityMitigator {
    /// Generate mitigation for known vulnerability patterns
    pub fn generate_mitigation(vuln_type: &str) -> Option<SecurityRecommendation> {
        match vuln_type {
            "command_injection" => Some(SecurityRecommendation {
                category: "Injection Prevention".to_string(),
                title: "Command Injection Mitigation".to_string(),
                description: "Use parameterized commands instead of shell execution".to_string(),
                remediation: "Avoid shell=True in subprocess calls".to_string(),
                priority: Priority::Critical,
            }),
            "path_traversal" => Some(SecurityRecommendation {
                category: "Path Security".to_string(),
                title: "Path Traversal Mitigation".to_string(),
                description: "Validate and sanitize file paths".to_string(),
                remediation: "Use os.path.realpath() and whitelist allowed paths".to_string(),
                priority: Priority::High,
            }),
            "secret_exposure" => Some(SecurityRecommendation {
                category: "Secrets Security".to_string(),
                title: "Secret Exposure Mitigation".to_string(),
                description: "Ensure secrets are not logged or exposed".to_string(),
                remediation: "Use secret masking and environment variables".to_string(),
                priority: Priority::Critical,
            }),
            _ => None,
        }
    }
}

/// Security scanner for defensive purposes
pub struct DefensiveScanner;

impl DefensiveScanner {
    /// Scan for security misconfigurations
    pub fn scan_misconfigurations(content: &str) -> Vec<SecurityRecommendation> {
        let mut recommendations = Vec::new();
        
        // Check for overly permissive permissions
        if content.contains("permissions:") && content.contains("contents: write") {
            recommendations.push(SecurityRecommendation {
                category: "Permissions".to_string(),
                title: "Reduce Repository Permissions".to_string(),
                description: "Workflow has write access to contents".to_string(),
                remediation: "Use minimal required permissions".to_string(),
                priority: Priority::High,
            });
        }
        
        // Check for unverified actions
        if content.contains("uses:") && !content.contains("@sha256") {
            recommendations.push(SecurityRecommendation {
                category: "Action Security".to_string(),
                title: "Pin Action Versions".to_string(),
                description: "Actions should be pinned to specific versions".to_string(),
                remediation: "Use @sha256 or exact version tags".to_string(),
                priority: Priority::Medium,
            });
        }
        
        // Check for self-hosted runners
        if content.contains("runs-on:") && content.contains("self-hosted") {
            recommendations.push(SecurityRecommendation {
                category: "Runner Security".to_string(),
                title: "Secure Self-Hosted Runners".to_string(),
                description: "Self-hosted runners may have security risks".to_string(),
                remediation: "Ensure runners are properly secured and isolated".to_string(),
                priority: Priority::High,
            });
        }
        
        recommendations
    }
}

/// Check if workflow follows security best practices
pub fn check_security_best_practices(workflow_content: &str) -> Vec<SecurityRecommendation> {
    let mut recommendations = Vec::new();
    
    // Check for GITHUB_TOKEN permissions
    if !workflow_content.contains("permissions:") {
        recommendations.push(SecurityRecommendation {
            category: "Token Security".to_string(),
            title: "Define Token Permissions".to_string(),
            description: "No explicit permissions defined for GITHUB_TOKEN".to_string(),
            remediation: "Add explicit permissions block to limit token scope".to_string(),
            priority: Priority::High,
        });
    }
    
    // Check for environment protection
    if workflow_content.contains("environment:") && !workflow_content.contains("protection_rules") {
        recommendations.push(SecurityRecommendation {
            category: "Environment Security".to_string(),
            title: "Enable Environment Protection".to_string(),
            description: "Environment should have protection rules".to_string(),
            remediation: "Configure required reviewers and wait intervals".to_string(),
            priority: Priority::Medium,
        });
    }
    
    recommendations
}
