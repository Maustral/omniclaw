//! General CI/CD security rules
//!
//! Security rules for common CI/CD platforms and patterns

use crate::core::{Finding, Severity};
use lazy_static::lazy_static;
use regex::Regex;
use std::path::Path;

/// CI/CD Rule definition
#[derive(Debug, Clone)]
pub struct CiCdRule {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub cwe_ids: &'static [u32],
    pub remediation: &'static str,
    pub platform: &'static str,
}

/// All general CI/CD rules
pub fn all_cicd_rules() -> Vec<CiCdRule> {
    vec![
        // GitHub Actions Rules
        CiCdRule {
            id: "CI-001",
            name: "Workflow trigger privilege escalation".into(),
            description: "Trigger executes in the context of the base branch with access to secrets.".into(),
            severity: Severity::High,
            cwe_ids: &[269],
            remediation: "Validate the triggering workflow's conclusions and limit permissions.".into(),
            platform: "github_actions",
        },
        CiCdRule {
            id: "CI-002",
            name: "Unpinned action reference".into(),
            description: "Using dynamic references instead of full commit SHA allows action modification.".into(),
            severity: Severity::High,
            cwe_ids: &[829],
            remediation: "Pin actions to a full commit SHA for reproducibility.".into(),
            platform: "github_actions",
        },
        CiCdRule {
            id: "CI-003",
            name: "Mutable version tag".into(),
            description: "Short version tags are mutable and can be changed retrospectively.".into(),
            severity: Severity::Medium,
            cwe_ids: &[829],
            remediation: "Use exact version tags or full commit SHAs.".into(),
            platform: "github_actions",
        },
        CiCdRule {
            id: "CI-004",
            name: "Artifact without verification".into(),
            description: "Artifact transfer without checksum verification allows tampering.".into(),
            severity: Severity::Medium,
            cwe_ids: &[494],
            remediation: "Add checksum verification after downloading artifacts.".into(),
            platform: "github_actions",
        },
        CiCdRule {
            id: "CI-005",
            name: "Script execution with user input".into(),
            description: "Script execution with user-controlled input enables code injection.".into(),
            severity: Severity::Critical,
            cwe_ids: &[94],
            remediation: "Never interpolate user-controlled inputs into scripts.".into(),
            platform: "github_actions",
        },
        CiCdRule {
            id: "CI-006",
            name: "Self-hosted runner usage".into(),
            description: "Self-hosted runners persist state between jobs, enabling persistent threats.".into(),
            severity: Severity::Medium,
            cwe_ids: &[250],
            remediation: "Use ephemeral runners or managed CI infrastructure.".into(),
            platform: "github_actions",
        },
        CiCdRule {
            id: "CI-007",
            name: "Missing permissions declaration".into(),
            description: "Without explicit permissions, default elevated access may be granted.".into(),
            severity: Severity::Medium,
            cwe_ids: &[269],
            remediation: "Add explicit permissions block with least-privilege scopes.".into(),
            platform: "github_actions",
        },
        CiCdRule {
            id: "CI-008",
            name: "Unvalidated action inputs".into(),
            description: "Action inputs used without validation are vulnerable to injection.".into(),
            severity: Severity::High,
            cwe_ids: &[20],
            remediation: "Validate and sanitize all inputs before use.".into(),
            platform: "github_actions",
        },
        CiCdRule {
            id: "CI-009",
            name: "Secrets inheritance".into(),
            description: "Passing all secrets to called workflows violates least-privilege.".into(),
            severity: Severity::High,
            cwe_ids: &[200],
            remediation: "Explicitly pass only required secrets.".into(),
            platform: "github_actions",
        },
        CiCdRule {
            id: "CI-010",
            name: "Excessive token permissions".into(),
            description: "Overly permissive token grants access beyond what's needed.".into(),
            severity: Severity::High,
            cwe_ids: &[269],
            remediation: "Use granular permissions for each workflow.".into(),
            platform: "github_actions",
        },
        CiCdRule {
            id: "CI-011",
            name: "User-controlled context injection".into(),
            description: "User-controllable context data can inject commands.".into(),
            severity: Severity::High,
            cwe_ids: &[94],
            remediation: "Never use user-controlled context directly in commands.".into(),
            platform: "github_actions",
        },
        CiCdRule {
            id: "CI-012",
            name: "Environment URL injection".into(),
            description: "Environment URL can be manipulated for phishing.".into(),
            severity: Severity::Medium,
            cwe_ids: &[601],
            remediation: "Validate environment URLs against an allowlist.".into(),
            platform: "github_actions",
        },
        CiCdRule {
            id: "CI-013",
            name: "Cache poisoning risk".into(),
            description: "Predictable cache keys allow cache poisoning attacks.".into(),
            severity: Severity::Medium,
            cwe_ids: &[345],
            remediation: "Include content hashes in cache keys.".into(),
            platform: "github_actions",
        },
        CiCdRule {
            id: "CI-014",
            name: "Over-scoped cloud credentials".into(),
            description: "Overly permissive cloud credentials grant excessive access.".into(),
            severity: Severity::High,
            cwe_ids: &[269],
            remediation: "Scope credentials to specific resources and actions.".into(),
            platform: "github_actions",
        },
        // GitLab CI Rules
        CiCdRule {
            id: "CI-200",
            name: "Remote include tampering".into(),
            description: "Remote includes can be tampered with by attackers.".into(),
            severity: Severity::Medium,
            cwe_ids: &[829],
            remediation: "Use local includes or verify remote file integrity.".into(),
            platform: "gitlab_ci",
        },
        CiCdRule {
            id: "CI-201",
            name: "Skippable security gates".into(),
            description: "Security stages that can be skipped may miss vulnerabilities.".into(),
            severity: Severity::Medium,
            cwe_ids: &[693],
            remediation: "Make security checks mandatory.".into(),
            platform: "gitlab_ci",
        },
        CiCdRule {
            id: "CI-202",
            name: "Unprotected variables".into(),
            description: "Sensitive variables without protection can be leaked.".into(),
            severity: Severity::Medium,
            cwe_ids: &[200],
            remediation: "Mark sensitive variables as protected and masked.".into(),
            platform: "gitlab_ci",
        },
        CiCdRule {
            id: "CI-203",
            name: "Exposed trigger tokens".into(),
            description: "Trigger tokens referenced directly risk exposure.".into(),
            severity: Severity::Medium,
            cwe_ids: &[200],
            remediation: "Use protected variables for tokens.".into(),
            platform: "gitlab_ci",
        },
        CiCdRule {
            id: "CI-204",
            name: "Privileged container execution".into(),
            description: "Privileged containers can escape and access host resources.".into(),
            severity: Severity::High,
            cwe_ids: &[250],
            remediation: "Avoid privileged containers; use managed runners.".into(),
            platform: "gitlab_ci",
        },
        // Jenkins Rules
        CiCdRule {
            id: "CI-300",
            name: "Dynamic dependency loading".into(),
            description: "Dynamic loading allows arbitrary code execution.".into(),
            severity: Severity::Critical,
            cwe_ids: &[829],
            remediation: "Use dependency management through build tools.".into(),
            platform: "jenkins",
        },
        CiCdRule {
            id: "CI-301",
            name: "Shell injection via DSL".into(),
            description: "String interpolation in shell commands allows injection.".into(),
            severity: Severity::High,
            cwe_ids: &[78],
            remediation: "Use proper escaping in shell commands.".into(),
            platform: "jenkins",
        },
        CiCdRule {
            id: "CI-302",
            name: "Dynamic library loading".into(),
            description: "Dynamic library loading is risky and hard to audit.".into(),
            severity: Severity::Medium,
            cwe_ids: &[829],
            remediation: "Use static library references with versions.".into(),
            platform: "jenkins",
        },
        CiCdRule {
            id: "CI-303",
            name: "Unversioned library reference".into(),
            description: "Unversioned libraries use mutable default branches.".into(),
            severity: Severity::Medium,
            cwe_ids: &[829],
            remediation: "Pin libraries to specific versions.".into(),
            platform: "jenkins",
        },
        CiCdRule {
            id: "CI-304",
            name: "Sandbox bypass risk".into(),
            description: "Sandbox bypass allows arbitrary code execution.".into(),
            severity: Severity::High,
            cwe_ids: &[693],
            remediation: "Avoid sandbox bypass techniques.".into(),
            platform: "jenkins",
        },
        CiCdRule {
            id: "CI-305",
            name: "In-code permission checks".into(),
            description: "Permission checks in pipeline code can be bypassed.".into(),
            severity: Severity::High,
            cwe_ids: &[269],
            remediation: "Use platform authorization matrix.".into(),
            platform: "jenkins",
        },
    ]
}

lazy_static! {
    // Generic CI/CD patterns (all platforms)
    
    /// Secret exfiltration via curl
    pub static ref SECRET_EXFIL_CURL: Regex = Regex::new(
        r"curl\s+.*\$\{?\{?\s*secrets\."
    ).unwrap();
    
    /// Secret exfiltration via wget
    pub static ref SECRET_EXFIL_WGET: Regex = Regex::new(
        r"wget\s+.*\$\{?\{?\s*secrets\."
    ).unwrap();
    
    /// Netcat reverse shell
    pub static ref NETCAT_REVERSE_SHELL: Regex = Regex::new(
        r"(?i)(nc|ncat|netcat)\s+(-e|-c)"
    ).unwrap();
    
    /// /dev/tcp reverse shell
    pub static ref DEV_TCP_SHELL: Regex = Regex::new(
        r"/dev/tcp/"
    ).unwrap();
    
    /// curl | bash pattern
    pub static ref CURL_PIPE_BASH: Regex = Regex::new(
        r"(?i)curl\s+.*\|\s*(ba)?sh"
    ).unwrap();
    
    /// wget | sh pattern
    pub static ref WGET_PIPE_SH: Regex = Regex::new(
        r"(?i)wget\s+.*\|\s*(ba)?sh"
    ).unwrap();
    
    /// Unpinned action reference (branch/tag)
    pub static ref UNPINNED_ACTION: Regex = Regex::new(
        r"uses:\s*\S+@(main|master|latest|v\d+)(?!\.[0-9])"
    ).unwrap();
    
    /// Mutable tag reference
    pub static ref MUTABLE_TAG: Regex = Regex::new(
        r"uses:\s*[\w-]+/[\w-]+@v\d+$"
    ).unwrap();
    
    /// Missing permissions block
    pub static ref MISSING_PERMISSIONS: Regex = Regex::new(
        r"^jobs:.*\n\s{2,}[a-z]+:\s*$"
    ).unwrap();
}

/// Apply generic CI/CD rules
pub fn apply_generic_rules(path: &Path, content: &str, findings: &mut Vec<Finding>) {
    // Check for secret exfiltration
    for (line_num, line) in content.lines().enumerate() {
        if SECRET_EXFIL_CURL.is_match(line) {
            findings.push(
                Finding::from_rule(
                    "CI-102",
                    "Secret Exfiltration via HTTP",
                    "Secrets are being sent to an external endpoint via HTTP.",
                    Severity::Critical,
                    &[200],
                    "Never pass secrets directly to HTTP clients. Use official integrations."
                )
                .with_file(path.to_path_buf())
                .with_line((line_num + 1) as u32)
                .with_evidence(line.trim())
                .with_source("github_actions")
            );
        }
        
        if SECRET_EXFIL_WGET.is_match(line) {
            findings.push(
                Finding::from_rule(
                    "CI-102",
                    "Secret Exfiltration via Download",
                    "Secrets are being sent to an external endpoint via download tool.",
                    Severity::Critical,
                    &[200],
                    "Never pass secrets directly to download tools. Use official integrations."
                )
                .with_file(path.to_path_buf())
                .with_line((line_num + 1) as u32)
                .with_evidence(line.trim())
                .with_source("github_actions")
            );
        }
        
        // Check for reverse shells
        if NETCAT_REVERSE_SHELL.is_match(line) {
            findings.push(
                Finding::from_rule(
                    "CI-103",
                    "Network Shell Detection",
                    "Network tool with shell execution flag detected.",
                    Severity::Critical,
                    &[78],
                    "Remove network shell patterns. Investigate for compromise."
                )
                .with_file(path.to_path_buf())
                .with_line((line_num + 1) as u32)
                .with_evidence(line.trim())
                .with_source("github_actions")
            );
        }
        
        if DEV_TCP_SHELL.is_match(line) {
            findings.push(
                Finding::from_rule(
                    "CI-103",
                    "Network Connection Detection",
                    "Direct network connection used, common in remote access.",
                    Severity::Critical,
                    &[78],
                    "Remove direct network connections. Investigate for compromise."
                )
                .with_file(path.to_path_buf())
                .with_line((line_num + 1) as u32)
                .with_evidence(line.trim())
                .with_source("github_actions")
            );
        }
        
        // Check for remote script execution
        if CURL_PIPE_BASH.is_match(line) {
            findings.push(
                Finding::from_rule(
                    "CI-104",
                    "Remote Script Execution",
                    "Downloading and executing remote scripts is a supply chain risk.",
                    Severity:: High,
                    &[829],
                    "Download scripts first, verify checksums, then execute."
                )
                .with_file(path.to_path_buf())
                .with_line((line_num + 1) as u32)
                .with_evidence(line.trim())
                .with_source("github_actions")
            );
        }
        
        if WGET_PIPE_SH.is_match(line) {
            findings.push(
                Finding::from_rule(
                    "CI-104",
                    "Remote Script Execution",
                    "Downloading and executing remote scripts is a supply chain risk.",
                    Severity::High,
                    &[829],
                    "Download scripts first, verify checksums, then execute."
                )
                .with_file(path.to_path_buf())
                .with_line((line_num + 1) as u32)
                .with_evidence(line.trim())
                .with_source("github_actions")
            );
        }
    }
}

/// Detect CI platform from file content
pub fn detect_platform(path: &Path, content: &str) -> &'static str {
    let path_str = path.to_string_lossy().to_lowercase();
    
    // GitHub Actions
    if path_str.contains(".github/workflows") 
        || content.contains("runs-on:") && content.contains("steps:") {
        return "github_actions";
    }
    
    // GitLab CI
    if path_str.contains(".gitlab-ci.yml") 
        || content.contains("stages:") && content.contains("script:") {
        return "gitlab_ci";
    }
    
    // Jenkins
    if path_str.contains("jenkinsfile") 
        || content.contains("pipeline {") 
        || content.contains("node {") {
        return "jenkins";
    }
    
    "unknown"
}

