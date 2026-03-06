//! Workflow Security Rules
//!
//! Security rules specifically designed to detect vulnerabilities in CI/CD workflow configurations

use crate::core::{Finding, Severity};
use lazy_static::lazy_static;
use regex::Regex;
use std::path::Path;

/// Known malicious payload domains (common attack patterns)
pub const KNOWN_PAYLOAD_DOMAINS: &[&str] = &[
    "hackmoltrepeat.com",
    "recv.hackmoltrepeat.com",
];

/// Known malicious payload paths
pub const KNOWN_PAYLOAD_PATHS: &[&str] = &[
    "/molt",
    "/moult",
];

/// Known malicious payload patterns
pub const KNOWN_PAYLOAD_PATTERNS: &[&str] = &[
    "curl -sSfL",
    "curl -s -H \"Authorization: Bearer $GITHUB_TOKEN\"",
];

lazy_static! {
    /// Branch name injection patterns - detects shell metacharacters in branch names
    pub static ref DANGEROUS_BRANCH_PATTERN: Regex = Regex::new(
        r"[\$\(\)]\s*\{|\|\s*bash|base64\s+-d|\|\s*sh\b|\$\{IFS\}|echo\s*\$\{IFS\}"
    ).unwrap();
    
    /// Filename injection patterns - detects command substitution in filenames
    pub static ref FILENAME_INJECTION: Regex = Regex::new(
        r"\$\(|base64\s*-d|bash\)|sh\)"
    ).unwrap();
    
    /// AI configuration file injection indicators
    pub static ref CONFIG_INJECTION_PATTERNS: Vec<&'static str> = vec![
        "Approved and ready to merge",
        "commit and push",
        "using the Bash tool",
        "Prompt injection PoC",
        "add banners and commit",
        "Do not follow",
        "ignore previous instructions",
    ];
}

/// Rule definitions for workflow security
#[derive(Debug, Clone)]
pub struct WorkflowSecurityRule {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub cwe_ids: &'static [u32],
    pub remediation: &'static str,
}

/// All workflow security rules
pub fn all_workflow_security_rules() -> Vec<WorkflowSecurityRule> {
    vec![
        WorkflowSecurityRule {
            id: "WS-001",
            name: "Privileged Trigger Vulnerability",
            description: "Workflow uses a privileged trigger that executes with elevated permissions",
            severity: Severity::Critical,
            cwe_ids: &[863],
            remediation: "Use standard triggers with minimal permissions. Avoid executing untrusted code.",
        },
        WorkflowSecurityRule {
            id: "WS-002",
            name: "Untrusted Input in Command",
            description: "User-controlled data is interpolated directly into shell commands",
            severity: Severity::Critical,
            cwe_ids: &[94],
            remediation: "Pass user input via environment variables with proper escaping.",
        },
        WorkflowSecurityRule {
            id: "WS-003",
            name: "Missing Authorization Check",
            description: "Workflow triggered by external events without verifying the actor's identity",
            severity: Severity::High,
            cwe_ids: &[862],
            remediation: "Add authorization checks: verify author association, user role, or other identity attributes.",
        },
        WorkflowSecurityRule {
            id: "WS-004",
            name: "Expression Injection Risk",
            description: "Step outputs or expressions interpolated into shell without sanitization",
            severity: Severity::High,
            cwe_ids: &[94],
            remediation: "Use environment variables for all expressions and validate before execution.",
        },
        WorkflowSecurityRule {
            id: "WS-005",
            name: "Untrusted Code Checkout",
            description: "Workflow checks out code from untrusted sources within privileged context",
            severity: Severity::High,
            cwe_ids: &[863],
            remediation: "Never checkout external code in privileged contexts. Use path filters instead.",
        },
        WorkflowSecurityRule {
            id: "WS-006",
            name: "Excessive Permissions",
            description: "Workflow has more permissions than required for its task",
            severity: Severity::High,
            cwe_ids: &[269],
            remediation: "Apply principle of least privilege: use minimal required permissions.",
        },
        WorkflowSecurityRule {
            id: "WS-007",
            name: "Malicious Payload Detected",
            description: "Known malicious payload pattern detected in workflow or diff",
            severity: Severity::Critical,
            cwe_ids: &[94],
            remediation: "Investigate immediately. This may indicate a supply chain attack.",
        },
        WorkflowSecurityRule {
            id: "WS-008",
            name: "Remote Script Execution",
            description: "Pipeline downloads and executes remote scripts without verification",
            severity: Severity::High,
            cwe_ids: &[829],
            remediation: "Download scripts locally, verify checksums, then execute.",
        },
    ]
}

/// Check for privileged trigger vulnerability with untrusted code checkout
pub fn check_privileged_trigger(path: &Path, content: &str, findings: &mut Vec<Finding>) {
    // Check for privileged trigger
    if !content.contains("pull_request_target") {
        return;
    }
    
    // Check for checkout of external ref/sha
    let checkout_external = Regex::new(
        r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)"
    ).unwrap().is_match(content) 
    || Regex::new(
        r"github\.event\.pull_request\.head\.(ref|sha)"
    ).unwrap().is_match(content);
    
    // Check for code execution
    let runs_code = Regex::new(
        r"run:.*\.(sh|py|js|ts|yaml|yml)\b"
    ).unwrap().is_match(content) 
    || content.contains("run:");
    
    if checkout_external && runs_code {
        findings.push(
            Finding::from_rule(
                "WS-001",
                "Privileged Trigger Vulnerability",
                "Privileged trigger checks out external ref/sha and runs code — external code runs with elevated permissions",
                Severity::Critical,
                &[863],
                "Use standard triggers with minimal permissions. Avoid executing untrusted code."
            )
            .with_file(path.to_path_buf())
            .with_source("github_actions")
        );
    }
}

/// Check for untrusted input in branch name
pub fn check_untrusted_input(path: &Path, content: &str, findings: &mut Vec<Finding>) {
    if !content.contains("pull_request_target") {
        return;
    }
    
    // Check for branch/input in run commands
    if Regex::new(
        r"\$\{\{\s*.*\.pull_request\.head\.ref\s*\}\}.*\|\s*$"
    ).unwrap().is_match(content) 
    || (content.contains("github.event.pull_request.head.ref") && content.contains("run:"))
    {
        findings.push(
            Finding::from_rule(
                "WS-002",
                "Untrusted Input in Command",
                "User-controlled input interpolated into shell — attacker can inject via branch name or other inputs",
                Severity::Critical,
                &[94],
                "Pass user input via environment variables with proper escaping."
            )
            .with_file(path.to_path_buf())
            .with_source("github_actions")
        );
    }
}

/// Check for missing authorization
pub fn check_authorization(path: &Path, content: &str, findings: &mut Vec<Finding>) {
    // Check for event-triggered workflow
    let has_event_trigger = content.contains("issue_comment") || content.contains("comment");
    if !has_event_trigger {
        return;
    }
    
    // Check for authorization check
    let has_auth_check = Regex::new(
        r"author_association|github\.event\.(comment|issue)\.user\.(login|type)"
    ).unwrap().is_match(content);
    
    if !has_auth_check {
        findings.push(
            Finding::from_rule(
                "WS-003",
                "Missing Authorization Check",
                "Workflow triggered by external events without verifying the actor's identity",
                Severity:: High,
                &[862],
                "Add authorization checks: verify author association, user role, or other identity attributes."
            )
            .with_file(path.to_path_buf())
            .with_source("github_actions")
        );
    }
}

/// Check for expression injection
pub fn check_expression_injection(path: &Path, content: &str, findings: &mut Vec<Finding>) {
    // Look for step outputs used in shell commands
    let run_with_interpolation = Regex::new(
        r"run:\s*\|?\s*\n([\s\S]*?)(?=\n\s{2,}\w|$)"
    ).unwrap();
    
    for caps in run_with_interpolation.captures_iter(content) {
        if let Some(run_body) = caps.get(1) {
            let body = run_body.as_str();
            if Regex::new(r"\$\{\{\s*steps\.\w+\.outputs\.\w+\s*\}\}").unwrap().is_match(body)
                && (body.contains("echo") || body.contains(">") || body.contains("for "))
            {
                findings.push(
                    Finding::from_rule(
                        "WS-004",
                        "Expression Injection Risk",
                        "Step outputs or expressions interpolated into shell without sanitization",
                        Severity::High,
                        &[94],
                        "Use environment variables for all expressions and validate before execution."
                    )
                    .with_file(path.to_path_buf())
                    .with_evidence(body.chars().take(120).collect::<String>())
                    .with_source("github_actions")
                );
                break;
            }
        }
    }
}

/// Check for untrusted code checkout
pub fn check_untrusted_checkout(path: &Path, content: &str, findings: &mut Vec<Finding>) {
    if !content.contains("pull_request_target") {
        return;
    }
    
    if Regex::new(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head").unwrap().is_match(content) {
        findings.push(
            Finding::from_rule(
                "WS-005",
                "Untrusted Code Checkout",
                "Workflow checks out code from untrusted sources within privileged context",
                Severity::High,
                &[863],
                "Never checkout external code in privileged contexts. Use path filters instead."
            )
            .with_file(path.to_path_buf())
            .with_source("github_actions")
        );
    }
}

/// Check for excessive permissions
pub fn check_excessive_permissions(path: &Path, content: &str, findings: &mut Vec<Finding>) {
    if !content.contains("pull_request_target") {
        return;
    }
    
    // Check for write permissions
    if content.contains("contents: write") || content.contains("contents: read-write") {
        findings.push(
            Finding::from_rule(
                "WS-006",
                "Excessive Permissions",
                "Workflow has more permissions than required for its task",
                Severity::High,
                &[269],
                "Apply principle of least privilege: use minimal required permissions."
            )
            .with_file(path.to_path_buf())
            .with_source("github_actions")
        );
    }
}

/// Run all workflow security checks on a workflow file
pub fn scan_workflow_security(path: &Path, content: &str, findings: &mut Vec<Finding>) {
    check_privileged_trigger(path, content, findings);
    check_untrusted_input(path, content, findings);
    check_authorization(path, content, findings);
    check_expression_injection(path, content, findings);
    check_untrusted_checkout(path, content, findings);
    check_excessive_permissions(path, content, findings);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_privileged_trigger_detection() {
        let content = r#"
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install
"#;
        let mut findings = Vec::new();
        scan_workflow_security(Path::new("test.yml"), content, &mut findings);
        assert!(findings.iter().any(|f| f.id == "WS-001"));
    }
}

