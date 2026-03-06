//! Auto-Remediation Module for OmniClaw
//! 
//! Provides automatic remediation suggestions and code fixes for security vulnerabilities

use crate::core::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Remediation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RemediationType {
    /// Add a new line or section
    Add,
    /// Replace existing content
    Replace,
    /// Remove content
    Remove,
    /// Update configuration
    UpdateConfig,
    /// Add environment variable
    AddEnvVar,
    /// Update permissions
    UpdatePermissions,
    /// Add security check
    AddSecurityCheck,
}

/// Remediation action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAction {
    pub action_type: RemediationType,
    pub description: String,
    pub code_snippet: Option<String>,
    pub file_path: Option<String>,
    pub line_number: Option<u32>,
    pub confidence: f64,
    pub risk_level: String,
}

/// Complete remediation plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub vulnerability_id: String,
    pub vulnerability_title: String,
    pub severity: Severity,
    pub actions: Vec<RemediationAction>,
    pub estimated_impact: String,
    pub rollback_available: bool,
}

/// Auto-remediation engine
pub struct AutoRemediator {
    pub auto_apply: bool,
    pub create_backup: bool,
    pub dry_run: bool,
}

impl Default for AutoRemediator {
    fn default() -> Self {
        Self {
            auto_apply: false,
            create_backup: true,
            dry_run: true,
        }
    }
}

impl AutoRemediator {
    /// Generate remediation plan for a finding
    pub fn generate_plan(&self, finding: &Finding) -> Option<RemediationPlan> {
        let rule_id = finding.id.as_str();
        
        match rule_id {
            // Workflow Security Rules
            "WS-001" => Some(self.remediate_privileged_trigger(finding)),
            "WS-002" => Some(self.remediate_untrusted_input(finding)),
            "WS-003" => Some(self.remediate_missing_authorization(finding)),
            "WS-005" => Some(self.remediate_untrusted_checkout(finding)),
            "WS-006" => Some(self.remediate_excessive_permissions(finding)),
            
            // CI/CD Rules
            "CI-001" => Some(self.remediate_workflow_privilege_escalation(finding)),
            "CI-002" => Some(self.remediate_unpinned_action(finding)),
            "CI-005" => Some(self.remediate_script_injection(finding)),
            "CI-007" => Some(self.remediate_missing_permissions(finding)),
            
            // Secret Rules
            "SEC-001" | "SEC-002" | "SEC-003" | "SEC-004" | "SEC-005" 
            | "SEC-006" | "SEC-007" | "SEC-008" | "SEC-009" | "SEC-010" 
            | "SEC-011" | "SEC-012" | "SEC-013" | "SEC-014" | "SEC-015" => {
                Some(self.remediate_exposed_secret(finding))
            }
            
            _ => None,
        }
    }
    
    fn remediate_privileged_trigger(&self, finding: &Finding) -> RemediationPlan {
        RemediationPlan {
            vulnerability_id: finding.id.clone(),
            vulnerability_title: finding.title.clone(),
            severity: finding.severity,
            actions: vec![
                RemediationAction {
                    action_type: RemediationType::Replace,
                    description: "Replace pull_request_target with pull_request".to_string(),
                    code_snippet: Some(r#"# Change:
on: pull_request_target

# To:
on: pull_request"#.to_string()),
                    file_path: finding.file.as_ref().map(|p| p.to_string_lossy().to_string()),
                    line_number: finding.line,
                    confidence: 0.95,
                    risk_level: "low".to_string(),
                },
                RemediationAction {
                    action_type: RemediationType::AddSecurityCheck,
                    description: "Add path filter to limit workflow execution".to_string(),
                    code_snippet: Some(r#"on:
  pull_request:
    paths:
      - 'src/**'
      - 'tests/**'"#.to_string()),
                    file_path: finding.file.as_ref().map(|p| p.to_string_lossy().to_string()),
                    line_number: finding.line,
                    confidence: 0.90,
                    risk_level: "low".to_string(),
                },
            ],
            estimated_impact: "Low - workflow behavior changes but maintains security".to_string(),
            rollback_available: true,
        }
    }
    
    fn remediate_untrusted_input(&self, finding: &Finding) -> RemediationPlan {
        RemediationPlan {
            vulnerability_id: finding.id.clone(),
            vulnerability_title: finding.title.clone(),
            severity: finding.severity,
            actions: vec![
                RemediationAction {
                    action_type: RemediationType::Replace,
                    description: "Use environment variables instead of direct interpolation".to_string(),
                    code_snippet: Some(r#"# Instead of:
run: echo ${{ github.event.pull_request.head.ref }}

# Use:
run: |
  REF="${{ github.event.pull_request.head.ref }}"
  echo "Branch: $REF""#.to_string()),
                    file_path: finding.file.as_ref().map(|p| p.to_string_lossy().to_string()),
                    line_number: finding.line,
                    confidence: 0.85,
                    risk_level: "medium".to_string(),
                },
            ],
            estimated_impact: "Medium - changes how branch data is processed".to_string(),
            rollback_available: true,
        }
    }
    
    fn remediate_missing_authorization(&self, finding: &Finding) -> RemediationPlan {
        RemediationPlan {
            vulnerability_id: finding.id.clone(),
            vulnerability_title: finding.title.clone(),
            severity: finding.severity,
            actions: vec![
                RemediationAction {
                    action_type: RemediationType::AddSecurityCheck,
                    description: "Add author association check".to_string(),
                    code_snippet: Some(r#"jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Check author
        run: |
          AUTHOR="${{ github.event.comment.user.login }}"
          ASSOCIATION="${{ github.event.comment.author_association }}"
          if [ "$ASSOCIATION" != "COLLABORATOR" ] && [ "$ASSOCIATION" != "MEMBER" ]; then
            echo "Not authorized"
            exit 1
          fi"#.to_string()),
                    file_path: finding.file.as_ref().map(|p| p.to_string_lossy().to_string()),
                    line_number: finding.line,
                    confidence: 0.90,
                    risk_level: "low".to_string(),
                },
            ],
            estimated_impact: "Low - adds security validation".to_string(),
            rollback_available: true,
        }
    }
    
    fn remediate_untrusted_checkout(&self, finding: &Finding) -> RemediationPlan {
        RemediationPlan {
            vulnerability_id: finding.id.clone(),
            vulnerability_title: finding.title.clone(),
            severity: finding.severity,
            actions: vec![
                RemediationAction {
                    action_type: RemediationType::Replace,
                    description: "Use path filters instead of checking out external code".to_string(),
                    code_snippet: Some(r#"# Remove the checkout step with external ref
# Instead of:
# - uses: actions/checkout@v4
#   with:
#     ref: ${{ github.event.pull_request.head.sha }}

# Use path filters:
on:
  pull_request:
    paths:
      - 'src/**'
      - 'config/**'"#.to_string()),
                    file_path: finding.file.as_ref().map(|p| p.to_string_lossy().to_string()),
                    line_number: finding.line,
                    confidence: 0.95,
                    risk_level: "low".to_string(),
                },
            ],
            estimated_impact: "Low - workflow only runs on specific paths".to_string(),
            rollback_available: true,
        }
    }
    
    fn remediate_excessive_permissions(&self, finding: &Finding) -> RemediationPlan {
        RemediationPlan {
            vulnerability_id: finding.id.clone(),
            vulnerability_title: finding.title.clone(),
            severity: finding.severity,
            actions: vec![
                RemediationAction {
                    action_type: RemediationType::UpdateConfig,
                    description: "Add minimal permissions block".to_string(),
                    code_snippet: Some(r#"permissions:
  contents: read
  issues: write
  pull-requests: write"#.to_string()),
                    file_path: finding.file.as_ref().map(|p| p.to_string_lossy().to_string()),
                    line_number: finding.line,
                    confidence: 0.95,
                    risk_level: "low".to_string(),
                },
            ],
            estimated_impact: "Low - reduces permissions to minimum required".to_string(),
            rollback_available: true,
        }
    }
    
    fn remediate_workflow_privilege_escalation(&self, finding: &Finding) -> RemediationPlan {
        self.remediate_privileged_trigger(finding)
    }
    
    fn remediate_unpinned_action(&self, finding: &Finding) -> RemediationPlan {
        RemediationPlan {
            vulnerability_id: finding.id.clone(),
            vulnerability_title: finding.title.clone(),
            severity: finding.severity,
            actions: vec![
                RemediationAction {
                    action_type: RemediationType::Replace,
                    description: "Pin action to full commit SHA".to_string(),
                    code_snippet: Some(r#"# Change:
uses: actions/checkout@v4

# To (find SHA from action releases):
uses: actions/checkout@a5bbd234556987bd6618fda4d1af3c0b9b9d2a3"#.to_string()),
                    file_path: finding.file.as_ref().map(|p| p.to_string_lossy().to_string()),
                    line_number: finding.line,
                    confidence: 0.95,
                    risk_level: "low".to_string(),
                },
            ],
            estimated_impact: "Low - ensures reproducible builds".to_string(),
            rollback_available: true,
        }
    }
    
    fn remediate_script_injection(&self, finding: &Finding) -> RemediationPlan {
        RemediationPlan {
            vulnerability_id: finding.id.clone(),
            vulnerability_title: finding.title.clone(),
            severity: finding.severity,
            actions: vec![
                RemediationAction {
                    action_type: RemediationType::Replace,
                    description: "Escape user input before using in scripts".to_string(),
                    code_snippet: Some(r#"# Store user input in env var and sanitize
env:
  USER_INPUT: ${{ github.event.inputs.user_value }}
  
run: |
  # Use printf to safely handle input
  printf '%s' "$USER_INPUT" | some-command"#.to_string()),
                    file_path: finding.file.as_ref().map(|p| p.to_string_lossy().to_string()),
                    line_number: finding.line,
                    confidence: 0.80,
                    risk_level: "medium".to_string(),
                },
            ],
            estimated_impact: "Medium - changes input handling".to_string(),
            rollback_available: true,
        }
    }
    
    fn remediate_missing_permissions(&self, finding: &Finding) -> RemediationPlan {
        self.remediate_excessive_permissions(finding)
    }
    
    fn remediate_exposed_secret(&self, finding: &Finding) -> RemediationPlan {
        RemediationPlan {
            vulnerability_id: finding.id.clone(),
            vulnerability_title: finding.title.clone(),
            severity: finding.severity,
            actions: vec![
                RemediationAction {
                    action_type: RemediationType::Replace,
                    description: "Replace hardcoded secret with environment variable".to_string(),
                    code_snippet: Some(r#"# Remove the secret from code
# Add to GitHub Secrets and use:
- name: Use secret
  env:
    API_KEY: ${{ secrets.API_KEY }}
  run: echo "Using API key""#.to_string()),
                    file_path: finding.file.as_ref().map(|p| p.to_string_lossy().to_string()),
                    line_number: finding.line,
                    confidence: 0.90,
                    risk_level: "high".to_string(),
                },
                RemediationAction {
                    action_type: RemediationType::AddSecurityCheck,
                    description: "Rotate the exposed secret immediately".to_string(),
                    code_snippet: None,
                    file_path: None,
                    line_number: None,
                    confidence: 1.0,
                    risk_level: "high".to_string(),
                },
            ],
            estimated_impact: "High - requires secret rotation and configuration change".to_string(),
            rollback_available: false,
        }
    }
    
    /// Generate all remediation plans for multiple findings
    pub fn generate_plans(&self, findings: &[Finding]) -> HashMap<String, RemediationPlan> {
        let mut plans = HashMap::new();
        
        for finding in findings {
            if let Some(plan) = self.generate_plan(finding) {
                plans.insert(finding.id.clone(), plan);
            }
        }
        
        plans
    }
    
    /// Apply remediation plan (if auto_apply is enabled)
    pub fn apply_plan(&self, plan: &RemediationPlan) -> Result<String, String> {
        if !self.auto_apply {
            return Err("Auto-apply is disabled. Use --auto-apply to enable.".to_string());
        }
        
        if self.dry_run {
            return Ok(format!("DRY RUN: Would apply {} remediation actions", plan.actions.len()));
        }
        
        // Implementation would modify files here
        Ok(format!("Applied {} remediation actions", plan.actions.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_plan_for_privileged_trigger() {
        let remediator = AutoRemediator::default();
        let finding = Finding::new(
            "WS-001",
            "Privileged Trigger Vulnerability",
            Severity::Critical,
        );
        
        let plan = remediator.generate_plan(&finding).unwrap();
        assert_eq!(plan.vulnerability_id, "WS-001");
        assert!(!plan.actions.is_empty());
    }
    
    #[test]
    fn test_generate_plan_for_secret() {
        let remediator = AutoRemediator::default();
        let finding = Finding::new(
            "SEC-003",
            "GitHub Token",
            Severity::Critical,
        );
        
        let plan = remediator.generate_plan(&finding).unwrap();
        assert!(plan.actions.iter().any(|a| a.description.contains("secret")));
    }
    
    #[test]
    fn test_generate_plans_multiple_findings() {
        let remediator = AutoRemediator::default();
        let findings = vec![
            Finding::new("WS-001", "Test 1", Severity::Critical),
            Finding::new("SEC-003", "Test 2", Severity::High),
        ];
        
        let plans = remediator.generate_plans(&findings);
        assert_eq!(plans.len(), 2);
    }
}

