//! OmniClaw MCP Server
//! 
//! Model Context Protocol server for AI integration

use omniclaw::scanner::LocalScanner;
use omniclaw::pr_guard::PRGuard;
use omniclaw::core::Severity;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// MCP tool for scanning workflows
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanRequest {
    pub path: String,
    pub deep: Option<bool>,
    pub min_severity: Option<String>,
}

/// MCP tool for PR Guard
#[derive(Debug, Serialize, Deserialize)]
pub struct GuardRequest {
    pub branch: Option<String>,
    pub files: Option<Vec<String>>,
    pub diff: Option<String>,
    pub ai_config: Option<String>,
}

/// MCP tool response
#[derive(Debug, Serialize, Deserialize)]
pub struct ToolResponse {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// List available MCP tools
pub fn list_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "omniclaw_scan".to_string(),
            description: "Scan local workflow files for security vulnerabilities".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to scan (directory or file)"
                    },
                    "deep": {
                        "type": "boolean",
                        "description": "Enable deep scan (recursive)"
                    },
                    "min_severity": {
                        "type": "string",
                        "description": "Minimum severity (critical, high, medium, low, info)"
                    }
                }
            }),
        },
        ToolDefinition {
            name: "omniclaw_guard".to_string(),
            description: "Run PR Guard checks on branch names, files, and diffs".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "branch": {
                        "type": "string",
                        "description": "Branch name to check"
                    },
                    "files": {
                        "type": "array",
                        "description": "List of files to check",
                        "items": { "type": "string" }
                    },
                    "diff": {
                        "type": "string",
                        "description": "Diff content to check"
                    },
                    "ai_config": {
                        "type": "string",
                        "description": "AI config content to check for injection"
                    }
                }
            }),
        },
        ToolDefinition {
            name: "omniclaw_rules".to_string(),
            description: "List all available security rules".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "platform": {
                        "type": "string",
                        "description": "Filter by platform (github_actions, gitlab_ci, jenkins)"
                    }
                }
            }),
        },
    ]
}

/// Tool definition
#[derive(Debug, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

/// Execute scan tool
pub fn execute_scan(request: ScanRequest) -> ToolResponse {
    let path = PathBuf::from(&request.path);
    
    if !path.exists() {
        return ToolResponse {
            success: false,
            data: None,
            error: Some(format!("Path does not exist: {}", request.path)),
        };
    }
    
    let mut config = omniclaw::ScannerConfig::default();
    config.deep_scan = request.deep.unwrap_or(false);
    
    if let Some(severity) = request.min_severity {
        config.min_severity = Severity::from_str(&severity);
    }
    
    let scanner = LocalScanner::with_config(config);
    let result = scanner.scan(&path);
    
    ToolResponse {
        success: true,
        data: Some(serde_json::json!({
            "findings": result.findings,
            "summary": result.summary,
        })),
        error: None,
    }
}

/// Execute guard tool
pub fn execute_guard(request: GuardRequest) -> ToolResponse {
    let guard = PRGuard::new();
    
    let result = guard.check(
        request.branch.as_deref(),
        request.files.as_deref(),
        request.diff.as_deref(),
        request.ai_config.as_deref(),
    );
    
    ToolResponse {
        success: result.safe,
        data: Some(serde_json::json!({
            "safe": result.safe,
            "results": result,
        })),
        error: None,
    }
}

/// Execute rules tool
pub fn execute_rules(platform: Option<String>) -> ToolResponse {
    let rules = omniclaw::rules::all_cicd_rules();
    let ws_rules = omniclaw::rules::all_workflow_security_rules();
    
    // Convert rules to serializable format
    let ws_rules_json: Vec<serde_json::Value> = ws_rules.iter().map(|r| {
        serde_json::json!({
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "severity": r.severity.to_string(),
            "cwe_ids": r.cwe_ids,
        })
    }).collect();
    
    let cicd_rules_json: Vec<serde_json::Value> = rules.iter().map(|r| {
        serde_json::json!({
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "severity": r.severity,
            "platform": r.platform,
        })
    }).collect();
    
    ToolResponse {
        success: true,
        data: Some(serde_json::json!({
            "workflow_security_rules": ws_rules_json,
            "cicd_rules": cicd_rules_json,
        })),
        error: None,
    }
}

fn main() {
    println!("OmniClaw MCP Server");
    println!("This is a placeholder for the MCP server implementation.");
    println!("Tools available:");
    
    for tool in list_tools() {
        println!("  - {}: {}", tool.name, tool.description);
    }
}

