//! Custom Rules Engine for OmniClaw
//! 
//! Allows users to define and execute custom security rules

use crate::core::{Finding, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Rule definition format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub pattern: String,
    pub file_types: Vec<String>,
    pub enabled: bool,
    pub tags: Vec<String>,
    pub remediation: Option<String>,
    pub cwe_ids: Option<Vec<u32>>,
}

impl CustomRule {
    pub fn new(id: impl Into<String>, name: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            severity: "Medium".to_string(),
            pattern: pattern.into(),
            file_types: vec!["*".to_string()],
            enabled: true,
            tags: vec![],
            remediation: None,
            cwe_ids: None,
        }
    }
    
    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = severity.into();
        self
    }
    
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
    
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }
    
    pub fn with_file_types(mut self, file_types: Vec<String>) -> Self {
        self.file_types = file_types;
        self
    }
    
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
    
    pub fn with_cwe_ids(mut self, cwe_ids: Vec<u32>) -> Self {
        self.cwe_ids = Some(cwe_ids);
        self
    }
    
    pub fn compile_pattern(&self) -> Result<Regex, regex::Error> {
        Regex::new(&self.pattern)
    }
}

/// Rules configuration file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    pub version: String,
    pub rules: Vec<CustomRule>,
}

/// Custom rules engine
pub struct RulesEngine {
    rules: Vec<CustomRule>,
    compiled_rules: HashMap<String, Regex>,
}

impl Default for RulesEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RulesEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            compiled_rules: HashMap::new(),
        }
    }
    
    /// Add a rule to the engine
    pub fn add_rule(&mut self, rule: CustomRule) -> Result<(), String> {
        // Compile the pattern to verify it's valid
        match rule.compile_pattern() {
            Ok(regex) => {
                if rule.enabled {
                    self.compiled_rules.insert(rule.id.clone(), regex);
                }
                self.rules.push(rule);
                Ok(())
            }
            Err(e) => Err(format!("Invalid regex pattern: {}", e)),
        }
    }
    
    /// Add multiple rules
    pub fn add_rules(&mut self, rules: Vec<CustomRule>) -> Result<(), String> {
        for rule in rules {
            self.add_rule(rule)?;
        }
        Ok(())
    }
    
    /// Load rules from YAML configuration
    pub fn load_from_yaml(&mut self, content: &str) -> Result<(), String> {
        #[derive(Deserialize)]
        struct YamlRulesConfig {
            rules: Vec<YamlCustomRule>,
        }
        
        #[derive(Deserialize)]
        struct YamlCustomRule {
            id: String,
            name: String,
            description: Option<String>,
            severity: Option<String>,
            pattern: String,
            file_types: Option<Vec<String>>,
            enabled: Option<bool>,
            tags: Option<Vec<String>>,
            remediation: Option<String>,
            cwe_ids: Option<Vec<u32>>,
        }
        
        let config: YamlRulesConfig = serde_yaml::from_str(content)
            .map_err(|e| format!("Failed to parse rules YAML: {}", e))?;
        
        for yaml_rule in config.rules {
            let rule = CustomRule {
                id: yaml_rule.id,
                name: yaml_rule.name,
                description: yaml_rule.description.unwrap_or_default(),
                severity: yaml_rule.severity.unwrap_or_else(|| "Medium".to_string()),
                pattern: yaml_rule.pattern,
                file_types: yaml_rule.file_types.unwrap_or_else(|| vec!["*".to_string()]),
                enabled: yaml_rule.enabled.unwrap_or(true),
                tags: yaml_rule.tags.unwrap_or_default(),
                remediation: yaml_rule.remediation,
                cwe_ids: yaml_rule.cwe_ids,
            };
            self.add_rule(rule)?;
        }
        
        Ok(())
    }
    
    /// Load rules from JSON configuration
    pub fn load_from_json(&mut self, content: &str) -> Result<(), String> {
        let config: RulesConfig = serde_json::from_str(content)
            .map_err(|e| format!("Failed to parse rules JSON: {}", e))?;
        
        for rule in config.rules {
            self.add_rule(rule)?;
        }
        
        Ok(())
    }
    
    /// Load rules from a file
    pub fn load_from_file(&mut self, path: &Path) -> Result<(), String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read rules file: {}", e))?;
        
        let path_str = path.to_string_lossy().to_lowercase();
        
        if path_str.ends_with(".yaml") || path_str.ends_with(".yml") {
            self.load_from_yaml(&content)
        } else if path_str.ends_with(".json") {
            self.load_from_json(&content)
        } else {
            Err("Unsupported rules file format. Use .yaml, .yml, or .json".to_string())
        }
    }
    
    /// Scan content with custom rules
    pub fn scan(&self, path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let file_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            
            // Check if rule applies to this file type
            let applies = rule.file_types.iter().any(|ft| {
                ft == "*" || file_name.ends_with(&format!(".{}", ft)) || ft == file_name
            });
            
            if !applies {
                continue;
            }
            
            // Get compiled pattern
            if let Some(pattern) = self.compiled_rules.get(&rule.id) {
                for (line_num, line) in content.lines().enumerate() {
                    if pattern.is_match(line) {
                        findings.push(Finding::new(
                            format!("CUSTOM-{}", rule.id),
                            rule.name.clone(),
                            self.parse_severity(&rule.severity),
                        )
                        .with_file(path.to_path_buf())
                        .with_line((line_num + 1) as u32)
                        .with_evidence(line.trim().to_string())
                        .with_description(rule.description.clone())
                        .with_remediation(rule.remediation.as_deref().unwrap_or(""))
                        .with_cwe_ids(rule.cwe_ids.as_deref().unwrap_or(&[]))
                        .with_source("custom_rules"));
                    }
                }
            }
        }
        
        findings
    }
    
    fn parse_severity(&self, s: &str) -> Severity {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "med" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
    
    /// Get all loaded rules
    pub fn get_rules(&self) -> &[CustomRule] {
        &self.rules
    }
    
    /// Enable or disable a rule
    pub fn set_enabled(&mut self, rule_id: &str, enabled: bool) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = enabled;
            
            // Update compiled rules
            if enabled {
                if let Ok(regex) = rule.compile_pattern() {
                    self.compiled_rules.insert(rule.id.clone(), regex);
                }
            } else {
                self.compiled_rules.remove(rule_id);
            }
            true
        } else {
            false
        }
    }
    
    /// Remove a rule
    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let idx = self.rules.iter().position(|r| r.id == rule_id);
        if let Some(idx) = idx {
            self.rules.remove(idx);
            self.compiled_rules.remove(rule_id);
            true
        } else {
            false
        }
    }
    
    /// Export rules to JSON
    pub fn to_json(&self) -> Result<String, String> {
        let config = RulesConfig {
            version: "1.0".to_string(),
            rules: self.rules.clone(),
        };
        serde_json::to_string_pretty(&config)
            .map_err(|e| format!("Failed to serialize rules: {}", e))
    }
    
    /// Export rules to YAML
    pub fn to_yaml(&self) -> Result<String, String> {
        serde_yaml::to_string(&self.rules)
            .map_err(|e| format!("Failed to serialize rules: {}", e))
    }
}

/// Create example custom rules
pub fn example_rules() -> Vec<CustomRule> {
    vec![
        CustomRule::new(
            "001",
            "TODO with security implications",
            r"(?i)TODO.*(?:security|vuln|exploit|hack)"
        )
        .with_severity("Medium")
        .with_description("TODO comment related to security")
        .with_remediation("Address the security TODO immediately")
        .with_file_types(vec!["rs".to_string(), "js".to_string(), "ts".to_string(), "py".to_string()]),
        
        CustomRule::new(
            "002",
            "Hardcoded IP address",
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        )
        .with_severity("Low")
        .with_description("Hardcoded IP address found")
        .with_remediation("Use environment variables or configuration for IP addresses")
        .with_file_types(vec!["*".to_string()]),
        
        CustomRule::new(
            "003",
            "Debug mode enabled in production",
            r"(?i)(debug:\s*true|DEBUG\s*=\s*1|ENABLE_DEBUG)"
        )
        .with_severity("High")
        .with_description("Debug mode detected in code")
        .with_remediation("Disable debug mode in production")
        .with_tags(vec!["production".to_string(), "security".to_string()]),
        
        CustomRule::new(
            "004",
            "Insecure random number generation",
            r"(?i)(Math\.random\(\)|Math\.floor\(Math\.random\(\))"
        )
        .with_severity("Medium")
        .with_description("Insecure random number generation detected")
        .with_remediation("Use cryptographically secure random number generation (e.g., crypto.getRandomValues)")
        .with_cwe_ids(vec![338])
        .with_file_types(vec!["js".to_string(), "ts".to_string()]),
        
        CustomRule::new(
            "005",
            "Console.log in production code",
            r"console\.(log|debug|info)\("
        )
        .with_severity("Low")
        .with_description("Console logging in production")
        .with_remediation("Remove console statements in production or use proper logging framework")
        .with_tags(vec!["best-practice".to_string()])
        .with_file_types(vec!["js".to_string(), "ts".to_string()]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    
    #[test]
    fn test_add_rule() {
        let mut engine = RulesEngine::new();
        
        let rule = CustomRule::new("TEST-001", "Test Rule", r"password\s*=\s*\w+")
            .with_severity("High");
        
        assert!(engine.add_rule(rule).is_ok());
        assert_eq!(engine.get_rules().len(), 1);
    }
    
    #[test]
    fn test_scan() {
        let mut engine = RulesEngine::new();
        
        let rule = CustomRule::new("TEST-001", "Password Detection", r"password\s*=")
            .with_severity("High")
            .with_file_types(vec!["js".to_string()]);
        
        engine.add_rule(rule).unwrap();
        
        let content = "const password = 'secret123';";
        let findings = engine.scan(Path::new("test.js"), content);
        
        assert!(!findings.is_empty());
        assert_eq!(findings[0].id, "CUSTOM-TEST-001");
    }
    
    #[test]
    fn test_example_rules() {
        let rules = example_rules();
        assert!(!rules.is_empty());
    }
    
    #[test]
    fn test_disable_rule() {
        let mut engine = RulesEngine::new();
        
        let rule = CustomRule::new("TEST-001", "Test", r"test");
        engine.add_rule(rule).unwrap();
        
        engine.set_enabled("TEST-001", false);
        
        let findings = engine.scan(Path::new("test.txt"), "test content");
        assert!(findings.is_empty());
    }
}

