//! Advanced Secret Scanner for OmniClaw
//! 
//! Detects secrets using entropy analysis, pattern matching, and context awareness

use crate::core::{Finding, Severity};
use crate::crypto::Sha256Hash;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

/// Minimum entropy threshold for high-entropy string detection
const HIGH_ENTROPY_THRESHOLD: f64 = 4.5;
const MEDIUM_ENTROPY_THRESHOLD: f64 = 3.5;

/// Secret type classification
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecretType {
    AwsAccessKey,
    AwsSecretKey,
    GithubToken,
    GitlabToken,
    JwtToken,
    PrivateKey,
    Password,
    ApiKey,
    DatabaseUrl,
    SlackToken,
    StripeKey,
    SendGridKey,
    TwilioKey,
    GenericSecret,
    HighEntropy,
}

impl SecretType {
    pub fn severity(&self) -> Severity {
        match self {
            SecretType::PrivateKey => Severity::Critical,
            SecretType::AwsSecretKey => Severity::Critical,
            SecretType::GithubToken => Severity::Critical,
            SecretType::GitlabToken => Severity::Critical,
            SecretType::JwtToken => Severity::High,
            SecretType::StripeKey => Severity::Critical,
            SecretType::HighEntropy => Severity::High,
            SecretType::GenericSecret => Severity::Medium,
            _ => Severity::Medium,
        }
    }

    pub fn id(&self) -> String {
        match self {
            SecretType::AwsAccessKey => "SEC-001".to_string(),
            SecretType::AwsSecretKey => "SEC-002".to_string(),
            SecretType::GithubToken => "SEC-003".to_string(),
            SecretType::GitlabToken => "SEC-004".to_string(),
            SecretType::JwtToken => "SEC-005".to_string(),
            SecretType::PrivateKey => "SEC-006".to_string(),
            SecretType::Password => "SEC-007".to_string(),
            SecretType::ApiKey => "SEC-008".to_string(),
            SecretType::DatabaseUrl => "SEC-009".to_string(),
            SecretType::SlackToken => "SEC-010".to_string(),
            SecretType::StripeKey => "SEC-011".to_string(),
            SecretType::SendGridKey => "SEC-012".to_string(),
            SecretType::TwilioKey => "SEC-013".to_string(),
            SecretType::HighEntropy => "SEC-014".to_string(),
            SecretType::GenericSecret => "SEC-015".to_string(),
        }
    }

    pub fn name(&self) -> String {
        match self {
            SecretType::AwsAccessKey => "AWS Access Key".to_string(),
            SecretType::AwsSecretKey => "AWS Secret Key".to_string(),
            SecretType::GithubToken => "GitHub Token".to_string(),
            SecretType::GitlabToken => "GitLab Token".to_string(),
            SecretType::JwtToken => "JWT Token".to_string(),
            SecretType::PrivateKey => "Private Key".to_string(),
            SecretType::Password => "Password".to_string(),
            SecretType::ApiKey => "API Key".to_string(),
            SecretType::DatabaseUrl => "Database URL".to_string(),
            SecretType::SlackToken => "Slack Token".to_string(),
            SecretType::StripeKey => "Stripe API Key".to_string(),
            SecretType::SendGridKey => "SendGrid API Key".to_string(),
            SecretType::TwilioKey => "Twilio API Key".to_string(),
            SecretType::HighEntropy => "High Entropy String".to_string(),
            SecretType::GenericSecret => "Potential Secret".to_string(),
        }
    }
}

/// Detected secret with metadata
#[derive(Debug, Clone)]
pub struct DetectedSecret {
    pub secret_type: SecretType,
    pub value_preview: String,
    pub line: u32,
    pub column: usize,
    pub context_before: String,
    pub context_after: String,
    pub entropy: f64,
    pub file_path: String,
}

lazy_static! {
    // AWS Access Key pattern
    pub static ref AWS_ACCESS_KEY: Regex = Regex::new(
        r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    ).unwrap();
    
    // AWS Secret Key pattern
pub static ref AWS_SECRET_KEY: Regex = Regex::new(
        r#"(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)[\s=:]+['"]?([A-Za-z0-9/+=]{40})['"]?"#
    ).unwrap();
    
    // GitHub Token pattern
    pub static ref GITHUB_TOKEN: Regex = Regex::new(
        r"(?:gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,})"
    ).unwrap();
    
    // GitLab Token pattern
    pub static ref GITLAB_TOKEN: Regex = Regex::new(
        r"glpat-[A-Za-z0-9\-]{20,}"
    ).unwrap();
    
    // JWT Token pattern
    pub static ref JWT_TOKEN: Regex = Regex::new(
        r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"
    ).unwrap();
    
    // Private Key patterns
    pub static ref PRIVATE_KEY: Regex = Regex::new(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ).unwrap();
    
    // Generic password patterns
    pub static ref PASSWORD_PATTERN: Regex = Regex::new(
        r#"(?i)(?:password|passwd|pwd|secret|token|api_key|apikey|auth)[\s]*[:=][\s]*['"]?([^'"]{8,})['"]?"#
    ).unwrap();
    
    // Database URL patterns
    pub static ref DATABASE_URL: Regex = Regex::new(
        r"(?i)(?:mysql|postgresql|postgres|mongodb|redis)://[^\s]+"
    ).unwrap();
    
    // Slack Token
    pub static ref SLACK_TOKEN: Regex = Regex::new(
        r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"
    ).unwrap();
    
    // Stripe Key
    pub static ref STRIPE_KEY: Regex = Regex::new(
        r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}"
    ).unwrap();
    
    // SendGrid Key
    pub static ref SENDGRID_KEY: Regex = Regex::new(
        r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"
    ).unwrap();
    
    // Twilio Key
    pub static ref TWILIO_KEY: Regex = Regex::new(
        r"SK[a-f0-9]{32}"
    ).unwrap();
}

/// Calculate Shannon entropy of a string
pub fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    
    let mut frequency = HashMap::new();
    for byte in s.bytes() {
        *frequency.entry(byte).or_insert(0) += 1;
    }
    
    let len = s.len() as f64;
    let mut entropy = 0.0;
    
    for count in frequency.values() {
        let probability = *count as f64 / len;
        entropy -= probability * probability.log2();
    }
    
    entropy
}

/// Check if a string has high entropy (potential secret)
pub fn has_high_entropy(s: &str, threshold: f64) -> bool {
    // Filter out very short strings
    if s.len() < 20 {
        return false;
    }
    
    // Filter out strings with low character diversity
    let unique_chars = s.chars().collect::<std::collections::HashSet<_>>().len();
    if unique_chars < 10 {
        return false;
    }
    
    calculate_entropy(s) >= threshold
}

/// Main secret scanner
pub struct SecretScanner {
    pub scan_entropy: bool,
    pub entropy_threshold: f64,
    pub context_lines: usize,
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self {
            scan_entropy: true,
            entropy_threshold: HIGH_ENTROPY_THRESHOLD,
            context_lines: 2,
        }
    }
}

impl SecretScanner {
    /// Scan a file for secrets
    pub fn scan_file(&self, path: &Path, content: &str) -> Vec<DetectedSecret> {
        let mut secrets = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = (line_idx + 1) as u32;
            
            // Check for AWS Access Key
            if let Some(m) = AWS_ACCESS_KEY.find(line) {
                secrets.push(DetectedSecret {
                    secret_type: SecretType::AwsAccessKey,
                    value_preview: m.as_str()[..std::cmp::min(20, m.as_str().len())].to_string() + "...",
                    line: line_num,
                    column: m.start(),
                    context_before: get_context(&lines, line_idx, self.context_lines, false),
                    context_after: get_context(&lines, line_idx, self.context_lines, true),
                    entropy: calculate_entropy(m.as_str()),
                    file_path: path.to_string_lossy().to_string(),
                });
            }
            
            // Check for AWS Secret Key
            if let Some(caps) = AWS_SECRET_KEY.captures(line) {
                if let Some(m) = caps.get(1) {
                    secrets.push(DetectedSecret {
                        secret_type: SecretType::AwsSecretKey,
                        value_preview: "AWS_SECRET_***".to_string(),
                        line: line_num,
                        column: m.start(),
                        context_before: get_context(&lines, line_idx, self.context_lines, false),
                        context_after: get_context(&lines, line_idx, self.context_lines, true),
                        entropy: calculate_entropy(m.as_str()),
                        file_path: path.to_string_lossy().to_string(),
                    });
                }
            }
            
            // Check for GitHub Token
            if let Some(m) = GITHUB_TOKEN.find(line) {
                secrets.push(DetectedSecret {
                    secret_type: SecretType::GithubToken,
                    value_preview: format!("{}...", &m.as_str()[..std::cmp::min(10, m.as_str().len())]),
                    line: line_num,
                    column: m.start(),
                    context_before: get_context(&lines, line_idx, self.context_lines, false),
                    context_after: get_context(&lines, line_idx, self.context_lines, true),
                    entropy: calculate_entropy(m.as_str()),
                    file_path: path.to_string_lossy().to_string(),
                });
            }
            
            // Check for GitLab Token
            if let Some(m) = GITLAB_TOKEN.find(line) {
                secrets.push(DetectedSecret {
                    secret_type: SecretType::GitlabToken,
                    value_preview: "glpat-***".to_string(),
                    line: line_num,
                    column: m.start(),
                    context_before: get_context(&lines, line_idx, self.context_lines, false),
                    context_after: get_context(&lines, line_idx, self.context_lines, true),
                    entropy: calculate_entropy(m.as_str()),
                    file_path: path.to_string_lossy().to_string(),
                });
            }
            
            // Check for JWT Token
            if let Some(m) = JWT_TOKEN.find(line) {
                secrets.push(DetectedSecret {
                    secret_type: SecretType::JwtToken,
                    value_preview: format!("{}...", &m.as_str()[..std::cmp::min(15, m.as_str().len())]),
                    line: line_num,
                    column: m.start(),
                    context_before: get_context(&lines, line_idx, self.context_lines, false),
                    context_after: get_context(&lines, line_idx, self.context_lines, true),
                    entropy: calculate_entropy(m.as_str()),
                    file_path: path.to_string_lossy().to_string(),
                });
            }
            
            // Check for Private Key
            if PRIVATE_KEY.is_match(line) {
                secrets.push(DetectedSecret {
                    secret_type: SecretType::PrivateKey,
                    value_preview: "-----BEGIN PRIVATE KEY-----".to_string(),
                    line: line_num,
                    column: 0,
                    context_before: get_context(&lines, line_idx, self.context_lines, false),
                    context_after: get_context(&lines, line_idx, self.context_lines, true),
                    entropy: calculate_entropy(line),
                    file_path: path.to_string_lossy().to_string(),
                });
            }
            
            // Check for Database URLs
            if let Some(m) = DATABASE_URL.find(line) {
                // Mask credentials in URL
                let masked = mask_url_credentials(m.as_str());
                secrets.push(DetectedSecret {
                    secret_type: SecretType::DatabaseUrl,
                    value_preview: masked,
                    line: line_num,
                    column: m.start(),
                    context_before: get_context(&lines, line_idx, self.context_lines, false),
                    context_after: get_context(&lines, line_idx, self.context_lines, true),
                    entropy: calculate_entropy(m.as_str()),
                    file_path: path.to_string_lossy().to_string(),
                });
            }
            
            // Check for Slack Token
            if let Some(m) = SLACK_TOKEN.find(line) {
                secrets.push(DetectedSecret {
                    secret_type: SecretType::SlackToken,
                    value_preview: "xoxb-***".to_string(),
                    line: line_num,
                    column: m.start(),
                    context_before: get_context(&lines, line_idx, self.context_lines, false),
                    context_after: get_context(&lines, line_idx, self.context_lines, true),
                    entropy: calculate_entropy(m.as_str()),
                    file_path: path.to_string_lossy().to_string(),
                });
            }
            
            // Check for Stripe Key
            if let Some(m) = STRIPE_KEY.find(line) {
                secrets.push(DetectedSecret {
                    secret_type: SecretType::StripeKey,
                    value_preview: format!("{}...", &m.as_str()[..std::cmp::min(8, m.as_str().len())]),
                    line: line_num,
                    column: m.start(),
                    context_before: get_context(&lines, line_idx, self.context_lines, false),
                    context_after: get_context(&lines, line_idx, self.context_lines, true),
                    entropy: calculate_entropy(m.as_str()),
                    file_path: path.to_string_lossy().to_string(),
                });
            }
            
            // Check for SendGrid Key
            if let Some(m) = SENDGRID_KEY.find(line) {
                secrets.push(DetectedSecret {
                    secret_type: SecretType::SendGridKey,
                    value_preview: "SG.***".to_string(),
                    line: line_num,
                    column: m.start(),
                    context_before: get_context(&lines, line_idx, self.context_lines, false),
                    context_after: get_context(&lines, line_idx, self.context_lines, true),
                    entropy: calculate_entropy(m.as_str()),
                    file_path: path.to_string_lossy().to_string(),
                });
            }
            
            // Check for Twilio Key
            if let Some(m) = TWILIO_KEY.find(line) {
                secrets.push(DetectedSecret {
                    secret_type: SecretType::TwilioKey,
                    value_preview: "SK***".to_string(),
                    line: line_num,
                    column: m.start(),
                    context_before: get_context(&lines, line_idx, self.context_lines, false),
                    context_after: get_context(&lines, line_idx, self.context_lines, true),
                    entropy: calculate_entropy(m.as_str()),
                    file_path: path.to_string_lossy().to_string(),
                });
            }
            
            // Check for generic password patterns
            if let Some(caps) = PASSWORD_PATTERN.captures(line) {
                if let Some(m) = caps.get(1) {
                    secrets.push(DetectedSecret {
                        secret_type: SecretType::Password,
                        value_preview: "***".to_string(),
                        line: line_num,
                        column: m.start(),
                        context_before: get_context(&lines, line_idx, self.context_lines, false),
                        context_after: get_context(&lines, line_idx, self.context_lines, true),
                        entropy: calculate_entropy(m.as_str()),
                        file_path: path.to_string_lossy().to_string(),
                    });
                }
            }
            
            // High entropy scanning (for potential unknown secret types)
            if self.scan_entropy {
                self.scan_high_entropy(line, line_idx, &lines, path, &mut secrets);
            }
        }
        
        secrets
    }
    
    fn scan_high_entropy(
        &self,
        line: &str,
        line_idx: usize,
        lines: &[&str],
        path: &Path,
        secrets: &mut Vec<DetectedSecret>,
    ) {
        // Look for long base64-like strings
        let base64_pattern = Regex::new(r"[A-Za-z0-9+/]{32,}={0,2}").unwrap();
        
        for m in base64_pattern.find_iter(line) {
            let s = m.as_str();
            let entropy = calculate_entropy(s);
            
            if entropy >= self.entropy_threshold {
                secrets.push(DetectedSecret {
                    secret_type: SecretType::HighEntropy,
                    value_preview: format!("{}...", &s[..std::cmp::min(15, s.len())]),
                    line: (line_idx + 1) as u32,
                    column: m.start(),
                    context_before: get_context(lines, line_idx, self.context_lines, false),
                    context_after: get_context(lines, line_idx, self.context_lines, true),
                    entropy,
                    file_path: path.to_string_lossy().to_string(),
                });
            }
        }
        
        // Look for hex strings that might be keys
        let hex_pattern = Regex::new(r"0x[a-fA-F0-9]{32,}").unwrap();
        
        for m in hex_pattern.find_iter(line) {
            let s = m.as_str();
            let entropy = calculate_entropy(s);
            
            if entropy >= self.entropy_threshold {
                secrets.push(DetectedSecret {
                    secret_type: SecretType::HighEntropy,
                    value_preview: format!("0x{}...", &s[2..std::cmp::min(18, s.len())]),
                    line: (line_idx + 1) as u32,
                    column: m.start(),
                    context_before: get_context(lines, line_idx, self.context_lines, false),
                    context_after: get_context(lines, line_idx, self.context_lines, true),
                    entropy,
                    file_path: path.to_string_lossy().to_string(),
                });
            }
        }
    }
    
    /// Convert detected secrets to OmniClaw findings
    pub fn to_findings(&self, secrets: &[DetectedSecret]) -> Vec<Finding> {
        secrets
            .iter()
            .map(|s| {
                Finding::new(
                    s.secret_type.id(),
                    s.secret_type.name(),
                    s.secret_type.severity(),
                )
                .with_file(std::path::PathBuf::from(&s.file_path))
                .with_line(s.line)
                .with_evidence(format!(
                    "Line {}: {} | Entropy: {:.2}",
                    s.line, s.value_preview, s.entropy
                ))
                .with_description(format!(
                    "Potential {} detected with entropy {:.2}. Review and rotate if legitimate.",
                    s.secret_type.name(),
                    s.entropy
                ))
                .with_remediation(get_remediation(&s.secret_type))
                .with_source("secret_scanner")
            })
            .collect()
    }
}

/// Get context lines around a match
fn get_context(lines: &[&str], line_idx: usize, count: usize, after: bool) -> String {
    let start = if after {
        line_idx + 1
    } else {
        line_idx.saturating_sub(count)
    };
    let end = if after {
        std::cmp::min(line_idx + count + 1, lines.len())
    } else {
        line_idx
    };
    
    lines[start..end]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Mask credentials in URL
fn mask_url_credentials(url: &str) -> String {
    // Simple implementation - mask user:pass@ portion
    let re = Regex::new(r"://([^:]+):([^@]+)@").unwrap();
    re.replace(url, "://***:***@").to_string()
}

/// Get remediation advice for secret type
fn get_remediation(secret_type: &SecretType) -> String {
    match secret_type {
        SecretType::AwsAccessKey | SecretType::AwsSecretKey => {
            "Rotate the AWS credentials immediately. Delete the exposed keys from IAM and create new ones. Enable AWS CloudTrail for monitoring.".to_string()
        }
        SecretType::GithubToken => {
            "Revoke the GitHub token immediately in Settings > Developer settings > Tokens. Enable token expiration and use fine-grained tokens with minimal permissions.".to_string()
        }
        SecretType::GitlabToken => {
            "Revoke the GitLab token in User Settings > Access Tokens. Consider using project-scoped tokens with minimal scope.".to_string()
        }
        SecretType::JwtToken => {
            "Invalidate the JWT token and implement token rotation. Use short-lived tokens and implement proper token storage.".to_string()
        }
        SecretType::PrivateKey => {
            "Immediately regenerate the private key. Revoke the exposed key from any services. Never commit private keys to repositories.".to_string()
        }
        SecretType::Password => {
            "Change the password immediately. Use a secrets manager instead of hardcoding passwords in source code.".to_string()
        }
        SecretType::DatabaseUrl => {
            "Rotate database credentials immediately. Use environment variables or a secrets manager to store connection strings.".to_string()
        }
        SecretType::StripeKey => {
            "Revoke the Stripe API key in the Stripe dashboard. Use test keys in development and ensure production keys are never committed.".to_string()
        }
        SecretType::HighEntropy => {
            "Investigate the high-entropy string. If it is a secret, rotate it and store it in a secrets manager. Consider using automated secret scanning.".to_string()
        }
        _ => {
            "Investigate the detected secret. If legitimate, move it to a secrets manager and ensure it is not committed to the repository.".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_entropy_calculation() {
        // High entropy (random-like)
        let high = "aB3#kL9@mN2$pQ5!";
        assert!(calculate_entropy(high) > 4.0);
        
        // Low entropy (repetitive)
        let low = "aaaaaaaaaa";
        assert!(calculate_entropy(low) < 2.0);
    }
    
    #[test]
    fn test_aws_key_detection() {
        let scanner = SecretScanner::default();
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let secrets = scanner.scan_file(Path::new("test.txt"), content);
        
        assert!(!secrets.is_empty());
        assert_eq!(secrets[0].secret_type, SecretType::AwsAccessKey);
    }
    
    #[test]
    fn test_github_token_detection() {
        let scanner = SecretScanner::default();
        let content = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let secrets = scanner.scan_file(Path::new("test.txt"), content);
        
        assert!(!secrets.is_empty());
        assert_eq!(secrets[0].secret_type, SecretType::GithubToken);
    }
    
    #[test]
    fn test_high_entropy_detection() {
        let scanner = SecretScanner::default();
        // Base64 string with high entropy
        let content = "API_KEY=dGhpcyBpcyBhIHZlcnkgbG9uZyBzZWNyZXQga2V5IGZvciB0ZXN0aW5n";
        let secrets = scanner.scan_file(Path::new("test.txt"), content);
        
        assert!(!secrets.is_empty());
    }
}
