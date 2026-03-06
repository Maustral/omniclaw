//! Remote scanner using GitHub API

use crate::core::{Finding, ScanSummary};
use crate::rules::workflow_security;
use crate::rules::cicd;
use reqwest::Client;
use serde::Deserialize;
use std::path::Path;
use std::time::Instant;

/// GitHub API client for remote scanning
pub struct RemoteScanner {
    client: Client,
    token: Option<String>,
    concurrency: usize,
}

#[derive(Debug, Deserialize)]
struct WorkflowFile {
    name: String,
    path: String,
    #[serde(default)]
    sha: String,
}

#[derive(Debug, Deserialize)]
struct WorkflowsResponse {
    #[serde(default)]
    workflows: Vec<WorkflowFile>,
}

impl RemoteScanner {
    /// Create a new remote scanner
    pub fn new(token: Option<String>, concurrency: usize) -> Self {
        Self {
            client: Client::new(),
            token,
            concurrency,
        }
    }
    
    /// Scan a single repository
    pub async fn scan_repo(&self, owner: &str, repo: &str) -> ScanResult {
        let start = Instant::now();
        let mut findings = Vec::new();
        
        let workflows = self.get_workflows(owner, repo).await;
        
        for workflow in &workflows {
            if let Ok(content) = self.get_file_content(owner, repo, &workflow.path).await {
                let path = Path::new(&workflow.path);
                workflow_security::scan_workflow_security(path, &content, &mut findings);
                cicd::apply_generic_rules(path, &content, &mut findings);
            }
        }
        
        let duration_ms = start.elapsed().as_millis() as u64;
        let summary = ScanSummary::from_findings(&findings, duration_ms, workflows.len());
        
        ScanResult { findings, summary }
    }
    
    /// Scan an entire organization
    pub async fn scan_org(&self, org: &str) -> OrgScanResult {
        let start = Instant::now();
        let mut all_findings = Vec::new();
        let mut repo_results = Vec::new();
        
        let repos = self.get_org_repos(org).await;
        
        for repo in repos {
            let repo_name = repo.name.clone();
            let result = self.scan_repo(org, &repo_name).await;
            let findings_count = result.findings.len();
            all_findings.extend(result.findings.clone());
            repo_results.push(RepoScanResult {
                name: repo_name,
                findings_count,
                findings: result.findings,
            });
        }
        
        let duration_ms = start.elapsed().as_millis() as u64;
        let summary = ScanSummary::from_findings(&all_findings, duration_ms, repo_results.len());
        
        OrgScanResult { repo_results, summary }
    }
    
    async fn get_workflows(&self, owner: &str, repo: &str) -> Vec<WorkflowFile> {
        let url = format!(
            "https://api.github.com/repos/{}/{}/contents/.github/workflows",
            owner, repo
        );
        
        let mut request = self.client.get(&url);
        
        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        request = request.header("User-Agent", "OmniClaw-Scanner");
        
        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    response.json().await.unwrap_or_default()
                } else {
                    Vec::new()
                }
            }
            Err(_) => Vec::new(),
        }
    }
    
    async fn get_file_content(&self, owner: &str, repo: &str, path: &str) -> Result<String, String> {
        let dir_url = format!(
            "https://api.github.com/repos/{}/{}/contents/.github/workflows",
            owner, repo
        );
        
        let mut request = self.client.get(&dir_url);
        
        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        request = request.header("User-Agent", "OmniClaw-Scanner");
        
        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    #[derive(Deserialize)]
                    struct DirEntry {
                        name: String,
                        download_url: Option<String>,
                    }
                    
                    if let Ok(entries) = response.json::<Vec<DirEntry>>().await {
                        for entry in entries {
                            if entry.name == Path::new(path).file_name().unwrap().to_string_lossy() {
                                if let Some(download_url) = entry.download_url {
                                    let mut req = self.client.get(&download_url);
                                    if let Some(token) = &self.token {
                                        req = req.header("Authorization", format!("Bearer {}", token));
                                    }
                                    if let Ok(resp) = req.send().await {
                                        if let Ok(content) = resp.text().await {
                                            if let Ok(decoded) = decode_github_content(&content) {
                                                return Ok(decoded);
                                            }
                                            return Ok(content);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err("Failed to fetch file".into())
            }
            Err(e) => Err(e.to_string()),
        }
    }
    
    async fn get_org_repos(&self, org: &str) -> Vec<Repo> {
        let url = format!("https://api.github.com/orgs/{}/repos", org);
        
        let mut request = self.client.get(&url);
        
        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        request = request.header("User-Agent", "OmniClaw-Scanner");
        
        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    response.json().await.unwrap_or_default()
                } else {
                    Vec::new()
                }
            }
            Err(_) => Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Repo {
    name: String,
}

#[derive(Debug)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
}

#[derive(Debug)]
pub struct OrgScanResult {
    pub repo_results: Vec<RepoScanResult>,
    pub summary: ScanSummary,
}

#[derive(Debug)]
pub struct RepoScanResult {
    pub name: String,
    pub findings_count: usize,
    pub findings: Vec<Finding>,
}

fn decode_github_content(encoded: &str) -> Result<String, String> {
    if let Ok(decoded) = base64_decode(encoded) {
        return Ok(decoded);
    }
    Err("Not base64 encoded".into())
}

fn base64_decode(input: &str) -> Result<String, String> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let input = input.trim();
    let mut output = Vec::new();
    
    let bytes: Vec<u8> = input.bytes()
        .filter(|&b| b != b'\n' && b != b'\r' && b != b' ')
        .collect();
    
    let mut i = 0;
    while i < bytes.len() {
        let mut block = [0u8; 4];
        for j in 0..4 {
            if i + j < bytes.len() {
                let b = bytes[i + j];
                if b == b'=' {
                    block[j] = 0;
                } else if let Some(pos) = CHARS.iter().position(|&x| x == b) {
                    block[j] = pos as u8;
                } else {
                    return Err("Invalid base64".into());
                }
            }
        }
        
        output.push((block[0] << 2) | (block[1] >> 4));
        if bytes.len() > i + 2 && bytes[i + 2] != b'=' {
            output.push((block[1] << 4) | (block[2] >> 2));
        }
        if bytes.len() > i + 3 && bytes[i + 3] != b'=' {
            output.push((block[2] << 6) | block[3]);
        }
        
        i += 4;
    }
    
    String::from_utf8(output).map_err(|_| "Invalid UTF-8".into())
}

