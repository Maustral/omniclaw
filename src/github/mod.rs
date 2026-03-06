//! GitHub API integration for OmniClaw

use reqwest::Client;
use serde::Deserialize;

/// GitHub client for API operations
pub struct GitHubClient {
    client: Client,
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Repository {
    pub name: String,
    pub full_name: String,
    pub owner: Owner,
    pub html_url: String,
}

#[derive(Debug, Deserialize)]
pub struct Owner {
    pub login: String,
}

#[derive(Debug, Deserialize)]
pub struct Workflow {
    pub name: String,
    pub path: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct Content {
    pub name: String,
    pub path: String,
    pub sha: String,
    pub content: Option<String>,
    pub encoding: Option<String>,
}

impl GitHubClient {
    /// Create a new GitHub client
    pub fn new(token: Option<String>) -> Self {
        Self {
            client: Client::new(),
            token,
        }
    }
    
    /// Get repository information
    pub async fn get_repo(&self, owner: &str, repo: &str) -> Result<Repository, String> {
        let url = format!("https://api.github.com/repos/{}/{}", owner, repo);
        
        let request = self.client.get(&url);
        let request = self.add_headers(request);
        
        let response = request.send().await.map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            response.json().await.map_err(|e| e.to_string())
        } else {
            Err(format!("Failed to get repo: {}", response.status()))
        }
    }
    
    /// Get workflow files from a repository
    pub async fn get_workflows(&self, owner: &str, repo: &str) -> Result<Vec<Workflow>, String> {
        let url = format!(
            "https://api.github.com/repos/{}/{}/actions/workflows",
            owner, repo
        );
        
        let request = self.client.get(&url);
        let request = self.add_headers(request);
        
        let response = request.send().await.map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            #[derive(Deserialize)]
            struct WorkflowsResponse {
                workflows: Vec<Workflow>,
            }
            let result: WorkflowsResponse = response.json().await.map_err(|e| e.to_string())?;
            Ok(result.workflows)
        } else {
            Err(format!("Failed to get workflows: {}", response.status()))
        }
    }
    
    /// Get workflow file content
    pub async fn get_workflow_content(&self, owner: &str, repo: &str, _path: &str) -> Result<String, String> {
        let url = format!(
            "https://api.github.com/repos/{}/contents/{}",
            owner, repo
        );
        
        let request = self.client.get(&url);
        let request = self.add_headers(request);
        
        let response = request.send().await.map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            let content: Content = response.json().await.map_err(|e| e.to_string())?;
            
            if let Some(encoded) = content.content {
                // Decode base64
                let decoded = base64_decode(&encoded);
                Ok(decoded)
            } else {
                Err("No content found".to_string())
            }
        } else {
            Err(format!("Failed to get content: {}", response.status()))
        }
    }
    
    /// Get all repositories in an organization
    pub async fn get_org_repos(&self, org: &str, page: u32, per_page: u32) -> Result<Vec<Repository>, String> {
        let url = format!(
            "https://api.github.com/orgs/{}/repos?page={}&per_page={}",
            org, page, per_page
        );
        
        let request = self.client.get(&url);
        let request = self.add_headers(request);
        
        let response = request.send().await.map_err(|e| e.to_string())?;
        
        if response.status().is_success() {
            response.json().await.map_err(|e| e.to_string())
        } else {
            Err(format!("Failed to get org repos: {}", response.status()))
        }
    }
    
    /// Add authentication and user-agent headers
    fn add_headers(&self, mut request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request = request.header("User-Agent", "OmniClaw-Scanner");
        
        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        request
    }
}

/// Simple base64 decoder
fn base64_decode(input: &str) -> String {
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
    
    String::from_utf8(output).unwrap_or_default()
}

