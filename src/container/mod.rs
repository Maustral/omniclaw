//! Container Security Module for OmniClaw
//! 
//! Analyzes Dockerfiles and Kubernetes manifests for security issues

use crate::core::{Finding, Severity};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Container security issue type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContainerIssue {
    // Dockerfile issues
    LatestTag,
    MissingUser,
    RootUser,
    ExposedSensitivePort,
    SensitiveDataInImage,
    MissingHealthCheck,
    InsecureBaseImage,
    MultipleCommands,
    InsecurePackageManager,
    SudoUsage,
    CredentialInEnvironment,
    SecretMounted,
    PrivilegedContainer,
    DangerousCapabilities,
    InsecureNetworking,
    MissingResourceLimits,
    HostNetworkMode,
    HostPidMode,
    InsecureRegistry,
    OutdatedPackages,
    
    // Kubernetes issues
    PrivilegedPod,
    HostPathVolume,
    SecretAsEnvVar,
    DefaultNamespace,
    MissingNetworkPolicy,
    MissingPodSecurityPolicy,
    ContainerRunningAsRoot,
    UnsafeSysctls,
    HostPort,
    ServiceTypeLoadBalancer,
    ClusterRoleBinding,
}

impl ContainerIssue {
    pub fn id(&self) -> String {
        match self {
            ContainerIssue::LatestTag => "CON-001".to_string(),
            ContainerIssue::MissingUser => "CON-002".to_string(),
            ContainerIssue::RootUser => "CON-003".to_string(),
            ContainerIssue::ExposedSensitivePort => "CON-004".to_string(),
            ContainerIssue::SensitiveDataInImage => "CON-005".to_string(),
            ContainerIssue::MissingHealthCheck => "CON-006".to_string(),
            ContainerIssue::InsecureBaseImage => "CON-007".to_string(),
            ContainerIssue::MultipleCommands => "CON-008".to_string(),
            ContainerIssue::InsecurePackageManager => "CON-009".to_string(),
            ContainerIssue::SudoUsage => "CON-010".to_string(),
            ContainerIssue::CredentialInEnvironment => "CON-011".to_string(),
            ContainerIssue::SecretMounted => "CON-012".to_string(),
            ContainerIssue::PrivilegedContainer => "CON-013".to_string(),
            ContainerIssue::DangerousCapabilities => "CON-014".to_string(),
            ContainerIssue::InsecureNetworking => "CON-015".to_string(),
            ContainerIssue::MissingResourceLimits => "CON-016".to_string(),
            ContainerIssue::HostNetworkMode => "CON-017".to_string(),
            ContainerIssue::HostPidMode => "CON-018".to_string(),
            ContainerIssue::InsecureRegistry => "CON-019".to_string(),
            ContainerIssue::OutdatedPackages => "CON-020".to_string(),
            
            // Kubernetes
            ContainerIssue::PrivilegedPod => "K8S-001".to_string(),
            ContainerIssue::HostPathVolume => "K8S-002".to_string(),
            ContainerIssue::SecretAsEnvVar => "K8S-003".to_string(),
            ContainerIssue::DefaultNamespace => "K8S-004".to_string(),
            ContainerIssue::MissingNetworkPolicy => "K8S-005".to_string(),
            ContainerIssue::MissingPodSecurityPolicy => "K8S-006".to_string(),
            ContainerIssue::ContainerRunningAsRoot => "K8S-007".to_string(),
            ContainerIssue::UnsafeSysctls => "K8S-008".to_string(),
            ContainerIssue::HostPort => "K8S-009".to_string(),
            ContainerIssue::ServiceTypeLoadBalancer => "K8S-010".to_string(),
            ContainerIssue::ClusterRoleBinding => "K8S-011".to_string(),
        }
    }
    
    pub fn severity(&self) -> Severity {
        match self {
            ContainerIssue::PrivilegedContainer 
            | ContainerIssue::PrivilegedPod
            | ContainerIssue::RootUser
            | ContainerIssue::ContainerRunningAsRoot
            | ContainerIssue::DangerousCapabilities
            | ContainerIssue::SensitiveDataInImage
            | ContainerIssue::SecretAsEnvVar
            | ContainerIssue::ClusterRoleBinding => Severity::Critical,
            
            ContainerIssue::LatestTag
            | ContainerIssue::ExposedSensitivePort
            | ContainerIssue::HostNetworkMode
            | ContainerIssue::HostPidMode
            | ContainerIssue::HostPathVolume
            | ContainerIssue::HostPort => Severity::High,
            
            ContainerIssue::MissingUser
            | ContainerIssue::MissingHealthCheck
            | ContainerIssue::InsecureBaseImage
            | ContainerIssue::InsecureNetworking
            | ContainerIssue::MissingResourceLimits
            | ContainerIssue::MissingNetworkPolicy
            | ContainerIssue::MissingPodSecurityPolicy
            | ContainerIssue::InsecureRegistry
            | ContainerIssue::OutdatedPackages
            | ContainerIssue::DefaultNamespace
            | ContainerIssue::UnsafeSysctls => Severity::Medium,
            
            _ => Severity::Low,
        }
    }
    
    pub fn name(&self) -> String {
        match self {
            ContainerIssue::LatestTag => "Latest Tag Used".to_string(),
            ContainerIssue::MissingUser => "Missing USER Directive".to_string(),
            ContainerIssue::RootUser => "Running as Root User".to_string(),
            ContainerIssue::ExposedSensitivePort => "Sensitive Port Exposed".to_string(),
            ContainerIssue::SensitiveDataInImage => "Sensitive Data in Image".to_string(),
            ContainerIssue::MissingHealthCheck => "Missing HEALTHCHECK".to_string(),
            ContainerIssue::InsecureBaseImage => "Insecure Base Image".to_string(),
            ContainerIssue::MultipleCommands => "Multiple RUN Commands".to_string(),
            ContainerIssue::InsecurePackageManager => "Insecure Package Manager".to_string(),
            ContainerIssue::SudoUsage => "SUDO Usage Detected".to_string(),
            ContainerIssue::CredentialInEnvironment => "Credentials in Environment".to_string(),
            ContainerIssue::SecretMounted => "Secret Mounted without Protection".to_string(),
            ContainerIssue::PrivilegedContainer => "Privileged Container".to_string(),
            ContainerIssue::DangerousCapabilities => "Dangerous Capabilities".to_string(),
            ContainerIssue::InsecureNetworking => "Insecure Networking Config".to_string(),
            ContainerIssue::MissingResourceLimits => "Missing Resource Limits".to_string(),
            ContainerIssue::HostNetworkMode => "Host Network Mode".to_string(),
            ContainerIssue::HostPidMode => "Host PID Mode".to_string(),
            ContainerIssue::InsecureRegistry => "Insecure Registry".to_string(),
            ContainerIssue::OutdatedPackages => "Outdated System Packages".to_string(),
            
            ContainerIssue::PrivilegedPod => "Privileged Pod".to_string(),
            ContainerIssue::HostPathVolume => "HostPath Volume Mount".to_string(),
            ContainerIssue::SecretAsEnvVar => "Secrets as Environment Variables".to_string(),
            ContainerIssue::DefaultNamespace => "Using Default Namespace".to_string(),
            ContainerIssue::MissingNetworkPolicy => "Missing Network Policy".to_string(),
            ContainerIssue::MissingPodSecurityPolicy => "Missing Pod Security Policy".to_string(),
            ContainerIssue::ContainerRunningAsRoot => "Container Running as Root".to_string(),
            ContainerIssue::UnsafeSysctls => "Unsafe Sysctls".to_string(),
            ContainerIssue::HostPort => "Host Port Binding".to_string(),
            ContainerIssue::ServiceTypeLoadBalancer => "LoadBalancer Service Type".to_string(),
            ContainerIssue::ClusterRoleBinding => "ClusterRole Binding Detected".to_string(),
        }
    }
    
    pub fn remediation(&self) -> String {
        match self {
            ContainerIssue::LatestTag => "Use specific version tags instead of 'latest'. Example: FROM node:18-alpine".to_string(),
            ContainerIssue::MissingUser => "Add a USER directive to run as non-root. Example: USER appuser".to_string(),
            ContainerIssue::RootUser => "Create and use a non-root user. Example: USER 1000:1000".to_string(),
            ContainerIssue::ExposedSensitivePort => "Avoid exposing sensitive ports (e.g., 22, 3389, 27017) to untrusted networks".to_string(),
            ContainerIssue::SensitiveDataInImage => "Never bake credentials into images. Use secrets or environment variables at runtime".to_string(),
            ContainerIssue::MissingHealthCheck => "Add HEALTHCHECK directive: HEALTHCHECK CMD curl --fail http://localhost/".to_string(),
            ContainerIssue::InsecureBaseImage => "Use official, minimal base images from trusted registries".to_string(),
            ContainerIssue::MultipleCommands => "Combine multiple RUN commands to reduce layers and attack surface".to_string(),
            ContainerIssue::InsecurePackageManager => "Use HTTPS for package downloads and verify checksums".to_string(),
            ContainerIssue::SudoUsage => "Avoid using SUDO. Configure proper permissions instead".to_string(),
            ContainerIssue::CredentialInEnvironment => "Use Docker secrets or external secret management instead of ENV".to_string(),
            ContainerIssue::SecretMounted => "Use Kubernetes secrets with proper access controls".to_string(),
            ContainerIssue::PrivilegedContainer => "Remove privileged: true from container security context".to_string(),
            ContainerIssue::DangerousCapabilities => "Drop all capabilities and add only required ones: securityContext: { capabilities: { drop: ['ALL'] } }".to_string(),
            ContainerIssue::InsecureNetworking => "Use container networking and avoid host networking".to_string(),
            ContainerIssue::MissingResourceLimits => "Add resource limits: resources: { limits: { cpu: '500m', memory: '256Mi' } }".to_string(),
            ContainerIssue::HostNetworkMode => "Use container network namespace: networkMode: service:container".to_string(),
            ContainerIssue::HostPidMode => "Use container PID namespace: pidMode: private".to_string(),
            ContainerIssue::InsecureRegistry => "Use trusted registries with HTTPS and image signing".to_string(),
            ContainerIssue::OutdatedPackages => "Regularly update base images and install security patches".to_string(),
            
            // Kubernetes
            ContainerIssue::PrivilegedPod => "Set privileged: false in security context".to_string(),
            ContainerIssue::HostPathVolume => "Use emptyDir volumes or persistentVolumeClaims instead of hostPath".to_string(),
            ContainerIssue::SecretAsEnvVar => "Mount secrets as volumes, not environment variables".to_string(),
            ContainerIssue::DefaultNamespace => "Use dedicated namespaces for applications".to_string(),
            ContainerIssue::MissingNetworkPolicy => "Define NetworkPolicy to restrict pod communication".to_string(),
            ContainerIssue::MissingPodSecurityPolicy => "Apply PodSecurityPolicy or use built-in policies".to_string(),
            ContainerIssue::ContainerRunningAsRoot => "Run containers as non-root: runAsNonRoot: true, runAsUser: 1000".to_string(),
            ContainerIssue::UnsafeSysctls => "Avoid unsafe sysctls or restrict them to namespaces".to_string(),
            ContainerIssue::HostPort => "Use Service or Ingress instead of hostPort".to_string(),
            ContainerIssue::ServiceTypeLoadBalancer => "Use ClusterIP with Ingress or VPN for internal services".to_string(),
            ContainerIssue::ClusterRoleBinding => "Use Role and RoleBinding for namespace-scoped permissions".to_string(),
        }
    }
}

/// Container security scanner
pub struct ContainerScanner {
    pub check_dockerfile: bool,
    pub check_kubernetes: bool,
}

impl Default for ContainerScanner {
    fn default() -> Self {
        Self {
            check_dockerfile: true,
            check_kubernetes: true,
        }
    }
}

lazy_static! {
    // Pattern to detect 'latest' tag
    pub static ref LATEST_TAG: Regex = Regex::new(r":latest$|:latest\s").unwrap();
    
    // Pattern to detect sensitive ports
    pub static ref SENSITIVE_PORTS: Regex = Regex::new(
        r"(?:EXPOSE|--expose)\s+(?:22|23|25|3306|3389|5432|6379|27017|9200|11211)"
    ).unwrap();
    
    // Pattern to detect credentials in environment
    pub static ref CREDENTIAL_PATTERN: Regex = Regex::new(
        r#"(?i)(?:password|passwd|secret|token|api_key|apikey|auth|credential)\s*=\s*['"]?\w+"#
    ).unwrap();
    
    // Pattern to detect root user
    pub static ref ROOT_USER: Regex = Regex::new(r#"(?i)(?:USER\s+root|UID\s*=\s*0)"#).unwrap();
    
    // Pattern to detect sudo
    pub static ref SUDO_USAGE: Regex = Regex::new(r#"(?i)\bsudo\b"#).unwrap();
    
    // Pattern to detect privileged mode
    pub static ref PRIVILEGED_MODE: Regex = Regex::new(r#"(?i)(privileged:\s*true|privileged\s+mode)"#).unwrap();
    
    // Pattern to detect host network
    pub static ref HOST_NETWORK: Regex = Regex::new(r#"(?i)(networkMode:\s*host|hostNetwork:\s*true)"#).unwrap();
    
    // Pattern to detect host PID
    pub static ref HOST_PID: Regex = Regex::new(r#"(?i)(pidMode:\s*host|hostPID:\s*true)"#).unwrap();
    
    // Dangerous capabilities
    pub static ref DANGEROUS_CAPS: Regex = Regex::new(
        r#"(?i)(capabilities:\s*\{[^}]*add:\s*\[.*(?:SYS_ADMIN|SYS_MODULE|SYS_RAWIO|SYS_PTRACE|NET_ADMIN|ALL)"#
    ).unwrap();
    
    // hostPath volume
    pub static ref HOST_PATH: Regex = Regex::new(r#"(?i)hostPath:\s*path:"#).unwrap();
}

impl ContainerScanner {
    /// Scan Dockerfile content
    pub fn scan_dockerfile(&self, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        for (line_num, line) in lines.iter().enumerate() {
            let line_num = (line_num + 1) as u32;
            let line_trimmed = line.trim();
            
            // Check for latest tag
            if LATEST_TAG.is_match(line_trimmed) {
                findings.push(create_finding(
                    ContainerIssue::LatestTag,
                    Some(line_num),
                    None,
                    line_trimmed,
                ));
            }
            
            // Check for exposed sensitive ports
            if SENSITIVE_PORTS.is_match(line_trimmed) {
                findings.push(create_finding(
                    ContainerIssue::ExposedSensitivePort,
                    Some(line_num),
                    None,
                    line_trimmed,
                ));
            }
            
            // Check for credentials in ENV
            if CREDENTIAL_PATTERN.is_match(line_trimmed) && line_trimmed.starts_with("ENV") {
                findings.push(create_finding(
                    ContainerIssue::CredentialInEnvironment,
                    Some(line_num),
                    None,
                    line_trimmed,
                ));
            }
            
            // Check for root user
            if ROOT_USER.is_match(line_trimmed) {
                findings.push(create_finding(
                    ContainerIssue::RootUser,
                    Some(line_num),
                    None,
                    line_trimmed,
                ));
            }
            
            // Check for sudo
            if SUDO_USAGE.is_match(line_trimmed) {
                findings.push(create_finding(
                    ContainerIssue::SudoUsage,
                    Some(line_num),
                    None,
                    line_trimmed,
                ));
            }
            
            // Check for missing USER directive (at end of file)
            if line_trimmed.starts_with("FROM") && !content.contains("USER ") {
                findings.push(create_finding(
                    ContainerIssue::MissingUser,
                    Some(line_num),
                    None,
                    "No USER directive found in Dockerfile",
                ));
            }
        }
        
        // Check for missing HEALTHCHECK
        if !content.contains("HEALTHCHECK") {
            findings.push(create_finding(
                ContainerIssue::MissingHealthCheck,
                None,
                None,
                "No HEALTHCHECK directive found",
            ));
        }
        
        // Check for insecure base image
        if content.contains("FROM ubuntu") || content.contains("FROM debian") {
            findings.push(create_finding(
                ContainerIssue::InsecureBaseImage,
                None,
                None,
                "Using generic base image",
            ));
        }
        
        // Check for multiple RUN commands (layer optimization)
        let run_count = content.lines().filter(|l| l.trim().starts_with("RUN")).count();
        if run_count > 5 {
            findings.push(create_finding(
                ContainerIssue::MultipleCommands,
                None,
                None,
                "Multiple RUN commands detected",
            ));
        }
        
        findings
    }
    
    /// Scan Kubernetes manifest
    pub fn scan_kubernetes(&self, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        for (line_num, line) in lines.iter().enumerate() {
            let line_num = (line_num + 1) as u32;
            let line_trimmed = line.trim();
            
            // Check for privileged container
            if PRIVILEGED_MODE.is_match(line_trimmed) {
                findings.push(create_finding(
                    ContainerIssue::PrivilegedContainer,
                    Some(line_num),
                    None,
                    line_trimmed,
                ));
            }
            
            // Check for host network
            if HOST_NETWORK.is_match(line_trimmed) {
                findings.push(create_finding(
                    ContainerIssue::HostNetworkMode,
                    Some(line_num),
                    None,
                    line_trimmed,
                ));
            }
            
            // Check for host PID
            if HOST_PID.is_match(line_trimmed) {
                findings.push(create_finding(
                    ContainerIssue::HostPidMode,
                    Some(line_num),
                    None,
                    line_trimmed,
                ));
            }
            
            // Check for dangerous capabilities
            if DANGEROUS_CAPS.is_match(line_trimmed) {
                findings.push(create_finding(
                    ContainerIssue::DangerousCapabilities,
                    Some(line_num),
                    None,
                    line_trimmed,
                ));
            }
            
            // Check for hostPath volume
            if HOST_PATH.is_match(line_trimmed) {
                findings.push(create_finding(
                    ContainerIssue::HostPathVolume,
                    Some(line_num),
                    None,
                    line_trimmed,
                ));
            }
            
            // Check for secrets as env vars
            if line_trimmed.contains("env:") || line_trimmed.contains("envFrom:") {
                if line_trimmed.contains("secretKeyRef") {
                    findings.push(create_finding(
                        ContainerIssue::SecretAsEnvVar,
                        Some(line_num),
                        None,
                        line_trimmed,
                    ));
                }
            }
            
            // Check for host port
            if line_trimmed.contains("hostPort:") {
                findings.push(create_finding(
                    ContainerIssue::HostPort,
                    Some(line_num),
                    None,
                    line_trimmed,
                ));
            }
            
            // Check for LoadBalancer service
            if line_trimmed.contains("type:") && line_trimmed.contains("LoadBalancer") {
                findings.push(create_finding(
                    ContainerIssue::ServiceTypeLoadBalancer,
                    Some(line_num),
                    None,
                    line_trimmed,
                ));
            }
            
            // Check for ClusterRoleBinding
            if line_trimmed.contains("kind:") && line_trimmed.contains("ClusterRoleBinding") {
                findings.push(create_finding(
                    ContainerIssue::ClusterRoleBinding,
                    Some(line_num),
                    None,
                    line_trimmed,
                ));
            }
        }
        
        // Check for default namespace
        if content.contains("namespace: default") || (!content.contains("namespace:") && content.contains("kind:")) {
            findings.push(create_finding(
                ContainerIssue::DefaultNamespace,
                None,
                None,
                "Using default namespace",
            ));
        }
        
        // Check for missing resource limits
        if content.contains("kind:") && content.contains("container") && !content.contains("resources:") {
            findings.push(create_finding(
                ContainerIssue::MissingResourceLimits,
                None,
                None,
                "No resource limits defined",
            ));
        }
        
        // Check for running as root
        if content.contains("runAsNonRoot:") && content.contains("runAsUser: 0") {
            findings.push(create_finding(
                ContainerIssue::ContainerRunningAsRoot,
                None,
                None,
                "Container configured to run as root",
            ));
        }
        
        findings
    }
    
    /// Auto-detect and scan container files
    pub fn scan_file(&self, path: &Path, content: &str) -> Vec<Finding> {
        let file_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        if file_name.to_lowercase().contains("dockerfile") || file_name == "Dockerfile" {
            self.scan_dockerfile(content)
        } else if file_name.ends_with(".yaml") || file_name.ends_with(".yml") {
            // Could be Kubernetes manifest
            if content.contains("kind:") {
                self.scan_kubernetes(content)
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    }
}

fn create_finding(
    issue: ContainerIssue,
    line: Option<u32>,
    column: Option<usize>,
    evidence: &str,
) -> Finding {
    Finding::new(
        issue.id(),
        issue.name(),
        issue.severity(),
    )
    .with_line(line.unwrap_or(0))
    .with_evidence(evidence.to_string())
    .with_description(format!("{}", issue.name()))
    .with_remediation(issue.remediation())
    .with_source("container_scanner")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    
    #[test]
    fn test_dockerfile_latest_tag() {
        let scanner = ContainerScanner::default();
        let dockerfile = r#"FROM node:latest
RUN npm install
        "#;
        
        let findings = scanner.scan_dockerfile(dockerfile);
        assert!(findings.iter().any(|f| f.id == "CON-001"));
    }
    
    #[test]
    fn test_dockerfile_credentials() {
        let scanner = ContainerScanner::default();
        let dockerfile = r#"FROM node:18
ENV API_KEY=secret123
        "#;
        
        let findings = scanner.scan_dockerfile(dockerfile);
        assert!(findings.iter().any(|f| f.id == "CON-011"));
    }
    
    #[test]
    fn test_kubernetes_privileged() {
        let scanner = ContainerScanner::default();
        let manifest = r#"kind: Pod
spec:
  containers:
  - name: test
    securityContext:
      privileged: true
        "#;
        
        let findings = scanner.scan_kubernetes(manifest);
        assert!(findings.iter().any(|f| f.id == "CON-013"));
    }
    
    #[test]
    fn test_kubernetes_hostpath() {
        let scanner = ContainerScanner::default();
        let manifest = r#"kind: Pod
spec:
  volumes:
  - name: data
    hostPath:
      path: /var/data
        "#;
        
        let findings = scanner.scan_kubernetes(manifest);
        assert!(findings.iter().any(|f| f.id == "K8S-002"));
    }
}

