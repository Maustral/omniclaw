//! SBOM (Software Bill of Materials) Module for OmniClaw
//! 
//! Generates and analyzes SBOM for dependency vulnerability detection

use crate::core::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Package ecosystem types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Npm,
    Pip,
    Maven,
    Gradle,
    Go,
    Cargo,
    NuGet,
    RubyGems,
    Composer,
    Unknown,
}

impl Ecosystem {
    pub fn from_string(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "npm" | "node" => Ecosystem::Npm,
            "pip" | "pypi" | "python" => Ecosystem::Pip,
            "maven" | "m2" => Ecosystem::Maven,
            "gradle" => Ecosystem::Gradle,
            "go" | "golang" => Ecosystem::Go,
            "cargo" | "rust" => Ecosystem::Cargo,
            "nuget" | "dotnet" => Ecosystem::NuGet,
            "rubygems" | "ruby" => Ecosystem::RubyGems,
            "composer" | "php" => Ecosystem::Composer,
            _ => Ecosystem::Unknown,
        }
    }
    
    pub fn name(&self) -> &str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pip => "pip",
            Ecosystem::Maven => "Maven",
            Ecosystem::Gradle => "Gradle",
            Ecosystem::Go => "Go",
            Ecosystem::Cargo => "Cargo",
            Ecosystem::NuGet => "NuGet",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::Composer => "Composer",
            Ecosystem::Unknown => "Unknown",
        }
    }
}

/// Package information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub license: Option<String>,
    pub source_url: Option<String>,
    pub dependencies: Vec<String>,
}

/// SBOM document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    pub format: String,
    pub version: String,
    pub generator: String,
    pub timestamp: String,
    pub packages: Vec<Package>,
    pub dependencies: HashMap<String, Vec<String>>,
}

/// Vulnerability information from SBOM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub package_name: String,
    pub affected_versions: String,
    pub severity: Severity,
    pub description: String,
    pub cve_id: Option<String>,
    pub remediation: String,
}

/// SBOM Scanner
pub struct SbomScanner {
    pub include_dev_deps: bool,
    pub check_licenses: bool,
}

impl Default for SbomScanner {
    fn default() -> Self {
        Self {
            include_dev_deps: false,
            check_licenses: true,
        }
    }
}

impl SbomScanner {
    /// Parse package.json (npm/Node.js)
    pub fn parse_package_json(&self, content: &str) -> Result<Sbom, String> {
        #[derive(Deserialize)]
        struct PackageJson {
            name: Option<String>,
            version: Option<String>,
            license: Option<serde_json::Value>,
            dependencies: Option<HashMap<String, String>>,
            #[serde(rename = "devDependencies")]
            dev_dependencies: Option<HashMap<String, String>>,
        }
        
        let pkg: PackageJson = serde_json::from_str(content)
            .map_err(|e| format!("Failed to parse package.json: {}", e))?;
        
        let mut packages = Vec::new();
        
        // Main dependencies
        if let Some(deps) = &pkg.dependencies {
            for (name, version) in deps {
                packages.push(Package {
                    name: name.clone(),
                    version: version.trim_start_matches('^').trim_start_matches('~').to_string(),
                    ecosystem: Ecosystem::Npm,
                    license: None,
                    source_url: None,
                    dependencies: vec![],
                });
            }
        }
        
        // Dev dependencies (if enabled)
        if self.include_dev_deps {
            if let Some(deps) = &pkg.dev_dependencies {
                for (name, version) in deps {
                    packages.push(Package {
                        name: name.clone(),
                        version: version.trim_start_matches('^').trim_start_matches('~').to_string(),
                        ecosystem: Ecosystem::Npm,
                        license: None,
                        source_url: None,
                        dependencies: vec![],
                    });
                }
            }
        }
        
        let timestamp = chrono::Utc::now().to_rfc3339();
        
        Ok(Sbom {
            format: "OmniClaw-SBOM".to_string(),
            version: "1.0".to_string(),
            generator: "OmniClaw SBOM Scanner".to_string(),
            timestamp,
            packages,
            dependencies: HashMap::new(),
        })
    }
    
    /// Parse requirements.txt (Python/pip)
    pub fn parse_requirements_txt(&self, content: &str) -> Result<Sbom, String> {
        let mut packages = Vec::new();
        
        for line in content.lines() {
            let line = line.trim();
            
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }
            
            // Parse package==version or package>=version
            let (name, version) = if let Some(pos) = line.find("==") {
                (line[..pos].trim().to_string(), line[pos + 2..].trim().to_string())
            } else if let Some(pos) = line.find(">=") {
                (line[..pos].trim().to_string(), format!(">={}", line[pos + 2..].trim()))
            } else if let Some(pos) = line.find("~=") {
                (line[..pos].trim().to_string(), format!("~={}", line[pos + 2..].trim()))
            } else {
                (line.to_string(), "latest".to_string())
            };
            
            packages.push(Package {
                name,
                version,
                ecosystem: Ecosystem::Pip,
                license: None,
                source_url: None,
                dependencies: vec![],
            });
        }
        
        let timestamp = chrono::Utc::now().to_rfc3339();
        
        Ok(Sbom {
            format: "OmniClaw-SBOM".to_string(),
            version: "1.0".to_string(),
            generator: "OmniClaw SBOM Scanner".to_string(),
            timestamp,
            packages,
            dependencies: HashMap::new(),
        })
    }
    
    /// Parse Cargo.toml (Rust)
    pub fn parse_cargo_toml(&self, content: &str) -> Result<Sbom, String> {
        #[derive(Deserialize)]
        struct CargoToml {
            package: Option<PackageInfo>,
            dependencies: Option<HashMap<String, toml::Value>>,
            #[serde(rename = "dev-dependencies")]
            dev_dependencies: Option<HashMap<String, toml::Value>>,
        }
        
        #[derive(Deserialize)]
        struct PackageInfo {
            name: Option<String>,
            version: Option<String>,
        }
        
        let cargo: CargoToml = toml::from_str(content)
            .map_err(|e| format!("Failed to parse Cargo.toml: {}", e))?;
        
        let mut packages = Vec::new();
        
        // Dependencies
        if let Some(deps) = &cargo.dependencies {
            for (name, value) in deps {
                let version = match value {
                    toml::Value::String(s) => s.clone(),
                    toml::Value::Table(t) => {
                        t.get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("*")
                            .to_string()
                    }
                    _ => "*".to_string(),
                };
                
                packages.push(Package {
                    name: name.clone(),
                    version,
                    ecosystem: Ecosystem::Cargo,
                    license: None,
                    source_url: None,
                    dependencies: vec![],
                });
            }
        }
        
        // Dev dependencies (if enabled)
        if self.include_dev_deps {
            if let Some(deps) = &cargo.dev_dependencies {
                for (name, value) in deps {
                    let version = match value {
                        toml::Value::String(s) => s.clone(),
                        toml::Value::Table(t) => {
                            t.get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("*")
                                .to_string()
                        }
                        _ => "*".to_string(),
                    };
                    
                    packages.push(Package {
                        name: name.clone(),
                        version,
                        ecosystem: Ecosystem::Cargo,
                        license: None,
                        source_url: None,
                        dependencies: vec![],
                    });
                }
            }
        }
        
        let timestamp = chrono::Utc::now().to_rfc3339();
        
        Ok(Sbom {
            format: "OmniClaw-SBOM".to_string(),
            version: "1.0".to_string(),
            generator: "OmniClaw SBOM Scanner".to_string(),
            timestamp,
            packages,
            dependencies: HashMap::new(),
        })
    }
    
    /// Parse go.mod (Go)
    pub fn parse_go_mod(&self, content: &str) -> Result<Sbom, String> {
        let mut packages = Vec::new();
        let mut in_require_block = false;
        
        for line in content.lines() {
            let line = line.trim();
            
            if line.starts_with("require (") {
                in_require_block = true;
                continue;
            }
            
            if line == ")" && in_require_block {
                in_require_block = false;
                continue;
            }
            
            if in_require_block || (!line.starts_with("module") && !line.starts_with("go ")) {
                if !line.is_empty() && !line.starts_with("//") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let name = parts[0].to_string();
                        let version = parts[1].trim_start_matches('v').to_string();
                        
                        packages.push(Package {
                            name,
                            version,
                            ecosystem: Ecosystem::Go,
                            license: None,
                            source_url: None,
                            dependencies: vec![],
                        });
                    }
                }
            }
        }
        
        let timestamp = chrono::Utc::now().to_rfc3339();
        
        Ok(Sbom {
            format: "OmniClaw-SBOM".to_string(),
            version: "1.0".to_string(),
            generator: "OmniClaw SBOM Scanner".to_string(),
            timestamp,
            packages,
            dependencies: HashMap::new(),
        })
    }
    
    /// Detect ecosystem from file
    pub fn detect_ecosystem(path: &Path) -> Ecosystem {
        let file_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        match file_name {
            "package.json" => Ecosystem::Npm,
            "requirements.txt" | "Pipfile" | "pyproject.toml" => Ecosystem::Pip,
            "Cargo.toml" => Ecosystem::Cargo,
            "go.mod" => Ecosystem::Go,
            "pom.xml" => Ecosystem::Maven,
            "build.gradle" | "build.gradle.kts" => Ecosystem::Gradle,
            "*.csproj" | "packages.config" => Ecosystem::NuGet,
            "Gemfile" => Ecosystem::RubyGems,
            "composer.json" => Ecosystem::Composer,
            _ => Ecosystem::Unknown,
        }
    }
    
    /// Parse SBOM from file
    pub fn parse_file(&self, path: &Path, content: &str) -> Result<Sbom, String> {
        let ecosystem = Self::detect_ecosystem(path);
        
        match ecosystem {
            Ecosystem::Npm => self.parse_package_json(content),
            Ecosystem::Pip => self.parse_requirements_txt(content),
            Ecosystem::Cargo => self.parse_cargo_toml(content),
            Ecosystem::Go => self.parse_go_mod(content),
            _ => Err(format!("Unsupported ecosystem for file: {}", path.display())),
        }
    }
    
    /// Export SBOM as JSON
    pub fn to_json(&self, sbom: &Sbom) -> Result<String, String> {
        serde_json::to_string_pretty(sbom)
            .map_err(|e| format!("Failed to serialize SBOM: {}", e))
    }
    
    /// Export SBOM as SPDX format (simplified)
    pub fn to_spdx(&self, sbom: &Sbom) -> String {
        let mut output = String::new();
        output.push_str("SPDXVersion: SPDX-2.2\n");
        output.push_str(&format!("DataLicense: CC0-1.0\n"));
        output.push_str("SPDXID: SPDXRef-DOCUMENT\n");
        output.push_str(&format!("DocumentName: {}\n", sbom.generator));
        output.push_str(&format!("DocumentNamespace: https://omniclaw.dev/sbom/{}\n", sbom.timestamp));
        output.push_str("\n");
        
        output.push_str("# Package Information\n");
        for (i, pkg) in sbom.packages.iter().enumerate() {
            output.push_str(&format!("PackageName: {}\n", pkg.name));
            output.push_str(&format!("SPDXID: SPDXRef-Package-{}\n", i + 1));
            output.push_str(&format!("PackageVersion: {}\n", pkg.version));
            output.push_str(&format!("PackageDownloadLocation: NOASSERTION\n"));
            output.push_str(&format!("FilesAnalyzed: false\n"));
            output.push_str("\n");
        }
        
        output
    }
    
    /// Generate findings from SBOM
    pub fn check_vulnerabilities(&self, sbom: &Sbom) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Known vulnerable packages (simplified example)
        let known_vulnerabilities = vec![
            ("lodash", "4.17.21", "CVE-2021-23337", Severity::High),
            ("moment", "2.29.2", "CVE-2022-24785", Severity::Medium),
            ("axios", "0.21.0", "CVE-2021-3749", Severity::High),
            ("express", "4.16.0", "CVE-2022-24999", Severity::High),
            ("jsonwebtoken", "8.5.0", "CVE-2022-23529", Severity::Critical),
            ("minimist", "1.2.5", "CVE-2021-44906", Severity::Critical),
            ("node-forge", "0.10.0", "CVE-2021-23369", Severity::High),
            ("tar", "6.0.0", "CVE-2021-37701", Severity::Critical),
        ];
        
        for pkg in &sbom.packages {
            for (vuln_name, vuln_version, cve_id, severity) in &known_vulnerabilities {
                if pkg.name == *vuln_name && pkg.version.starts_with(vuln_version) {
                    findings.push(Finding::new(
                        format!("SBOM-{}", cve_id.replace("-", "")),
                        format!("Vulnerable dependency: {}", pkg.name),
                        *severity,
                    )
                    .with_description(format!(
                        "Package {} version {} has known vulnerability {}",
                        pkg.name, pkg.version, cve_id
                    ))
                    .with_remediation(format!(
                        "Upgrade {} to the latest version. Run: cargo update {}",
                        pkg.name, pkg.name
                    ))
                    .with_source("sbom_scanner"));
                }
            }
        }
        
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_package_json() {
        let scanner = SbomScanner::default();
        let content = r#"{
            "name": "test-project",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "4.17.21"
            }
        }"#;
        
        let sbom = scanner.parse_package_json(content).unwrap();
        assert_eq!(sbom.packages.len(), 2);
    }
    
    #[test]
    fn test_parse_requirements_txt() {
        let scanner = SbomScanner::default();
        let content = r#"
# Comments are ignored
requests==2.28.0
flask>=2.0.0
django~=4.0
        "#;
        
        let sbom = scanner.parse_requirements_txt(content).unwrap();
        assert_eq!(sbom.packages.len(), 3);
    }
    
    #[test]
    fn test_detect_ecosystem() {
        assert_eq!(SbomScanner::detect_ecosystem(Path::new("package.json")), Ecosystem::Npm);
        assert_eq!(SbomScanner::detect_ecosystem(Path::new("requirements.txt")), Ecosystem::Pip);
        assert_eq!(SbomScanner::detect_ecosystem(Path::new("Cargo.toml")), Ecosystem::Cargo);
        assert_eq!(SbomScanner::detect_ecosystem(Path::new("go.mod")), Ecosystem::Go);
    }
}

