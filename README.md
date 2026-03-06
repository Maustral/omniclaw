# OmniClaw 🦷⚡

<p align="center">
  <img src="assets/logos/logo.svg" alt="OmniClaw - Unified CI/CD Security Scanner" width="400" />
</p>

<p align="center">
  <img src="assets/logos/omniclaw_logo.svg" alt="OmniClaw Banner" width="600" />
</p>

**Unified CI/CD Security Scanner** — Comprehensive security analysis for CI/CD pipelines.

[![GitHub Stars](https://img.shields.io/github/stars/Maustral/omniclaw?style=social)](https://github.com/Maustral/omniclaw/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/Maustral/omniclaw?style=social)](https://github.com/Maustral/omniclaw/network)
[![License](https://img.shields.io/github/license/Maustral/omniclaw)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![Build](https://img.shields.io/github/actions/workflow/status/Maustral/omniclaw/ci.yml)](https://github.com/Maustral/omniclaw/actions)

---

## Features

### 🔍 Comprehensive Scanning
- **Workflow Security Analysis**: detect privileged triggers, untrusted input injection, and authorization bypasses
- **Multi-Platform CI/CD Support**: GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure Pipelines, Travis CI
- **30+ Security Rules**: Coverage for critical vulnerabilities with CWE mappings
- **YAML Structural Analysis**: Deep parsing to detect multi-step attack chains

### 🛡️ PR Guard
- **Branch Name Protection**: Detect command substitution and shell metacharacters
- **Filename Validation**: Block injection attempts via file names
- **Diff Analysis**: Detect known malicious payload patterns
- **AI Config Protection**: Identify prompt injection attempts in AI configuration files

### 🔐 Advanced Secret Detection
- **Entropy Analysis**: Detect high-entropy strings that may be secrets
- **Pattern Matching**: 15+ secret types (AWS, GitHub, GitLab, JWT, Stripe, etc.)
- **Context Awareness**: Multi-line context for better detection

### 🤖 Auto-Remediation
- **Smart Fixes**: Automatic code fixes for common vulnerabilities
- **Detailed Guidance**: Step-by-step remediation instructions
- **Risk Assessment**: Confidence levels and impact analysis

### 📦 SBOM Support
- **Dependency Scanning**: npm, pip, Cargo, Go, Maven, Gradle
- **Vulnerability Detection**: Known vulnerable packages
- **SPDX Export**: Standard SBOM format export

### 🐳 Container Security
- **Dockerfile Analysis**: Best practices and security issues
- **Kubernetes Security**: Pod security, network policies, secrets
- **20+ Container Rules**: Privileged containers, root users, capabilities

### ⚙️ Custom Rules Engine
- **YAML/JSON Configuration**: Define custom security rules
- **Regex Patterns**: Flexible pattern matching
- **File Type Filtering**: Apply rules to specific file types

### 🛡️ Threat Intelligence
- **Known Malicious Domains**: Built-in threat database
- **Vulnerable Patterns**: Common exploitation patterns
- **Credential Exposure**: Detect compromised secrets

### 🔒 Cryptography
- **AES-256-GCM Encryption**: Secure findings storage
- **SHA-256/SHA-512 Hashing**: File integrity verification
- **Secure Random Generation**: Cryptographically secure tokens

### 📊 Multiple Output Formats
- **Text**: Human-readable console output with color
- **JSON**: Full structured data for automation
- **SARIF**: GitHub Code Scanning integration

### 🤖 AI Integration
- **MCP Server**: Integration with AI assistants for automated security workflows

### ⚠️ Offensive Security Tools (Authorized Testing Only)
> **WARNING**: These tools are for **authorized security testing only**. Only use on systems you own or have explicit written permission to test.

- **VulnerabilityProbe**: Detect command injection, path traversal, SSRF patterns
- **ExploitSimulator**: Analyze CI/CD workflow weaknesses (educational/defensive)
- **PayloadGenerator**: Generate test payloads for security testing

### 🛡️ Defensive Security Tools
- **PipelineHardener**: Analyze workflows and provide hardening recommendations
- **VulnerabilityMitigator**: Generate mitigations for known vulnerability patterns
- **DefensiveScanner**: Scan for security misconfigurations
- **Security Best Practices**: Check workflow compliance with security standards

---

## Installation

### From Source

```bash
git clone https://github.com/omniclaw/omniclaw.git
cd omniclaw
cargo build --release

# Binary at: target/release/omniclaw
```

---

## Usage

### Scan Local Workflows

```bash
# Scan default location
omniclaw scan

# Scan specific directory
omniclaw scan path/to/workflows

# Deep scan (recursive)
omniclaw scan --deep

# JSON output
omniclaw scan --format json
```

### PR Guard

```bash
# Check branch name
omniclaw guard --branch "fix/$(curl evil.com)"

# Check files
omniclaw guard --files '["$(echo hacked).md"]'

# Full guard check
omniclaw guard --branch "feature/test" --files '["src/main.rs"]' --diff "curl malicious.com"
```

---

## Rules Overview

### Workflow Security Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| WS-001 | Critical | Privileged trigger with untrusted code execution |
| WS-002 | Critical | Untrusted input in shell commands |
| WS-003 | High | Missing authorization check |
| WS-004 | High | Expression injection risk |
| WS-005 | High | Untrusted code checkout |
| WS-006 | High | Excessive permissions |
| WS-007 | Critical | Malicious payload detected |
| WS-008 | High | Remote script execution |

### Secret Detection Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| SEC-001 | High | AWS Access Key |
| SEC-002 | Critical | AWS Secret Key |
| SEC-003 | Critical | GitHub Token |
| SEC-004 | Critical | GitLab Token |
| SEC-005 | High | JWT Token |
| SEC-006 | Critical | Private Key |
| SEC-014 | High | High Entropy String |

### Container Security Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| CON-001 | High | Latest Tag Used |
| CON-002 | Medium | Missing USER Directive |
| CON-003 | Critical | Running as Root User |
| CON-013 | Critical | Privileged Container |

### General CI/CD Rules

| Rule ID | Severity | Platform | Description |
|---------|----------|----------|-------------|
| CI-001 | High | GitHub Actions | Workflow trigger privilege escalation |
| CI-002 | High | GitHub Actions | Unpinned action reference |
| CI-005 | Critical | GitHub Actions | Script execution with user input |
| CI-102 | Critical | Generic | Secret exfiltration via HTTP |
| CI-103 | Critical | Generic | Network shell detection |

---

## Architecture

```
omniclaw/
├── src/
│   ├── core/          # Core types (Finding, Severity, Config)
│   ├── rules/         # Security rules
│   ├── scanner/       # Scanning engines
│   ├── pr_guard/      # PR Guard functionality
│   ├── secrets/       # Advanced secret detection
│   ├── remediation/   # Auto-remediation
│   ├── sbom/          # SBOM support
│   ├── container/     # Container security
│   ├── rules_engine/  # Custom rules engine
│   ├── threat_intel/  # Threat intelligence
│   ├── crypto/        # Cryptography utilities
│   ├── github/       # GitHub API integration
│   ├── output/        # Output formatters
│   ├── offensive/     # Offensive security tools (authorized testing only)
│   ├── defensive/     # Defensive security tools
│   └── mcp/           # MCP server
```

---

## Why OmniClaw?

1. **Comprehensive**: 50+ security rules across multiple domains
2. **Advanced Detection**: Entropy analysis, threat intelligence, AI config protection
3. **Auto-Remediation**: Smart fixes with risk assessment
4. **Customizable**: Define your own security rules
5. **Cryptographic Security**: Protect your scan results
6. **Multi-Platform**: GitHub, GitLab, Jenkins, and more

---

## License

Dual-licensed under **MIT** and **Apache 2.0**.
