# OmniClaw 🔒

## Project Overview

OmniClaw is a comprehensive CI/CD security scanner built in Rust that helps identify vulnerabilities in continuous integration and deployment pipelines.

## Features

- Multi-platform CI/CD security scanning
- 50+ security rules
- PR Guard for branch protection
- Secret detection with entropy analysis
- Auto-remediation capabilities
- SBOM support
- Container security analysis
- Threat intelligence integration
- Cryptographic data protection

## Building

```bash
cargo build --release
```

## Running Tests

```bash
cargo test
```

## Quick Start

```bash
# Scan workflows
./target/release/omniclaw scan

# Run PR Guard
./target/release/omniclaw guard --branch "fix/bug"

# List rules
./target/release/omniclaw rules
```

## Architecture

```
src/
├── core/           # Core types
├── scanner/        # Scanning engines
├── secrets/        # Secret detection
├── remediation/    # Auto-fix
├── sbom/           # SBOM support
├── container/      # Container security
├── rules_engine/   # Custom rules
├── threat_intel/   # Threat intelligence
├── crypto/         # Cryptography
├── output/         # Output formatters
└── mcp/           # AI integration
```

## License

MIT or Apache-2.0

