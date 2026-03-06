//! OmniClaw - Unified CI/CD Security Scanner
//! 
//! A comprehensive security scanner for CI/CD pipelines

pub mod core;
pub mod scanner;
pub mod pr_guard;
pub mod github;
pub mod rules;
pub mod output;
pub mod crypto;
pub mod secrets;
pub mod remediation;
pub mod sbom;
pub mod container;
pub mod rules_engine;
pub mod threat_intel;
pub mod offensive;
pub mod defensive;

pub use scanner::LocalScanner;
pub use scanner::local::ScannerConfig;
pub use pr_guard::PRGuard;
pub use core::{Finding, Severity, ScanSummary, Config};
pub use crypto::{Crypto, SecureKey, Encryptor, Decryptor, SecureToken, Sha256Hash, Sha512Hash, FileIntegrity, CryptoError};
pub use secrets::{SecretScanner, DetectedSecret, SecretType};
pub use remediation::{AutoRemediator, RemediationPlan, RemediationAction, RemediationType};
pub use sbom::{SbomScanner, Sbom, Package, Ecosystem};
pub use container::{ContainerScanner, ContainerIssue};
pub use rules_engine::{RulesEngine, CustomRule, example_rules};
pub use threat_intel::{ThreatIntel, ThreatEntry, ThreatSource, create_with_builtin};
pub use offensive::{VulnerabilityProbe, ExploitSimulator, PayloadGenerator, check_dangerous_input};
pub use defensive::{PipelineHardener, VulnerabilityMitigator, DefensiveScanner, check_security_best_practices, SecurityRecommendation, Priority, HardeningCheck};
