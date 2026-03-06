//! OmniClaw - Unified CI/CD Security Scanner
//! 
//! Main CLI entry point

use clap::{Parser, Subcommand};
use omniclaw::core::{Finding, ScanSummary, Severity};
use omniclaw::scanner::LocalScanner;
use omniclaw::pr_guard::PRGuard;
use omniclaw::output::{TextFormatter, JsonFormatter, SarifFormatter, Formatter};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "omniclaw")]
#[command(version = "1.0.0")]
#[command(about = "Unified CI/CD Security Scanner", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Output format (text, json, sarif)
    #[arg(short, long, default_value = "text")]
    format: String,
    
    /// Output file (optional)
    #[arg(short, long)]
    output: Option<PathBuf>,
    
    /// GitHub token for API access
    #[arg(short, long, env = "GITHUB_TOKEN")]
    token: Option<String>,
    
    /// Minimum severity to report (critical, high, medium, low, info)
    #[arg(long, default_value = "info")]
    min_severity: String,
    
    /// Disable workflow security checks
    #[arg(long)]
    no_workflow_security: bool,
    
    /// Disable general CI/CD checks
    #[arg(long)]
    no_cicd_checks: bool,
    
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan local workflow files
    Scan {
        /// Path to scan (directory or file)
        #[arg(default_value = ".github/workflows")]
        path: PathBuf,
        
        /// Enable deep scan (recursive)
        #[arg(long)]
        deep: bool,
    },
    
    /// Scan a GitHub repository (requires token)
    ScanRepo {
        /// Repository in format owner/repo
        #[arg(value_parser = parse_repo)]
        repo: String,
    },
    
    /// Scan all repos in a GitHub organization
    ScanOrg {
        /// Organization name
        org: String,
        
        /// Concurrency level
        #[arg(long, default_value = "4")]
        concurrency: usize,
    },
    
    /// Run PR Guard checks
    Guard {
        /// Branch name
        #[arg(long, env = "GITHUB_HEAD_REF")]
        branch: Option<String>,
        
        /// Files (JSON array)
        #[arg(long)]
        files: Option<String>,
        
        /// Diff content
        #[arg(long)]
        diff: Option<String>,
        
        /// AI config content (CLAUDE.md, etc.)
        #[arg(long)]
        ai_config: Option<String>,
    },
    
    /// List all available rules
    Rules {
        /// Filter by platform (github_actions, gitlab_ci, jenkins)
        #[arg(long)]
        platform: Option<String>,
    },
}

fn parse_repo(s: &str) -> Result<String, String> {
    if s.contains('/') {
        Ok(s.to_string())
    } else {
        Err("Repository must be in format owner/repo".to_string())
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();
    
    let cli = Cli::parse();
    
    let result = match &cli.command {
        Commands::Scan { path, deep } => run_scan(path, *deep, &cli),
        Commands::ScanRepo { repo } => run_scan_repo(repo, &cli),
        Commands::ScanOrg { org, concurrency } => run_scan_org(org, *concurrency, &cli),
        Commands::Guard { branch, files, diff, ai_config } => run_guard(branch.as_deref(), files.as_deref(), diff.as_deref(), ai_config.as_deref()),
        Commands::Rules { platform } => list_rules(platform.as_deref()),
    };
    
    match result {
        Ok(output) => {
            if let Some(output_file) = &cli.output {
                std::fs::write(output_file, &output).expect("Failed to write output file");
                println!("Output written to {}", output_file.display());
            } else {
                println!("{}", output);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn run_scan(path: &PathBuf, deep: bool, cli: &Cli) -> Result<String, String> {
    let mut config = omniclaw::ScannerConfig::default();
    config.deep_scan = deep;
    config.workflow_security_checks = !cli.no_workflow_security;
    config.cicd_checks = !cli.no_cicd_checks;
    config.min_severity = Severity::from_str(&cli.min_severity);
    
    let scanner = LocalScanner::with_config(config);
    let result = scanner.scan(path);
    
    format_output(&result.findings, &result.summary, &cli.format)
}

fn run_scan_repo(_repo: &str, _cli: &Cli) -> Result<String, String> {
    Err("Remote repo scanning not yet implemented. Use local scanning instead.".to_string())
}

fn run_scan_org(_org: &str, _concurrency: usize, _cli: &Cli) -> Result<String, String> {
    Err("Organization scanning not yet implemented. Use local scanning instead.".to_string())
}

fn run_guard(branch: Option<&str>, files: Option<&str>, diff: Option<&str>, ai_config: Option<&str>) -> Result<String, String> {
    let guard = PRGuard::new();
    
    let files_vec: Option<Vec<String>> = files.and_then(|s| serde_json::from_str(s).ok());
    
    let result = guard.check(
        branch,
        files_vec.as_deref(),
        diff,
        ai_config,
    );
    
    let output = if result.safe {
        format!("✓ PR is safe - {}\n", result.summary)
    } else {
        let mut output = format!("✗ PR has issues - {}\n\n", result.summary);
        
        if !result.branch.safe {
            output.push_str(&format!("  Branch: {}\n", result.branch.reason.as_ref().unwrap()));
        }
        
        if !result.filenames.safe {
            for issue in &result.filenames.issues {
                output.push_str(&format!("  File: {} - {}\n", issue.file, issue.reason));
            }
        }
        
        if !result.diff.safe {
            for m in &result.diff.matches {
                output.push_str(&format!("  Diff match: {} ({})\n", m.pattern, m.match_type));
            }
        }
        
        if !result.ai_config.safe {
            for s in &result.ai_config.suspicious {
                output.push_str(&format!("  AI Config: Suspicious pattern: {}\n", s));
            }
        }
        
        output
    };
    
    Ok(output)
}

fn list_rules(platform: Option<&str>) -> Result<String, String> {
    let rules = omniclaw::rules::all_cicd_rules();
    let ws_rules = omniclaw::rules::all_workflow_security_rules();
    
    let mut output = String::new();
    output.push_str("OmniClaw Security Rules\n");
    output.push_str(&"=".repeat(60));
    output.push_str("\n\n");
    
    // Workflow Security Rules
    output.push_str("Workflow Security Rules:\n");
    output.push_str(&"-".repeat(60));
    output.push_str("\n");
    
    for rule in &ws_rules {
        output.push_str(&format!(
            "[{}] {} - {}\n",
            rule.severity, rule.id, rule.name
        ));
        output.push_str(&format!("  {}\n", rule.description));
        output.push_str(&format!("  CWE: {:?}\n\n", rule.cwe_ids));
    }
    
    // CI/CD Rules
    output.push_str("General CI/CD Rules:\n");
    output.push_str(&"-".repeat(60));
    output.push_str("\n");
    
    for rule in &rules {
        if let Some(p) = platform {
            if rule.platform == p {
                output.push_str(&format!(
                    "[{}] {} - {}\n",
                    rule.severity, rule.id, rule.name
                ));
                output.push_str(&format!("  {}\n", rule.description));
                output.push_str(&format!("  Platform: {}\n\n", rule.platform));
            }
        } else {
            output.push_str(&format!(
                "[{}] {} - {} ({})\n",
                rule.severity, rule.id, rule.name, rule.platform
            ));
        }
    }
    
    Ok(output)
}

fn format_output(findings: &[Finding], summary: &ScanSummary, format: &str) -> Result<String, String> {
    match format.to_lowercase().as_str() {
        "json" => {
            let formatter = JsonFormatter::new();
            Ok(formatter.format(findings, summary))
        }
        "sarif" => {
            let formatter = SarifFormatter::new();
            Ok(formatter.format(findings, summary))
        }
        _ => {
            let formatter = TextFormatter::new();
            Ok(formatter.format(findings, summary))
        }
    }
}

