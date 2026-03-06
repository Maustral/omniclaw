//! Core types and structures for OmniClaw

pub mod finding;
pub mod severity;
pub mod config;

pub use finding::Finding;
pub use finding::ScanSummary;
pub use severity::Severity;
pub use config::Config;
