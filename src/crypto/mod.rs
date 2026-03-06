//! Cryptography module for OmniClaw
//! 
//! Provides encryption, hashing, and secure random generation utilities
//! for protecting sensitive scan data and findings.

pub mod encryption;
pub mod hash;

pub use encryption::*;
pub use hash::*;

use thiserror::Error;

/// Cryptography-related errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Invalid key length")]
    InvalidKeyLength,
    
    #[error("Invalid data format")]
    InvalidFormat,
    
    #[error("Random generation failed")]
    RandomGenerationFailed,
}

