//! Hashing utilities for OmniClaw
//! 
//! Provides SHA-256 and SHA-512 hashing for file integrity verification,
//! content fingerprinting, and secure comparisons.

use sha2::{Sha256, Sha512, Digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hex;
use std::path::Path;

/// SHA-256 hash output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha256Hash(pub [u8; 32]);

impl Sha256Hash {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }
    
    /// Compute hash from data
    pub fn compute(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Self(hash)
    }
    
    /// Compute hash from string
    pub fn compute_string(s: &str) -> Self {
        Self::compute(s.as_bytes())
    }
    
    /// Compute hash from file
    pub fn compute_file(path: &Path) -> std::io::Result<Self> {
        use std::fs::File;
        use std::io::Read;
        
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Ok(Self(hash))
    }
    
    /// Encode as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    
    /// Encode as base64 string
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }
    
    /// Decode from hex string
    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Some(Self(hash))
    }
    
    /// Decode from base64 string
    pub fn from_base64(base64_str: &str) -> Option<Self> {
        let bytes = BASE64.decode(base64_str).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Some(Self(hash))
    }
}

impl std::fmt::Display for Sha256Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// SHA-512 hash output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha512Hash(pub [u8; 64]);

impl Sha512Hash {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self(*bytes)
    }
    
    /// Compute hash from data
    pub fn compute(data: &[u8]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&result);
        Self(hash)
    }
    
    /// Compute hash from string
    pub fn compute_string(s: &str) -> Self {
        Self::compute(s.as_bytes())
    }
    
    /// Compute hash from file
    pub fn compute_file(path: &Path) -> std::io::Result<Self> {
        use std::fs::File;
        use std::io::Read;
        
        let mut file = File::open(path)?;
        let mut hasher = Sha512::new();
        let mut buffer = [0u8; 8192];
        
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        
        let result = hasher.finalize();
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&result);
        Ok(Self(hash))
    }
    
    /// Encode as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    
    /// Encode as base64 string
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }
    
    /// Decode from hex string
    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 64 {
            return None;
        }
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&bytes);
        Some(Self(hash))
    }
}

impl std::fmt::Display for Sha512Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// File integrity checker
pub struct FileIntegrity {
    algorithm: HashAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
}

impl FileIntegrity {
    /// Create new integrity checker
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self { algorithm }
    }
    
    /// Create with SHA-256 (default)
    pub fn sha256() -> Self {
        Self::new(HashAlgorithm::Sha256)
    }
    
    /// Create with SHA-512
    pub fn sha512() -> Self {
        Self::new(HashAlgorithm::Sha512)
    }
    
    /// Compute hash of a file
    pub fn hash_file(&self, path: &Path) -> std::io::Result<String> {
        match self.algorithm {
            HashAlgorithm::Sha256 => {
                let hash = Sha256Hash::compute_file(path)?;
                Ok(hash.to_hex())
            }
            HashAlgorithm::Sha512 => {
                let hash = Sha512Hash::compute_file(path)?;
                Ok(hash.to_hex())
            }
        }
    }
    
    /// Verify file integrity against known hash
    pub fn verify(&self, path: &Path, expected_hash: &str) -> std::io::Result<bool> {
        let computed = self.hash_file(path)?;
        Ok(computed.eq_ignore_ascii_case(expected_hash))
    }
    
    /// Create a manifest of hashes for a directory
    pub fn create_manifest(&self, dir: &Path) -> std::io::Result<std::collections::HashMap<String, String>> {
        use std::fs;
        
        let mut manifest = std::collections::HashMap::new();
        
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                let hash = self.hash_file(&path)?;
                let relative = path.strip_prefix(dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                manifest.insert(relative, hash);
            }
        }
        
        Ok(manifest)
    }
}

/// Constant-time string comparison (for secure comparisons)
pub fn secure_compare(a: &str, b: &str) -> bool {
    use std::time::Duration;
    
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    
    if a_bytes.len() != b_bytes.len() {
        // Perform the comparison anyway to avoid timing attacks
        // but return false at the end
        let mut result = 0u8;
        for (i, &byte) in a_bytes.iter().enumerate() {
            if i < b_bytes.len() {
                result |= byte ^ b_bytes[i];
            } else {
                result |= byte;
            }
        }
        
        // Add a small delay to normalize timing
        std::thread::sleep(Duration::from_micros(100));
        
        return false;
    }
    
    let mut result = 0u8;
    for (&byte_a, &byte_b) in a_bytes.iter().zip(b_bytes.iter()) {
        result |= byte_a ^ byte_b;
    }
    
    // Small delay to prevent timing attacks
    std::thread::sleep(Duration::from_micros(100));
    
    result == 0
}

/// Compute checksum for multiple files (Merkle tree style)
pub fn compute_directory_checksum(dir: &Path) -> std::io::Result<String> {
    use std::fs;
    use std::collections::BTreeMap;
    
    let mut hashes: BTreeMap<String, String> = BTreeMap::new();
    
    // Collect all file hashes
    fn collect_hashes(dir: &Path, hashes: &mut BTreeMap<String, String>) -> std::io::Result<()> {
        
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                collect_hashes(&path, hashes)?;
            } else if path.is_file() {
                let hash = Sha256Hash::compute_file(&path)?.to_hex();
                let relative = path.to_string_lossy().to_string();
                hashes.insert(relative, hash);
            }
        }
        Ok(())
    }
    
    collect_hashes(dir, &mut hashes)?;
    
    // Combine all hashes
    let mut combined = String::new();
    for (_, hash) in &hashes {
        combined.push_str(hash);
    }
    
    // Hash the combined string
    Ok(Sha256Hash::compute_string(&combined).to_hex())
}

/// Hash output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFormat {
    Hex,
    Base64,
}

impl HashFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "hex" => Some(Self::Hex),
            "base64" | "b64" => Some(Self::Base64),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_sha256_compute() {
        let hash = Sha256Hash::compute_string("hello");
        assert_eq!(hash.to_hex(), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }
    
    #[test]
    fn test_sha512_compute() {
        let hash = Sha512Hash::compute_string("hello");
        assert_eq!(hash.to_hex().len(), 128);
    }
    
    #[test]
    fn test_file_hash() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"test content").unwrap();
        
        let hash = Sha256Hash::compute_file(file.path()).unwrap();
        assert_eq!(hash.to_hex(), "d8e8fca2dc0f896fd7cb4cb0031ba249bd8b8e7f6f1e9a1c8e8f2a4b5c6d7e8");
    }
    
    #[test]
    fn test_hash_format() {
        let hash = Sha256Hash::compute_string("test");
        
        let hex = hash.to_hex();
        let b64 = hash.to_base64();
        
        assert!(!hex.is_empty());
        assert!(!b64.is_empty());
        
        // Verify round-trip
        let from_hex = Sha256Hash::from_hex(&hex).unwrap();
        let from_b64 = Sha256Hash::from_base64(&b64).unwrap();
        
        assert_eq!(hash.0, from_hex.0);
        assert_eq!(hash.0, from_b64.0);
    }
    
    #[test]
    fn test_secure_compare() {
        assert!(secure_compare("test", "test"));
        assert!(!secure_compare("test", " Test"));
        assert!(!secure_compare("test", "test1"));
    }
    
    #[test]
    fn test_file_integrity() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"test content").unwrap();
        
        let checker = FileIntegrity::sha256();
        let hash = checker.hash_file(file.path()).unwrap();
        
        assert!(checker.verify(file.path(), &hash).unwrap());
        assert!(!checker.verify(file.path(), "wrong_hash").unwrap());
    }
}

