//! Encryption utilities for OmniClaw
//! 
//! Provides AES-256-GCM encryption for protecting sensitive scan data,
//! findings, and configuration information.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use crate::crypto::CryptoError;

/// Default key size in bytes (256 bits)
pub const KEY_SIZE: usize = 32;
/// Nonce size in bytes (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Secure encryption key
#[derive(Clone)]
pub struct SecureKey {
    key: [u8; KEY_SIZE],
}

impl SecureKey {
    /// Generate a new random key
    pub fn generate() -> Result<Self, CryptoError> {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Ok(Self { key })
    }
    
    /// Create key from a passphrase using SHA-256
    pub fn from_passphrase(passphrase: &str) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        let result = hasher.finalize();
        
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&result[..KEY_SIZE]);
        Self { key }
    }
    
    /// Create key from raw bytes (must be exactly 32 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength);
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { key })
    }
    
    /// Get key as bytes
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }
    
    /// Encode key as base64 string
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.key)
    }
    
    /// Decode key from base64 string
    pub fn from_base64(encoded: &str) -> Result<Self, CryptoError> {
        let bytes = BASE64.decode(encoded)
            .map_err(|_| CryptoError::InvalidFormat)?;
        Self::from_bytes(&bytes)
    }
}

/// Encrypted data container
pub struct EncryptedData {
    /// Nonce used for encryption (12 bytes)
    pub nonce: Vec<u8>,
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Serialize to base64 string (nonce:ciphertext format)
    pub fn to_string(&self) -> String {
        format!(
            "{}:{}",
            BASE64.encode(&self.nonce),
            BASE64.encode(&self.ciphertext)
        )
    }
    
    /// Deserialize from base64 string
    pub fn from_string(encoded: &str) -> Result<Self, CryptoError> {
        let parts: Vec<&str> = encoded.split(':').collect();
        if parts.len() != 2 {
            return Err(CryptoError::InvalidFormat);
        }
        
        let nonce = BASE64.decode(parts[0])
            .map_err(|_| CryptoError::InvalidFormat)?;
        let ciphertext = BASE64.decode(parts[1])
            .map_err(|_| CryptoError::InvalidFormat)?;
        
        Ok(Self { nonce, ciphertext })
    }
}

/// Encryptor for secure data protection
pub struct Encryptor {
    cipher: Aes256Gcm,
}

impl Encryptor {
    /// Create encryptor with a secure key
    pub fn new(key: &SecureKey) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .expect("Key size is valid for AES-256-GCM");
        Self { cipher }
    }
    
    /// Encrypt data with a random nonce
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt
        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        
        Ok(EncryptedData {
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        })
    }
    
    /// Encrypt a string
    pub fn encrypt_string(&self, plaintext: &str) -> Result<String, CryptoError> {
        let encrypted = self.encrypt(plaintext.as_bytes())?;
        Ok(encrypted.to_string())
    }
    
    /// Encrypt JSON-serializable data
    pub fn encrypt_json<T: serde::Serialize>(&self, data: &T) -> Result<String, CryptoError> {
        let json = serde_json::to_vec(data)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        let encrypted = self.encrypt(&json)?;
        Ok(encrypted.to_string())
    }
}

/// Decryptor for secure data
pub struct Decryptor {
    cipher: Aes256Gcm,
}

impl Decryptor {
    /// Create decryptor with a secure key
    pub fn new(key: &SecureKey) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .expect("Key size is valid for AES-256-GCM");
        Self { cipher }
    }
    
    /// Decrypt encrypted data
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>, CryptoError> {
        if encrypted.nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidFormat);
        }
        
        let nonce = Nonce::from_slice(&encrypted.nonce);
        
        self.cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
    
    /// Decrypt a string
    pub fn decrypt_string(&self, encrypted: &str) -> Result<String, CryptoError> {
        let encrypted_data = EncryptedData::from_string(encrypted)?;
        let decrypted = self.decrypt(&encrypted_data)?;
        String::from_utf8(decrypted)
            .map_err(|_| CryptoError::InvalidFormat)
    }
    
    /// Decrypt JSON data
    pub fn decrypt_json<T: serde::de::DeserializeOwned>(&self, encrypted: &str) -> Result<T, CryptoError> {
        let encrypted_data = EncryptedData::from_string(encrypted)?;
        let decrypted = self.decrypt(&encrypted_data)?;
        serde_json::from_slice(&decrypted)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
}

/// Combined encrypt/decrypt helper
pub struct Crypto {
    encryptor: Encryptor,
    decryptor: Decryptor,
}

impl Crypto {
    /// Create new crypto handler with a secure key
    pub fn new(key: SecureKey) -> Self {
        Self {
            encryptor: Encryptor::new(&key),
            decryptor: Decryptor::new(&key),
        }
    }
    
    /// Create from passphrase
    pub fn from_passphrase(passphrase: &str) -> Self {
        let key = SecureKey::from_passphrase(passphrase);
        Self::new(key)
    }
    
    /// Encrypt data
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
        self.encryptor.encrypt(plaintext)
    }
    
    /// Decrypt data
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>, CryptoError> {
        self.decryptor.decrypt(encrypted)
    }
    
    /// Encrypt string
    pub fn encrypt_string(&self, plaintext: &str) -> Result<String, CryptoError> {
        self.encryptor.encrypt_string(plaintext)
    }
    
    /// Decrypt string
    pub fn decrypt_string(&self, encrypted: &str) -> Result<String, CryptoError> {
        self.decryptor.decrypt_string(encrypted)
    }
    
    /// Encrypt JSON
    pub fn encrypt_json<T: serde::Serialize>(&self, data: &T) -> Result<String, CryptoError> {
        self.encryptor.encrypt_json(data)
    }
    
    /// Decrypt JSON
    pub fn decrypt_json<T: serde::de::DeserializeOwned>(&self, encrypted: &str) -> Result<T, CryptoError> {
        self.decryptor.decrypt_json(encrypted)
    }
}

/// Secure token generator
pub struct SecureToken {
    _priv: (),
}

impl SecureToken {
    /// Generate a random token of specified length
    pub fn generate(length: usize) -> Vec<u8> {
        let mut token = vec![0u8; length];
        OsRng.fill_bytes(&mut token);
        token
    }
    
    /// Generate a random token as hex string
    pub fn generate_hex(length: usize) -> String {
        let bytes = Self::generate(length);
        hex::encode(bytes)
    }
    
    /// Generate a random token as base64 string
    pub fn generate_base64(length: usize) -> String {
        let bytes = Self::generate(length);
        BASE64.encode(&bytes)
    }
    
    /// Generate a secure random number
    pub fn random_u64() -> u64 {
        let mut bytes = [0u8; 8];
        OsRng.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    
    /// Generate a secure random number within range
    pub fn random_in_range(min: u64, max: u64) -> u64 {
        let range = max - min + 1;
        let random = Self::random_u64();
        min + (random % range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_generation() {
        let key = SecureKey::generate().unwrap();
        assert_eq!(key.as_bytes().len(), KEY_SIZE);
    }
    
    #[test]
    fn test_key_from_passphrase() {
        let key = SecureKey::from_passphrase("test_password");
        assert_eq!(key.as_bytes().len(), KEY_SIZE);
    }
    
    #[test]
    fn test_encrypt_decrypt() {
        let key = SecureKey::generate().unwrap();
        let crypto = Crypto::new(key);
        
        let plaintext = "Hello, OmniClaw!";
        let encrypted = crypto.encrypt_string(plaintext).unwrap();
        let decrypted = crypto.decrypt_string(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }
    
    #[test]
    fn test_encrypt_json() {
        #[derive(Serialize, Deserialize, PartialEq)]
        struct TestData {
            name: String,
            value: i32,
        }
        
        let key = SecureKey::generate().unwrap();
        let crypto = Crypto::new(key);
        
        let data = TestData {
            name: "test".to_string(),
            value: 42,
        };
        
        let encrypted = crypto.encrypt_json(&data).unwrap();
        let decrypted: TestData = crypto.decrypt_json(&encrypted).unwrap();
        
        assert_eq!(data, decrypted);
    }
    
    #[test]
    fn test_secure_token() {
        let token = SecureToken::generate(32);
        assert_eq!(token.len(), 32);
        
        let hex = SecureToken::generate_hex(16);
        assert_eq!(hex.len(), 32); // hex doubles length
        
        let base64 = SecureToken::generate_base64(16);
        // base64 output length varies
        assert!(!base64.is_empty());
    }
}

