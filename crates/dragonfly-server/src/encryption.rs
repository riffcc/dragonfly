use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use base64::{Engine as _, engine::general_purpose};
use tracing::{error, info, warn};
use std::{env, fs, path::Path, io::Write};

// Gets the encryption key from the SECRET_KEY env var, the .env file, or generates a new one
fn get_encryption_key() -> [u8; 32] {
    // Try to get SECRET_KEY from environment first
    match env::var("SECRET_KEY") {
        Ok(env_key) => {
            // Create a 32-byte key from the environment variable
            let mut key = [0u8; 32];
            
            // Use the bytes directly if possible, or derive using a simple PBKDF
            if env_key.len() >= 32 {
                key.copy_from_slice(&env_key.as_bytes()[0..32]);
            } else {
                // Simple stretching for shorter keys (not cryptographically strong, but functional)
                let mut stretched = env_key.as_bytes().to_vec();
                while stretched.len() < 32 {
                    stretched.extend_from_slice(env_key.as_bytes());
                }
                key.copy_from_slice(&stretched[0..32]);
            }
            
            return key;
        },
        Err(_) => {
            // SECRET_KEY not found in environment, check for .env file
            let env_file_path = "/var/lib/dragonfly/.env";
            let key = load_or_create_key_file(env_file_path);
            
            // If we get a valid key from the file, return it
            if let Some(file_key) = key {
                return file_key;
            }
            
            // Fallback key - used only if we can't read or create the .env file
            warn!("Using insecure fallback encryption key - credentials will NOT be securely stored!");
            warn!("Set SECRET_KEY environment variable or ensure /var/lib/dragonfly/.env is writable");
            
            let fallback = "DRAGONFLY_DEFAULT_FALLBACK_SECRET_KEY_32B".to_string();
            let mut key = [0u8; 32];
            let mut stretched = fallback.as_bytes().to_vec();
            while stretched.len() < 32 {
                stretched.extend_from_slice(fallback.as_bytes());
            }
            key.copy_from_slice(&stretched[0..32]);
            
            key
        }
    }
}

// Loads a key from the specified file path or creates a new one if it doesn't exist
fn load_or_create_key_file(file_path: &str) -> Option<[u8; 32]> {
    // Check if .env file exists and try to read SECRET_KEY
    if let Ok(content) = fs::read_to_string(file_path) {
        for line in content.lines() {
            if line.starts_with("SECRET_KEY=") {
                let key_str = line.trim_start_matches("SECRET_KEY=");
                
                // If the key is base64 encoded, decode it
                if let Ok(decoded) = general_purpose::STANDARD.decode(key_str) {
                    if decoded.len() >= 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&decoded[0..32]);
                        info!("Successfully loaded encryption key from {}", file_path);
                        return Some(key);
                    }
                }
                
                // If not base64 encoded or not long enough, use as a password
                let mut key = [0u8; 32];
                let mut stretched = key_str.as_bytes().to_vec();
                while stretched.len() < 32 {
                    stretched.extend_from_slice(key_str.as_bytes());
                }
                key.copy_from_slice(&stretched[0..32]);
                info!("Successfully loaded encryption key from {}", file_path);
                return Some(key);
            }
        }
    }
    
    // File doesn't exist or doesn't contain SECRET_KEY, generate a new key
    // Use Aes256Gcm's implementation of OsRng and generate_nonce for randomness
    let mut key = [0u8; 32];
    for chunk in key.chunks_mut(12) {
        // Use generate_nonce to get random bytes (it returns 12 bytes)
        let random_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
        let len = chunk.len().min(random_bytes.len());
        chunk[..len].copy_from_slice(&random_bytes[..len]);
    }
    
    // Try to create the directory if it doesn't exist
    if let Some(parent_dir) = Path::new(file_path).parent() {
        if !parent_dir.exists() {
            if let Err(e) = fs::create_dir_all(parent_dir) {
                error!("Failed to create directory {}: {}", parent_dir.display(), e);
                return None;
            }
        }
    }
    
    // Write the key to the file
    let key_b64 = general_purpose::STANDARD.encode(&key);
    let env_content = format!("SECRET_KEY={}\n", key_b64);
    
    match fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(env_content.as_bytes()) {
                error!("Failed to write to {}: {}", file_path, e);
                return None;
            }
            
            // Try to set restrictive permissions on the file (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) = fs::set_permissions(file_path, fs::Permissions::from_mode(0o600)) {
                    warn!("Failed to set permissions on {}: {}", file_path, e);
                }
            }
            
            info!("Generated and saved new encryption key to {}", file_path);
            Some(key)
        },
        Err(e) => {
            error!("Failed to open {} for writing: {}", file_path, e);
            None
        }
    }
}

// Encrypt a string using AES-GCM
pub fn encrypt_string(plaintext: &str) -> Result<String, anyhow::Error> {
    let key = get_encryption_key();
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    
    // Create a unique nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    // Encrypt the plaintext
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes().as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
    
    // Combine nonce and ciphertext and base64 encode
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    
    Ok(general_purpose::STANDARD.encode(combined))
}

// Decrypt a string using AES-GCM
pub fn decrypt_string(encrypted: &str) -> Result<String, anyhow::Error> {
    let key = get_encryption_key();
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    
    // Decode the base64 string
    let combined = general_purpose::STANDARD.decode(encrypted)
        .map_err(|e| anyhow::anyhow!("Base64 decode failed: {}", e))?;
    
    // Split the nonce and ciphertext
    if combined.len() < 12 {
        return Err(anyhow::anyhow!("Invalid encrypted data: too short"));
    }
    
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Decrypt the ciphertext
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
    
    // Convert bytes to string
    String::from_utf8(plaintext)
        .map_err(|e| anyhow::anyhow!("UTF-8 conversion failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // Helper to set SECRET_KEY for testing (env var manipulation is unsafe in Rust 2024)
    fn set_test_key(key: &str) {
        unsafe { std::env::set_var("SECRET_KEY", key); }
    }

    fn clear_test_key() {
        unsafe { std::env::remove_var("SECRET_KEY"); }
    }

    #[test]
    #[serial]
    fn test_encrypt_decrypt_roundtrip() {
        set_test_key("test_secret_key_for_encryption_testing_32bytes");

        let original = "Hello, World! This is a test message.";
        let encrypted = encrypt_string(original).expect("Encryption should succeed");

        // Encrypted string should be different from original
        assert_ne!(encrypted, original);

        // Decrypt should return original
        let decrypted = decrypt_string(&encrypted).expect("Decryption should succeed");
        assert_eq!(decrypted, original);

        clear_test_key();
    }

    #[test]
    #[serial]
    fn test_encrypt_different_each_time() {
        set_test_key("test_secret_key_for_encryption_testing_32bytes");

        let original = "Same message";
        let encrypted1 = encrypt_string(original).expect("Encryption should succeed");
        let encrypted2 = encrypt_string(original).expect("Encryption should succeed");

        // Due to random nonce, encryptions should be different
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same thing
        let decrypted1 = decrypt_string(&encrypted1).expect("Decryption should succeed");
        let decrypted2 = decrypt_string(&encrypted2).expect("Decryption should succeed");
        assert_eq!(decrypted1, original);
        assert_eq!(decrypted2, original);

        clear_test_key();
    }

    #[test]
    #[serial]
    fn test_encrypt_empty_string() {
        set_test_key("test_secret_key_for_encryption_testing_32bytes");

        let original = "";
        let encrypted = encrypt_string(original).expect("Encryption should succeed");
        let decrypted = decrypt_string(&encrypted).expect("Decryption should succeed");
        assert_eq!(decrypted, original);

        clear_test_key();
    }

    #[test]
    #[serial]
    fn test_encrypt_unicode() {
        set_test_key("test_secret_key_for_encryption_testing_32bytes");

        let original = "Hello 世界! 🎉 Привет мир!";
        let encrypted = encrypt_string(original).expect("Encryption should succeed");
        let decrypted = decrypt_string(&encrypted).expect("Decryption should succeed");
        assert_eq!(decrypted, original);

        clear_test_key();
    }

    #[test]
    #[serial]
    fn test_decrypt_invalid_base64() {
        set_test_key("test_secret_key_for_encryption_testing_32bytes");

        let result = decrypt_string("not-valid-base64!!!");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Base64"));

        clear_test_key();
    }

    #[test]
    #[serial]
    fn test_decrypt_too_short() {
        set_test_key("test_secret_key_for_encryption_testing_32bytes");

        // Valid base64 but too short to contain nonce + ciphertext
        let result = decrypt_string("c2hvcnQ="); // "short" in base64
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));

        clear_test_key();
    }

    #[test]
    #[serial]
    fn test_key_stretching_short_key() {
        // Test with a short key - should still work via stretching
        set_test_key("short");

        let original = "test message";
        let encrypted = encrypt_string(original).expect("Encryption should succeed");
        let decrypted = decrypt_string(&encrypted).expect("Decryption should succeed");
        assert_eq!(decrypted, original);

        clear_test_key();
    }
} 