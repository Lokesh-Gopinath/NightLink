//! Cryptographic operations for nite

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::Rng;
use sha2::{Sha256, Digest};

pub fn generate_keypair() -> SigningKey {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    SigningKey::from_bytes(&bytes)
}

pub fn encrypt_private_key(private_key: &[u8], passphrase: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), anyhow::Error> {
    let salt: [u8; 16] = rand::thread_rng().gen();
    let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hasher.update(&salt);
    let hash = hasher.finalize();
    let key = Key::<Aes256Gcm>::from_slice(&hash[..32]);
    let nonce = Nonce::from_slice(&nonce_bytes[..]);
    let cipher = Aes256Gcm::new(key);
    let encrypted = cipher.encrypt(nonce, private_key)?;
    Ok((encrypted, salt.to_vec(), nonce_bytes.to_vec()))
}

pub fn decrypt_private_key(encrypted: &[u8], passphrase: &str, salt: &[u8], nonce: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hasher.update(salt);
    let hash = hasher.finalize();
    let key = Key::<Aes256Gcm>::from_slice(&hash[..32]);
    let nonce = Nonce::from_slice(&nonce[..12]);
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(nonce, encrypted).map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

/// Derive a shared secret using SHA256 of concatenated keys (simplified ECDH)
pub fn derive_shared_secret(private_key: &[u8], peer_public_key: &[u8]) -> Result<[u8; 32], anyhow::Error> {
    let private_arr: [u8; 32] = private_key.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid private key length"))?;
    let public_arr: [u8; 32] = peer_public_key.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;
    let mut hasher = Sha256::new();
    hasher.update(&private_arr);
    hasher.update(&public_arr);
    let result = hasher.finalize();
    let mut shared = [0u8; 32];
    shared.copy_from_slice(&result);
    Ok(shared)
}

pub fn encrypt_message(message: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let key = Key::<Aes256Gcm>::from_slice(&shared_secret[..32]);
    let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(nonce, message)?;
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt_message(encrypted: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    if encrypted.len() < 12 {
        return Err(anyhow::anyhow!("Encrypted data too short"));
    }
    let key = Key::<Aes256Gcm>::from_slice(&shared_secret[..32]);
    let nonce = Nonce::from_slice(&encrypted[..12]);
    let cipher = Aes256Gcm::new(key);
    cipher.decrypt(nonce, &encrypted[12..]).map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, anyhow::Error> {
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid verifying key length"))?;
    Ok(VerifyingKey::from_bytes(&key_bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_keypair_generation() {
        let signing_key = generate_keypair();
        let verifying_key = signing_key.verifying_key();
        assert_eq!(verifying_key.to_bytes().len(), 32);
    }
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let private_key = [0u8; 32];
        let passphrase = "test_password";
        let (encrypted, salt, nonce) = encrypt_private_key(&private_key, passphrase).unwrap();
        let decrypted = decrypt_private_key(&encrypted, passphrase, &salt, &nonce).unwrap();
        assert_eq!(private_key.to_vec(), decrypted);
    }
    #[test]
    fn test_message_encrypt_decrypt() {
        let message = b"Hello, nite!";
        let shared_secret = [0u8; 32];
        let encrypted = encrypt_message(message, &shared_secret).unwrap();
        let decrypted = decrypt_message(&encrypted, &shared_secret).unwrap();
        assert_eq!(message.to_vec(), decrypted);
    }
}