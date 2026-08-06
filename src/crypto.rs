use ed25519_dalek::{SigningKey, VerifyingKey};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use sha2::{Sha256, Digest};
use argon2::Argon2;
use rand::Rng;

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    let signing_key = SigningKey::from_bytes(&bytes);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn encrypt_private_key(private_key: &[u8], passphrase: &str) -> Result<Vec<u8>, anyhow::Error> {
    let salt = rand::thread_rng().gen::<[u8; 16]>();
    let argon2 = Argon2::default();
    
    let mut key_bytes = [0u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), &salt, &mut key_bytes)?;
    
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let nonce = rand::thread_rng().gen::<[u8; 12]>();
    let cipher = Aes256Gcm::new(key);
    
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), private_key)?;
    
    let mut blob = Vec::with_capacity(16 + 12 + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

pub fn decrypt_private_key(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, anyhow::Error> {
    if encrypted.len() < 28 {
        return Err(anyhow::anyhow!("Encrypted key too short"));
    }
    
    let salt = &encrypted[..16];
    let nonce = &encrypted[16..28];
    let ciphertext = &encrypted[28..];
    
    let argon2 = Argon2::default();
    let mut key_bytes = [0u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)?;
    
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    Ok(cipher.decrypt(Nonce::from_slice(nonce), ciphertext)?)
}

pub fn derive_session_key(my_private: &[u8], their_public: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(my_private);
    hasher.update(their_public);
    hasher.finalize().to_vec()
}