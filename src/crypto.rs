//! Cryptographic primitives for NightLink.
//!
//! Two layers:
//! 1. **Key-at-rest** — the Ed25519 identity seed is stored encrypted with
//!    argon2id (KDF) + AES-256-GCM, protected by the user passphrase.
//! 2. **Session encryption** — a fresh X25519 ephemeral key is generated for
//!    every chat; the session key is derived from ECDH over the ephemeral and
//!    static X25519 keys, then messages are sealed with ChaCha20-Poly1305
//!    using a fresh random nonce per message.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

// ==================== key generation / key-at-rest ====================

/// Generate a fresh Ed25519 identity keypair.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    let signing_key = SigningKey::from_bytes(&bytes);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Encrypt the 32-byte private key seed with a passphrase (argon2id + AES-GCM).
pub fn encrypt_private_key(private_key: &[u8], passphrase: &str) -> Result<Vec<u8>, anyhow::Error> {
    let salt = rand::thread_rng().gen::<[u8; 16]>();
    let argon2 = Argon2::default();

    let mut key_bytes = [0u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), &salt, &mut key_bytes)?;

    let key = GenericArray::from_slice(&key_bytes);
    let nonce = rand::thread_rng().gen::<[u8; 12]>();
    let cipher = Aes256Gcm::new(key);

    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), private_key)?;

    let mut blob = Vec::with_capacity(16 + 12 + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt a key-at-rest blob with the passphrase. Returns the 32-byte seed.
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

    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    Ok(cipher.decrypt(Nonce::from_slice(nonce), ciphertext)?)
}

// ==================== static X25519 identity keys ====================

/// Derive a deterministic static X25519 private key from an Ed25519 seed
/// (XEdDSA-style: SHA-512 then clamp).
pub fn derive_static_x25519(ed25519_seed: &[u8; 32]) -> StaticSecret {
    let hashed = Sha512::digest(ed25519_seed);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hashed[..32]);
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    StaticSecret::from(key)
}

/// Derive the static X25519 keypair from the Ed25519 identity seed.
pub fn static_x25519_keypair(ed25519_seed: &[u8; 32]) -> (StaticSecret, PublicKey) {
    let secret = derive_static_x25519(ed25519_seed);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Generate a fresh ephemeral X25519 keypair for a single chat session.
pub fn generate_ephemeral() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    (secret, public)
}

// ==================== Ed25519 identity signatures ====================

/// Sign a message with the Ed25519 identity key.
pub fn sign_message(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// Verify an Ed25519 signature against a public key.
pub fn verify_signature(
    public_key: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> bool {
    public_key.verify(message, signature).is_ok()
}

// ==================== session keys ====================

/// Derive a per-session ChaCha20-Poly1305 cipher from ECDH using both the
/// fresh ephemeral pair and the static identity pair. Both peers compute the
/// same key because the two DH terms are symmetric.
pub fn derive_session_key(
    our_ephemeral: EphemeralSecret,
    their_ephemeral: &PublicKey,
    our_static: &StaticSecret,
    their_static: &PublicKey,
) -> ChaCha20Poly1305 {
    let ee = our_ephemeral.diffie_hellman(their_ephemeral);
    let ss = our_static.diffie_hellman(their_static);

    let mut hasher = Sha256::new();
    hasher.update(ee.as_bytes());
    hasher.update(ss.as_bytes());
    let digest = hasher.finalize();
    let key = GenericArray::from_slice(&digest);

    ChaCha20Poly1305::new(key)
}

/// Encrypt a message with ChaCha20-Poly1305 using a fresh random nonce.
/// Returns `<12-byte nonce><ciphertext>`.
pub fn encrypt_message(cipher: &ChaCha20Poly1305, message: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, message)?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a `<12-byte nonce><ciphertext>` blob.
pub fn decrypt_message(cipher: &ChaCha20Poly1305, blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    if blob.len() < 12 {
        return Err(anyhow::anyhow!("Encrypted message too short"));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let nonce = GenericArray::from_slice(nonce_bytes);
    Ok(cipher.decrypt(nonce, ciphertext)?)
}

// ============================ tests ============================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_at_rest_round_trip() {
        let (signing_key, _) = generate_keypair();
        let encrypted = encrypt_private_key(&signing_key.to_bytes(), "hunter2").unwrap();
        let decrypted = decrypt_private_key(&encrypted, "hunter2").unwrap();
        assert_eq!(decrypted, signing_key.to_bytes().to_vec());

        assert!(decrypt_private_key(&encrypted, "wrong-pass").is_err());
    }

    #[test]
    fn static_key_is_deterministic() {
        let seed = [42u8; 32];
        let (s1, p1) = static_x25519_keypair(&seed);
        let (_, p2) = static_x25519_keypair(&seed);
        assert_eq!(PublicKey::from(&s1).to_bytes(), p1.to_bytes());
        assert_eq!(p1.to_bytes(), p2.to_bytes());
    }

    #[test]
    fn session_keys_agree_between_two_parties() {
        let (a_static, a_static_pub) = static_x25519_keypair(&[7u8; 32]);
        let (b_static, b_static_pub) = static_x25519_keypair(&[9u8; 32]);
        let (a_eph, a_eph_pub) = generate_ephemeral();
        let (b_eph, b_eph_pub) = generate_ephemeral();

        let alice_cipher = derive_session_key(a_eph, &b_eph_pub, &a_static, &b_static_pub);
        let bob_cipher = derive_session_key(b_eph, &a_eph_pub, &b_static, &a_static_pub);

        let blob = encrypt_message(&alice_cipher, b"hello over tor!").unwrap();
        assert_eq!(decrypt_message(&bob_cipher, &blob).unwrap(), b"hello over tor!");

        let blob2 = encrypt_message(&bob_cipher, b"replying").unwrap();
        assert_eq!(decrypt_message(&alice_cipher, &blob2).unwrap(), b"replying");
    }

    #[test]
    fn wrong_party_cannot_decrypt() {
        let (a_static, _) = static_x25519_keypair(&[1u8; 32]);
        let (_, b_static_pub) = static_x25519_keypair(&[2u8; 32]);
        let (evil_static, evil_static_pub) = static_x25519_keypair(&[3u8; 32]);
        let (a_eph, a_eph_pub) = generate_ephemeral();
        let (b_eph, b_eph_pub) = generate_ephemeral();

        let alice_cipher = derive_session_key(a_eph, &b_eph_pub, &a_static, &b_static_pub);
        let evil_cipher = derive_session_key(b_eph, &a_eph_pub, &evil_static, &evil_static_pub);

        let blob = encrypt_message(&alice_cipher, b"confidential").unwrap();
        assert!(decrypt_message(&evil_cipher, &blob).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let (a_static, a_static_pub) = static_x25519_keypair(&[1u8; 32]);
        let (b_static, b_static_pub) = static_x25519_keypair(&[2u8; 32]);
        let (a_eph, a_eph_pub) = generate_ephemeral();
        let (b_eph, b_eph_pub) = generate_ephemeral();

        let alice_cipher = derive_session_key(a_eph, &b_eph_pub, &a_static, &b_static_pub);
        let bob_cipher = derive_session_key(b_eph, &a_eph_pub, &b_static, &a_static_pub);

        let mut blob = encrypt_message(&alice_cipher, b"integrity check").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01; // flip one bit of ciphertext
        assert!(decrypt_message(&bob_cipher, &blob).is_err());
    }

    #[test]
    fn each_message_uses_a_fresh_nonce() {
        let (a_static, _) = static_x25519_keypair(&[1u8; 32]);
        let (_, b_static_pub) = static_x25519_keypair(&[2u8; 32]);
        let (a_eph, _) = generate_ephemeral();
        let (_, b_eph_pub) = generate_ephemeral();
        let cipher = derive_session_key(a_eph, &b_eph_pub, &a_static, &b_static_pub);

        let m1 = encrypt_message(&cipher, b"same text").unwrap();
        let m2 = encrypt_message(&cipher, b"same text").unwrap();
        assert_ne!(m1[..12], m2[..12], "nonces must differ");
    }

    #[test]
    fn ed25519_signature_round_trip_and_verification() {
        let (signing_key, verifying_key) = generate_keypair();
        let message = b"the ephemeral x25519 key bytes";

        let sig = sign_message(&signing_key, message);
        assert!(verify_signature(&verifying_key, message, &sig));

        // Tampered message fails.
        assert!(!verify_signature(&verifying_key, b"tampered", &sig));

        // A different identity's key fails.
        let (_, other_vk) = generate_keypair();
        assert!(!verify_signature(&other_vk, message, &sig));
    }
}