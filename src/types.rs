use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::Mutex as TokioMutex;

use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

pub type NLID = String;
pub type Error = anyhow::Error;

use crate::theme::Theme;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub nl_id: NLID,
    pub display_name: String,
    pub private_key_encrypted: Vec<u8>,
    pub public_key: Vec<u8>,
    pub tor_address: Option<String>,
    pub contacts: HashMap<NLID, Contact>,
    #[serde(default = "Theme::default")]
    pub theme: Theme,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Contact {
    pub nl_id: String,
    pub alias: String,
    pub tor_address: String,
    /// Contact's Ed25519 public key (32 bytes). Empty vec = not provided;
    /// identity is then verified via the NL-ID hash + signature only.
    #[serde(default)]
    pub public_key: Vec<u8>,
}

/// A queued, not-yet-answered connection request.
#[derive(Debug)]
pub struct PendingConnection {
    pub peer_nl_id: String,
    pub peer_alias: String,
    /// `true` = inbound request awaiting accept/reject; `false` = outbound ping.
    pub incoming: bool,
    /// Parked stream so accept/reject can reply on it once decided.
    pub stream: Option<TcpStream>,
    /// Peer's ephemeral X25519 key (inbound requests only).
    pub peer_ephemeral_public: Option<PublicKey>,
    /// Peer's static X25519 identity key (inbound requests only).
    pub peer_static_public: Option<PublicKey>,
    /// Peer's CLAIMED Ed25519 public key (32 bytes) from the CONNECT frame.
    pub peer_ed25519_public: Option<Vec<u8>>,
    /// Ed25519 signature (64 bytes) over the peer's ephemeral X25519 key.
    pub peer_eph_signature: Option<Vec<u8>>,
}

/// An active one-to-one chat session. The write half is shared between the
/// shell (message sending) and the session owner.
pub struct ChatSession {
    pub peer_nl_id: String,
    pub peer_alias: String,
    pub write: Arc<TokioMutex<OwnedWriteHalf>>,
    /// ChaCha20-Poly1305 cipher built from the ECDH session key.
    pub cipher: ChaCha20Poly1305,
    /// Peer's static X25519 identity key (persists across sessions).
    // Kept for reference/debug; session operations use `cipher`.
    #[allow(dead_code)]
    pub peer_static_public: PublicKey,
}

impl std::fmt::Debug for ChatSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatSession")
            .field("peer_nl_id", &self.peer_nl_id)
            .field("peer_alias", &self.peer_alias)
            .finish()
    }
}

/// All identity material derived from the passphrase-unlocked Ed25519 seed.
/// Never serialized; held only for the lifetime of the shell.
pub struct IdentityKeys {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub static_secret: StaticSecret,
    pub static_public: PublicKey,
}

#[derive(Debug)]
pub struct AppState {
    pub current_chat: Option<ChatSession>,          // Active chat session
    pub pending_connections: Vec<PendingConnection>, // Pending connection requests
    pub is_tor_ready: bool,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            current_chat: None,
            pending_connections: Vec::new(),
            is_tor_ready: false,
        }
    }
}

pub fn get_config_dir() -> PathBuf {
    directories::ProjectDirs::from("dev", "nite", "nite")
        .expect("Failed to get config dir")
        .config_dir()
        .to_path_buf()
}

pub fn format_nl_id(public_key: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(public_key);
    let hex_str = hex::encode(&hash[..12]);
    let formatted = hex_str.chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
        .to_uppercase();
    format!("NL-{}", formatted)
}

pub fn get_config_path() -> PathBuf {
    get_config_dir().join("config.toml")
}