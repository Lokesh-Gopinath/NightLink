//! nite - CLI P2P Messenger
//!
//! Core types and utilities for the nite application:
//! identity (NL-ID), configuration, contacts, and transport mode abstraction.

use std::path::PathBuf;
use serde::{Serialize, Deserialize};

/// Transport mode for connections
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TransportMode {
    Direct,
    Tor,
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportMode::Direct => write!(f, "direct"),
            TransportMode::Tor => write!(f, "tor"),
        }
    }
}

/// A contact in the user's address book
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub nl_id: String,
    pub alias: Option<String>,
    pub direct_address: Option<String>,
    pub tor_address: Option<String>,
}

/// Configuration structure for storing user identity and settings
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub nl_id: String,
    pub display_name: String,
    pub public_key: Vec<u8>,
    pub private_key_encrypted: Vec<u8>,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub listen_port: u16,
    pub transport_mode: TransportMode,
    pub contacts: Vec<Contact>,
}

/// Generate an NL-ID from a public key
pub fn derive_nl_id(public_key: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let hash = hasher.finalize();
    let hex_str = hex::encode(&hash[..12]);
    format!(
        "NL-{}-{}-{}",
        &hex_str[0..4].to_uppercase(),
        &hex_str[4..8].to_uppercase(),
        &hex_str[8..12].to_uppercase()
    )
}

/// Get the configuration directory
pub fn get_config_dir() -> PathBuf {
    directories::ProjectDirs::from("dev", "nite", "nite")
        .expect("Failed to get config directory")
        .config_dir()
        .to_path_buf()
}

/// Get the path to the config file
pub fn get_config_path() -> PathBuf {
    get_config_dir().join("config.toml")
}

/// Get the path to the public key file
pub fn get_public_key_path() -> PathBuf {
    get_config_dir().join("public.key")
}