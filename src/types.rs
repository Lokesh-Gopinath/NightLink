use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
    pub theme: Theme,  // NEW: Theme support
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Contact {
    pub alias: String,
    pub tor_address: String,
}

#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub pending_connections: HashMap<String, tokio::net::TcpStream>,
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
