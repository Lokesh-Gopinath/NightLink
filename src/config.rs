use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::types::{get_config_dir, get_config_path, Config, Contact, Error, format_nl_id};

/// Legacy config format for backward compatibility
#[derive(Debug, Serialize, Deserialize)]
struct LegacyConfig {
    nl_id: String,
    display_name: String,
    private_key_encrypted: Vec<u8>,
    public_key: Vec<u8>,
    salt: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    tor_address: Option<String>,
    listen_port: Option<u16>,
    transport_mode: Option<String>,
    contacts: Vec<LegacyContact>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LegacyContact {
    nl_id: String,
    alias: Option<String>,
    tor_address: Option<String>,
}

fn prompt_line(prompt: &str) -> Result<String, Error> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub fn initialize() -> Result<Config, Error> {
    let config_dir = get_config_dir();
    fs::create_dir_all(&config_dir)?;

    let (signing_key, verifying_key) = crypto::generate_keypair();
    let nl_id = format_nl_id(&verifying_key.to_bytes());

    println!("[nite] First run setup");
    println!("[nite] Your NightLink ID: {}", nl_id);

    let display_name = prompt_line("[nite] Display name (default: anonymous): ")?;
    let display_name = if display_name.is_empty() {
        "anonymous".to_string()
    } else {
        display_name
    };

    let passphrase = rpassword::prompt_password("[nite] Passphrase to encrypt private key: ")?;
    let encrypted_key = crypto::encrypt_private_key(&signing_key.to_bytes(), &passphrase)?;

    let config = Config {
        nl_id,
        display_name,
        private_key_encrypted: encrypted_key,
        public_key: verifying_key.to_bytes().to_vec(),
        tor_address: None,
        contacts: HashMap::new(),
    };

    save(&config)?;
    println!("[nite] Initialization complete");
    Ok(config)
}

pub fn initialize_silent() -> Result<Config, Error> {
    let config_dir = get_config_dir();
    fs::create_dir_all(&config_dir)?;

    let (signing_key, verifying_key) = crypto::generate_keypair();
    let nl_id = format_nl_id(&verifying_key.to_bytes());

    let passphrase = rpassword::prompt_password("\nEnter passphrase to encrypt private key: ")?;
    let encrypted_key = crypto::encrypt_private_key(&signing_key.to_bytes(), &passphrase)?;

    let config = Config {
        nl_id,
        display_name: "anonymous".to_string(),
        private_key_encrypted: encrypted_key,
        public_key: verifying_key.to_bytes().to_vec(),
        tor_address: None,
        contacts: HashMap::new(),
    };

    let config_path = get_config_path();
    for _ in 0..3 {
        match fs::write(&config_path, toml::to_string(&config)?) {
            Ok(_) => return Ok(config),
            Err(e) if e.to_string().contains("being used by another process") => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(anyhow::anyhow!("Config file is locked. Close other nite.exe instances."))
}

pub fn reinitialize() -> Result<Config, Error> {
    let config_dir = get_config_dir();
    if config_dir.exists() {
        fs::remove_dir_all(&config_dir)?;
    }
    initialize()
}

pub fn load() -> Result<Config, Error> {
    let config = fs::read_to_string(get_config_path())?;

    if let Ok(config) = toml::from_str::<Config>(&config) {
        return Ok(config);
    }

    let legacy: LegacyConfig = toml::from_str(&config)?;
    let mut contacts = HashMap::new();
    for contact in legacy.contacts {
        contacts.insert(
            contact.nl_id.clone(),
            Contact {
                alias: contact.alias.unwrap_or_else(|| contact.nl_id.clone()),
                tor_address: contact.tor_address.unwrap_or_default(),
            },
        );
    }

    let private_key_encrypted = if let (Some(salt), Some(nonce)) = (&legacy.salt, &legacy.nonce) {
        let mut blob = Vec::with_capacity(salt.len() + nonce.len() + legacy.private_key_encrypted.len());
        blob.extend_from_slice(salt);
        blob.extend_from_slice(nonce);
        blob.extend_from_slice(&legacy.private_key_encrypted);
        blob
    } else {
        legacy.private_key_encrypted
    };

    let migrated = Config {
        nl_id: legacy.nl_id,
        display_name: legacy.display_name,
        private_key_encrypted,
        public_key: legacy.public_key,
        tor_address: legacy.tor_address,
        contacts,
    };

    save(&migrated)?;
    println!("[nite] Migrated config to new format");
    Ok(migrated)
}

pub fn save(config: &Config) -> Result<(), Error> {
    fs::create_dir_all(get_config_dir())?;
    fs::write(get_config_path(), toml::to_string(config)?)?;
    Ok(())
}

pub fn print_fingerprint(config: &Config) -> Result<(), Error> {
    let fingerprint = config
        .public_key
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");
    println!("[nite] NightLink ID: {}", config.nl_id);
    println!("[nite] Display name: {}", config.display_name);
    println!("[nite] Fingerprint: {}", fingerprint);
    println!("[nite] Transport: tor");
    if let Some(addr) = &config.tor_address {
        println!("[nite] Tor address: {}", addr);
    }
    Ok(())
}

pub fn add_contact(config: &mut Config, nl_id: String, alias: String, tor_address: String) -> Result<(), Error> {
    config.contacts.insert(nl_id.clone(), Contact { alias, tor_address });
    save(config)?;
    println!("[nite] Contact saved: {}", nl_id);
    Ok(())
}

pub fn list_contacts(config: &Config) {
    if config.contacts.is_empty() {
        println!("[nite] No contacts");
        return;
    }

    println!("[nite] Contacts:");
    for (nl_id, contact) in &config.contacts {
        println!("[nite]   {} ({}) -> {}", contact.alias, nl_id, contact.tor_address);
    }
}

pub fn get_alias_for_nl_id(config: &Config, nl_id: &str) -> Option<String> {
    config
        .contacts
        .get(nl_id)
        .map(|contact| contact.alias.clone())
}