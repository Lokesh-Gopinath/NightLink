//! Configuration management for nite

use crate::types::{get_config_dir, get_config_path, get_public_key_path, Config, Contact, TransportMode, derive_nl_id};
use std::fs;

pub fn initialize(transport: TransportMode) -> Result<Config, anyhow::Error> {
    let config_dir = get_config_dir();
    fs::create_dir_all(&config_dir)?;

    let signing_key = crate::crypto::generate_keypair();
    let verifying_key = signing_key.verifying_key();
    let nl_id = derive_nl_id(&verifying_key.to_bytes());

    println!("[nite] First run initialization");
    println!("[nite] Your NightLink ID: {}", nl_id);
    println!("[nite] Enter display name (default: anonymous):");

    let mut display_name = String::new();
    std::io::stdin().read_line(&mut display_name)?;
    let display_name = display_name.trim().to_string();
    let display_name = if display_name.is_empty() { "anonymous".to_string() } else { display_name };

    let passphrase = rpassword::prompt_password("[nite] Enter passphrase to encrypt private key: ")?;
    let (encrypted_key, salt, nonce) = crate::crypto::encrypt_private_key(&signing_key.to_bytes(), &passphrase)?;

    let config = Config {
        nl_id,
        display_name,
        public_key: verifying_key.to_bytes().to_vec(),
        private_key_encrypted: encrypted_key,
        salt,
        nonce,
        listen_port: 4444,
        transport_mode: transport,
        contacts: Vec::new(),
    };

    let config_path = get_config_path();
    fs::write(&config_path, toml::to_string(&config)?)?;
    fs::write(get_public_key_path(), &config.public_key)?;

    println!("[nite] Initialization complete");
    println!("[nite] Config saved to: {}", config_path.display());

    if transport == TransportMode::Direct {
        println!("[nite] Direct mode: listening on port {}", config.listen_port);
    } else {
        println!("[nite] Tor mode requires a running Tor daemon on localhost:9050");
        println!("[nite] Use 'nite serve' to start listening for connections");
    }

    Ok(config)
}

pub fn reinitialize(transport: TransportMode) -> Result<Config, anyhow::Error> {
    let config_dir = get_config_dir();
    if config_dir.exists() {
        fs::remove_dir_all(&config_dir)?;
    }
    initialize(transport)
}

pub fn load() -> Result<Config, anyhow::Error> {
    let config_path = get_config_path();
    let config_str = fs::read_to_string(&config_path)?;
    let config: Config = toml::from_str(&config_str)?;
    Ok(config)
}

pub fn print_fingerprint() -> Result<(), anyhow::Error> {
    let config = load()?;
    let fingerprint: String = config.public_key[..8]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");
    println!("[nite] NightLink ID: {}", config.nl_id);
    println!("[nite] Display name: {}", config.display_name);
    println!("[nite] Fingerprint: {}", fingerprint);
    println!("[nite] Transport: {}", config.transport_mode);
    Ok(())
}

pub fn add_contact(nl_id: &str, alias: Option<&str>, direct_addr: Option<&str>, tor_addr: Option<&str>) -> Result<(), anyhow::Error> {
    let mut config = load()?;
    if config.contacts.iter().any(|c| c.nl_id == nl_id) {
        return Err(anyhow::anyhow!("Contact with NL-ID {} already exists", nl_id));
    }
    let contact = Contact {
        nl_id: nl_id.to_string(),
        alias: alias.map(|s| s.to_string()),
        direct_address: direct_addr.map(|s| s.to_string()),
        tor_address: tor_addr.map(|s| s.to_string()),
    };
    config.contacts.push(contact);
    save(&config)?;
    println!("[nite] Contact added: {}", nl_id);
    Ok(())
}

pub fn list_contacts() -> Result<(), anyhow::Error> {
    let config = load()?;
    if config.contacts.is_empty() {
        println!("[nite] No contacts saved");
        return Ok(());
    }
    println!("[nite] Contacts:");
    for contact in &config.contacts {
        let alias = contact.alias.as_deref().unwrap_or("-");
        let direct = contact.direct_address.as_deref().unwrap_or("-");
        let tor = contact.tor_address.as_deref().unwrap_or("-");
        println!("  {} | alias: {} | direct: {} | tor: {}", contact.nl_id, alias, direct, tor);
    }
    Ok(())
}

pub fn resolve_contact(identifier: &str, transport: TransportMode) -> Result<(String, String), anyhow::Error> {
    let config = load()?;
    let contact = config.contacts.iter().find(|c| {
        c.nl_id == identifier || c.alias.as_deref() == Some(identifier)
    });
    match contact {
        Some(c) => {
            let addr = match transport {
                TransportMode::Direct => c.direct_address.clone()
                    .ok_or_else(|| anyhow::anyhow!("Contact {} has no direct address", c.nl_id))?,
                TransportMode::Tor => c.tor_address.clone()
                    .ok_or_else(|| anyhow::anyhow!("Contact {} has no Tor address", c.nl_id))?,
            };
            Ok((c.nl_id.clone(), addr))
        }
        None => Ok(("remote".to_string(), identifier.to_string())),
    }
}

pub fn save(config: &Config) -> Result<(), anyhow::Error> {
    let config_path = get_config_path();
    fs::write(config_path, toml::to_string(config)?)?;
    Ok(())
}