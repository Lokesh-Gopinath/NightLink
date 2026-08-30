use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::theme::Theme;
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
    #[serde(default)]
    public_key: Option<Vec<u8>>,
}

fn prompt_line(prompt: &str) -> Result<String, Error> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

/// Prompt for a secret, printing `*` for every character typed.
///
/// On Windows the console is switched to raw input read via the Win32 console
/// API so each key press can be echoed as a single `*` (backspace erases the
/// last `*`). On non-Windows platforms `rpassword` reads the secret blindly.
pub fn prompt_masked(prompt: &str) -> Result<String, Error> {
    #[cfg(windows)]
    {
        prompt_masked_windows(prompt)
    }
    #[cfg(not(windows))]
    {
        Ok(rpassword::prompt_password(prompt)?)
    }
}

/// Windows implementation of `prompt_masked` using the raw console API.
#[cfg(windows)]
fn prompt_masked_windows(prompt: &str) -> Result<String, Error> {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, ReadConsoleInputW, SetConsoleMode,
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, INPUT_RECORD, KEY_EVENT, KEY_EVENT_RECORD,
        STD_INPUT_HANDLE,
    };

    print!("{}", prompt);
    io::stdout().flush()?;

    unsafe {
        let handle = GetStdHandle(STD_INPUT_HANDLE);
        // If stdin is redirected (no console), fall back to a plain read.
        let mut mode: u32 = 0;
        if GetConsoleMode(handle, &mut mode) == 0 {
            let _ = mode;
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            return Ok(line.trim_end_matches(['\r', '\n']).to_string());
        }
        let previous = mode;
        // Disable line input + echo so we can render the masked output.
        SetConsoleMode(handle, previous & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));

        let mut passphrase = String::new();
        'input: loop {
            let mut record = std::mem::zeroed::<INPUT_RECORD>();
            let mut num_read: u32 = 0;
            if ReadConsoleInputW(handle, &mut record, 1, &mut num_read) == 0 || num_read == 0 {
                continue;
            }
            if record.EventType as u32 != KEY_EVENT {
                continue;
            }
            let key: KEY_EVENT_RECORD = record.Event.KeyEvent;
            if key.bKeyDown == 0 {
                continue;
            }
            // VK_RETURN = 0x0D, VK_BACK = 0x08
            if key.wVirtualKeyCode == 0x0D {
                break 'input;
            }
            if key.wVirtualKeyCode == 0x08 {
                if !passphrase.is_empty() {
                    passphrase.pop();
                    print!("\x08 \x08");
                    io::stdout().flush()?;
                }
                continue;
            }
            let ch = key.uChar.UnicodeChar;
            if ch != 0 {
                if let Some(c) = char::from_u32(ch as u32) {
                    if !c.is_control() {
                        passphrase.push(c);
                        print!("*");
                        io::stdout().flush()?;
                    }
                }
            }
        }
        SetConsoleMode(handle, previous);
        println!();
        Ok(passphrase)
    }
}

/// True if any contact (other than `except_nl_id`) already uses `alias`,
/// compared case-insensitively.
pub fn alias_taken(config: &Config, alias: &str, except_nl_id: Option<&str>) -> bool {
    let alias_lower = alias.to_lowercase();
    config
        .contacts
        .values()
        .any(|c| Some(c.nl_id.as_str()) != except_nl_id && c.alias.to_lowercase() == alias_lower)
}

/// Remove a contact whose alias matches `alias` (case-insensitive). Returns
/// `true` when a contact was removed, `false` when none matched. Does **not**
/// persist the change — the caller is responsible for `config::save`.
pub fn remove_contact_by_alias(config: &mut Config, alias: &str) -> Result<bool, Error> {
    let alias_lower = alias.to_lowercase();
    let Some(nl_id) = config
        .contacts
        .values()
        .find(|c| c.alias.to_lowercase() == alias_lower)
        .map(|c| c.nl_id.clone())
    else {
        return Ok(false);
    };
    config.contacts.remove(&nl_id);
    Ok(true)
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

    let passphrase = prompt_masked("[nite] Passphrase to encrypt private key: ")?;
    let encrypted_key = crypto::encrypt_private_key(&signing_key.to_bytes(), &passphrase)?;

    let config = Config {
        nl_id,
        display_name,
        private_key_encrypted: encrypted_key,
        public_key: verifying_key.to_bytes().to_vec(),
        tor_address: None,
        contacts: HashMap::new(),
        theme: Theme::default(),
    };

    save(&config)?;
    println!("[nite] Initialization complete");
    Ok(config)
}

pub fn initialize_silent() -> Result<(Config, String), Error> {
    let config_dir = get_config_dir();
    fs::create_dir_all(&config_dir)?;

    let (signing_key, verifying_key) = crypto::generate_keypair();
    let nl_id = format_nl_id(&verifying_key.to_bytes());

    let passphrase = prompt_masked("\nEnter passphrase to encrypt private key: ")?;
    let encrypted_key = crypto::encrypt_private_key(&signing_key.to_bytes(), &passphrase)?;

    let config = Config {
        nl_id,
        display_name: String::new(),
        private_key_encrypted: encrypted_key,
        public_key: verifying_key.to_bytes().to_vec(),
        tor_address: None,
        contacts: HashMap::new(),
        theme: Theme::default(),
    };

    let config_path = get_config_path();
    for _ in 0..3 {
        match fs::write(&config_path, toml::to_string(&config)?) {
            Ok(_) => return Ok((config, passphrase)),
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

    // Try parsing as new format first
    if let Ok(config) = toml::from_str::<Config>(&config) {
        return Ok(config);
    }

    // Try parsing as legacy format
    if let Ok(legacy) = toml::from_str::<LegacyConfig>(&config) {
        let mut contacts = HashMap::new();
        for contact in legacy.contacts {
            contacts.insert(
                contact.nl_id.clone(),
                Contact {
                    nl_id: contact.nl_id.clone(),
                    alias: contact.alias.unwrap_or_else(|| contact.nl_id.clone()),
                    tor_address: contact.tor_address.unwrap_or_default(),
                    public_key: contact.public_key.unwrap_or_default(),
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
            theme: Theme::default(),
        };

        save(&migrated)?;
        println!("[nite] Migrated config to new format");
        return Ok(migrated);
    }

    // If both fail, return a helpful error
    Err(anyhow::anyhow!(
        "Config file is corrupted or in an unsupported format.\n\
        Please delete {} and run 'init' to create a new config.",
        get_config_path().display()
    ))
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

pub fn add_contact(
    config: &mut Config,
    nl_id: String,
    alias: String,
    tor_address: String,
    public_key: Vec<u8>,
) -> Result<(), Error> {
    config.contacts.insert(nl_id.clone(), Contact {
        nl_id: nl_id.clone(),
        alias,
        tor_address,
        public_key,
    });
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> Config {
        Config {
            nl_id: "NL-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG".to_string(),
            display_name: "tester".to_string(),
            private_key_encrypted: vec![1, 2, 3],
            public_key: vec![0u8; 32],
            tor_address: None,
            contacts: HashMap::new(),
            theme: Theme::default(),
        }
    }

    fn contact(nl_id: &str, alias: &str) -> Contact {
        Contact {
            nl_id: nl_id.to_string(),
            alias: alias.to_string(),
            tor_address: "abc123.onion:4444".to_string(),
            public_key: Vec::new(),
        }
    }

    #[test]
    fn alias_taken_is_case_insensitive_and_excludes_excepted_contact() {
        let mut config = sample_config();
        config
            .contacts
            .insert("NL-ONE".to_string(), contact("NL-ONE", "Alice"));

        assert!(alias_taken(&config, "alice", None));
        assert!(alias_taken(&config, "ALICE", None));
        assert!(!alias_taken(&config, "bob", None));
        // Updating Alice herself keeps her alias valid.
        assert!(!alias_taken(&config, "alice", Some("NL-ONE")));
        // The same alias looked at from another contact's perspective is taken.
        assert!(alias_taken(&config, "alice", Some("NL-TWO")));
    }

    #[test]
    fn remove_contact_by_alias_removes_case_insensitively() {
        let mut config = sample_config();
        config
            .contacts
            .insert("NL-ONE".to_string(), contact("NL-ONE", "Alice"));
        config
            .contacts
            .insert("NL-TWO".to_string(), contact("NL-TWO", "Bob"));

        assert!(remove_contact_by_alias(&mut config, "ALICE").unwrap());
        assert_eq!(config.contacts.len(), 1);
        assert!(config.contacts.contains_key("NL-TWO"));

        assert!(!remove_contact_by_alias(&mut config, "Charlie").unwrap());
        assert_eq!(config.contacts.len(), 1);
    }
}