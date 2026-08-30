use std::io::{self, Write};
use std::sync::Arc;
use std::process::Command;
use clap::{Parser, Subcommand};
use tokio::sync::Mutex;
use ed25519_dalek::SigningKey;

mod types;
mod config;
mod crypto;
mod theme;
mod tor;
mod chat;

use types::{AppState, Contact};

/// Clear terminal
fn clear_terminal() {
    #[cfg(windows)]
    {
        let _ = Command::new("cmd").args(["/C", "cls"]).status();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("clear").status();
    }
}


/// Pause and exit
fn pause_and_exit(code: i32) -> ! {
    println!("\nPress ENTER to exit...");
    let _ = io::stdin().read_line(&mut String::new());
    std::process::exit(code);
}

/// Load config or initialize (SILENTLY). Returns the config and, when a fresh
/// config was just created, the passphrase used for it (so we don't ask twice).
fn load_or_init_config() -> Result<(types::Config, Option<String>), anyhow::Error> {
    let config_path = types::get_config_path();
    if config_path.exists() {
        for _ in 0..3 {
            match config::load() {
                Ok(c) => return Ok((c, None)),
                Err(e) if e.to_string().contains("being used by another process") => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(e) => return Err(e),
            }
        }
        return Err(anyhow::anyhow!("Config file is locked. Close other instances."));
    } else {
        match config::initialize_silent() {
            Ok((c, pass)) => Ok((c, Some(pass))),
            Err(e) => Err(e),
        }
    }
}

/// Prompt for the passphrase and derive the static X25519 identity keypair.
/// On a fresh install the passphrase was just chosen, so it is reused and the
/// user is not prompted twice.
fn unlock_identity(
    config: &types::Config,
    first_run_passphrase: &mut Option<String>,
) -> Result<types::IdentityKeys, anyhow::Error> {
    let mut attempts = 0u8;
    loop {
        let passphrase = match first_run_passphrase.take() {
            Some(p) => p,
            None => config::prompt_masked("[nite] Enter your passphrase to unlock your identity: ")?,
        };
        match crypto::decrypt_private_key(&config.private_key_encrypted, &passphrase) {
            Ok(seed) => {
                if seed.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "Decrypted identity seed has an unexpected length"
                    ));
                }
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&seed);
                let signing_key = SigningKey::from_bytes(&bytes);
                let verifying_key = signing_key.verifying_key();
                let (static_secret, static_public) = crypto::static_x25519_keypair(&bytes);
                return Ok(types::IdentityKeys {
                    signing_key,
                    verifying_key,
                    static_secret,
                    static_public,
                });
            }
            Err(_) => {
                attempts += 1;
                if attempts >= 3 {
                    return Err(anyhow::anyhow!(
                        "Invalid passphrase after 3 attempts. Restart NightLink."
                    ));
                }
                println!("[nite] Incorrect passphrase. Try again.");
            }
        }
    }
}

/// Get command suggestion for unknown commands
fn get_suggestion(input: &str, commands: &[&str]) -> Option<String> {
    commands.iter()
        .find(|&&cmd| cmd.starts_with(input))
        .map(|&s| s.to_string())
}

/// Validate a display name: 1-32 characters, restricted to letters, numbers,
/// spaces, hyphens and underscores.
fn validate_display_name(name: &str) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("display name cannot be empty.".to_string());
    }
    if trimmed.chars().count() > 32 {
        return Err("display name must be at most 32 characters.".to_string());
    }
    let valid = trimmed
        .chars()
        .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_');
    if !valid {
        return Err(
            "only letters, numbers, spaces, hyphens and underscores are allowed.".to_string(),
        );
    }
    Ok(())
}

#[derive(Parser)]
#[command(name = "nite")]
#[command(about = "Tor-only P2P encrypted chat", long_about = None)]
#[command(disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Fingerprint,
    /// Nested contact commands
    Contact {
        #[command(subcommand)]
        command: ContactCommands,
    },
    /// Flat alternative: contact-add
    #[command(name = "contact-add")]
    ContactAdd {
        nl_id: String,
        alias: String,
        tor_address: String,
        /// Optional Ed25519 public key (hex) for identity verification.
        #[arg(long, value_name = "HEX")]
        public_key: Option<String>,
    },
    /// Flat alternative: contact-list
    #[command(name = "contact-list")]
    ContactList,
    /// Flat alternative: delete a contact without the `contact` prefix
    #[command(name = "del", alias = "rm")]
    DeleteContact { alias: String },
    Ping { target: String },
    Pending,
    Accept { alias: String },
    Reject { alias: String },
    /// Change your display name
    #[command(name = "set-display-name", alias = "set-name")]
    SetDisplayName {
        /// New display name (1-32 chars: letters, numbers, spaces, hyphens, underscores)
        name: String,
    },
    Theme { name: String },
    Help,
    Exit,
}

#[derive(Subcommand)]
enum ContactCommands {
    Add {
        nl_id: String,
        alias: String,
        tor_address: String,
        /// Optional Ed25519 public key (hex) for identity verification.
        #[arg(long, value_name = "HEX")]
        public_key: Option<String>,
    },
    /// Delete a contact by alias
    #[command(alias = "remove")]
    Delete { alias: String },
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("\n[nite] FATAL ERROR: {}", panic_info);
        pause_and_exit(1);
    }));

    #[cfg(debug_assertions)]
    {
        use tracing_subscriber::{fmt, EnvFilter};
        fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
    }

    // ===== PHASE 1: Start Tor + Hidden Service =====
    println!("[nite] Starting Tor daemon and hidden service...");
    let (_hs_dir, onion_addr) = match tor::start_tor_daemon() {
        Ok((dir, addr)) => {
            println!("[nite] Your .onion address: {}", addr);
            (dir, addr)
        },
        Err(e) => {
            eprintln!("[nite] Error: Failed to start Tor: {}", e);
            eprintln!("[nite] Error: Tor failed to start. Check your connection/firewall or restart the application.");
            pause_and_exit(1);
        }
    };

    // ===== PHASE 2: Wait for Bootstrap =====
    println!("[nite] Tor is bootstrapping... (may take up to 10 minutes)");
    if let Err(e) = tor::wait_for_full_bootstrap().await {
        eprintln!("[nite] Error: Failed to start Tor. Check your network/firewall or restart the application.");
        eprintln!("[nite] Details: {}", e);
        pause_and_exit(1);
    }

    // ===== PHASE 3: Clear + Show UI =====
    clear_terminal();

    // ===== PHASE 4: Load/Init Config + Save Onion Address =====
    let (mut config, mut first_run_passphrase) = match load_or_init_config() {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("[nite] Error: Config corrupted. Reset? (y/n)");
            let mut choice = String::new();
            io::stdin().read_line(&mut choice)?;
            if choice.trim().to_lowercase() == "y" {
                let config_dir = types::get_config_dir();
                let _ = std::fs::remove_dir_all(&config_dir);
                let (cfg, pass) = config::initialize_silent()?;
                (cfg, Some(pass))
            } else {
                eprintln!("[nite] Error: {}", e);
                pause_and_exit(1);
            }
        }
    };
    config.tor_address = Some(format!("{}:4444", onion_addr));
    config::save(&config)?;

    // ===== PHASE 4.5: Unlock identity with the passphrase =====
    let identity = unlock_identity(&config, &mut first_run_passphrase)?;

    // Apply theme and show ASCII art
    config.theme.apply();
    println!("{}", config.theme.ascii_art());

    // ===== PHASE 5: Start Listener =====
    let state = Arc::new(Mutex::new(AppState::new()));

    tokio::spawn({
        let state = state.clone();
        async move {
            if let Err(e) = chat::start_listener(state).await {
                eprintln!("[nite] Listener error: {}", e);
            }
        }
    });
    // Printed synchronously so it appears on its own line, never glued to the
    // shell prompt that start_shell prints next.
    println!("[nite] Listening for connections on {}...", chat::LISTEN_ADDR);

    // ===== First-run display name prompt =====
    // Only shown when the stored display name is empty (fresh identity).
    if config.display_name.is_empty() {
        print!("[nite] Enter your display name: ");
        io::stdout().flush()?;
        let mut name = String::new();
        io::stdin().read_line(&mut name)?;
        let name = name.trim().to_string();

        if name.is_empty() {
            config.display_name = "User".to_string();
            println!("[nite] Using default display name: User");
        } else if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_')
        {
            config.display_name = "User".to_string();
            println!("[nite] Invalid characters. Using default display name: User");
        } else if name.len() > 32 {
            config.display_name = name[..32].to_string();
            println!("[nite] Display name truncated to 32 characters");
        } else {
            config.display_name = name;
        }

        config::save(&config)?;
    }

    // ===== PHASE 6: Interactive Shell =====
    start_shell(config, state, identity).await?;

    Ok(())
}

/// Read one completed line through the stdin worker. Must only be called while
/// the worker is idle (i.e. between the shell's own line requests), so modal
/// prompts like `(y/n)` can safely read a line without racing the shell.
fn stdin_read_line(
    want_tx: &std::sync::mpsc::Sender<()>,
    got_rx: &std::sync::mpsc::Receiver<String>,
) -> anyhow::Result<String> {
    want_tx.send(())?;
    got_rx.recv().map_err(|_| anyhow::anyhow!("stdin closed"))
}

/// Start interactive shell.
///
/// Input is read by a small worker thread that only reads a line when asked:
/// the shell requests one line at a time, so modal inputs (passphrase, y/n
/// prompts) that talk to the console directly never race with the worker.
/// While waiting for a line the shell polls the chat state so an accepted
/// connection switches the prompt to the chat prompt immediately, without the
/// user having to press an extra Enter.
#[allow(clippy::too_many_arguments)]
async fn start_shell(
    mut config: types::Config,
    state: Arc<Mutex<AppState>>,
    mut identity: types::IdentityKeys,
) -> anyhow::Result<()> {
    // ---- stdin worker: one line per request ----
    let (want_tx, want_rx) = std::sync::mpsc::channel::<()>();
    let (got_tx, got_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let stdin = io::stdin();
        while want_rx.recv().is_ok() {
            let mut line = String::new();
            match stdin.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if got_tx.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Whether the UI currently shows a chat prompt (for transition redraws).
    let mut in_chat = false;
    // Whether the current prompt line is already on screen.
    let mut prompt_drawn = false;

    loop {
        // Current chat partner (None = main prompt).
        let chat_with = {
            let state_guard = state.lock().await;
            state_guard
                .current_chat
                .as_ref()
                .map(|session| session.peer_alias.clone())
        };
        let now_in_chat = chat_with.is_some();

        // ---- draw / re-draw the right prompt when the state changed ----
        if now_in_chat != in_chat {
            in_chat = now_in_chat;
            if let Some(alias) = &chat_with {
                let p = format!("[nite~{}]: ", alias);
                // If a background task already drew the chat prompt (and
                // bumped LAST_PROMPT), don't print a second one.
                let already = types::LAST_PROMPT.lock().map(|lp| *lp == p).unwrap_or(false);
                if !already {
                    print!("{}", p);
                    io::stdout().flush()?;
                    if let Ok(mut lp) = types::LAST_PROMPT.lock() {
                        *lp = p;
                    }
                }
                prompt_drawn = true;
            } else {
                let p = config.theme.prompt();
                print!("{}", p);
                io::stdout().flush()?;
                if let Ok(mut lp) = types::LAST_PROMPT.lock() {
                    *lp = p;
                }
                prompt_drawn = true;
            }
        } else if !prompt_drawn {
            let p = if let Some(alias) = &chat_with {
                format!("[nite~{}]: ", alias)
            } else {
                config.theme.prompt()
            };
            print!("{}", p);
            io::stdout().flush()?;
            if let Ok(mut lp) = types::LAST_PROMPT.lock() {
                *lp = p;
            }
            prompt_drawn = true;
        }

        // ---- request one line; poll chat state while waiting ----
        if want_tx.send(()).is_err() {
            break; // stdin closed
        }
        let line = match got_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(line) => line,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break, // stdin closed
        };
        prompt_drawn = false;

        let input = line.trim().to_string();
        if input.is_empty() {
            continue;
        }

        // Check for chat exit commands
        if input == "/exit" || input == "/back" {
            chat::leave_chat(state.clone()).await;
            continue;
        }

        // If in chat mode, send the input as a network message
        if now_in_chat {
            if let Err(e) = chat::send_message(state.clone(), &input).await {
                println!("{}", config.theme.error(&format!("Failed to send: {}. Connection may be lost.", e)));
                let mut state_guard = state.lock().await;
                state_guard.current_chat = None;
            }
            continue;
        }

        // Parse command
        let args = std::iter::once("nite").chain(input.split_whitespace());
        let cli = match Cli::try_parse_from(args) {
            Ok(cli) => cli,
            Err(e) => {
                let suggestions = ["init", "fingerprint", "contact add", "contact list", "ping", "pending", "accept", "reject", "help", "exit"];
                if let Some(suggestion) = get_suggestion(&input, &suggestions) {
                    println!("{}", config.theme.error(&format!("Unknown command. Did you mean '{}'?", suggestion)));
                } else {
                    println!("{}", config.theme.error(&e.to_string()));
                }
                continue;
            }
        };

        match cli.command {
            Some(Commands::Init) => {
                let (new_config, passphrase) = config::initialize_silent()?;
                println!("{}", config.theme.log(&format!("Re-initialized. Your NL-ID: {}", new_config.nl_id)));
                // Re-derive the static identity keys for the new identity.
                if let Ok(seed) = crypto::decrypt_private_key(&new_config.private_key_encrypted, &passphrase) {
                    if seed.len() == 32 {
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&seed);
                        let signing_key = SigningKey::from_bytes(&bytes);
                        let verifying_key = signing_key.verifying_key();
                        let (s, p) = crypto::static_x25519_keypair(&bytes);
                        identity = types::IdentityKeys {
                            signing_key,
                            verifying_key,
                            static_secret: s,
                            static_public: p,
                        };
                    }
                }
                config = new_config;
                config::save(&config)?;
            }

            Some(Commands::Fingerprint) => {
                println!("{}", config.theme.log(&format!("NightLink ID: {}", config.nl_id)));
                println!("{}", config.theme.log(&format!("Display name: {}", config.display_name)));
                let fingerprint = hex::encode(&config.public_key[..8]);
                println!("{}", config.theme.log(&format!("Fingerprint: {}", fingerprint)));
                println!("{}", config.theme.log("Transport: tor"));

                if let Some(addr) = &config.tor_address {
                    println!("{}", config.theme.log(&format!("Tor address: {}", addr)));
                } else {
                    let hs_dir = types::get_config_dir().join("tor/hidden_service/hostname");
                    if hs_dir.exists() {
                        if let Ok(onion_addr) = std::fs::read_to_string(&hs_dir) {
                            config.tor_address = Some(format!("{}:4444", onion_addr.trim()));
                            config::save(&config)?;
                            println!("{}", config.theme.log(&format!("Tor address: {}", config.tor_address.as_ref().unwrap())));
                        } else {
                            println!("{}", config.theme.log("Tor address: Generating... (may take upto 5 mins on first run)"));
                        }
                    } else {
                        println!("{}", config.theme.log("Tor address: Starting hidden service..."));
                    }
                }
            }

            Some(Commands::Contact { command }) => {
                match command {
                    ContactCommands::Add { nl_id, alias, tor_address, public_key } => {
                        // Validate NL-ID format
                        if !nl_id.starts_with("NL-") || nl_id.split('-').count() != 7 {
                            println!("{}", config.theme.error("Invalid NL-ID format. Use NL-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"));
                            continue;
                        }

                        let nl_id = nl_id.to_uppercase();

                        // Optional contact public key for identity verification.
                        let public_key_bytes = match public_key {
                            Some(pk_hex) => match hex::decode(&pk_hex) {
                                Ok(bytes) if bytes.len() == 32 => bytes,
                                Ok(_) => {
                                    println!("{}", config.theme.error("Public key must be 32 bytes (Ed25519)"));
                                    continue;
                                }
                                Err(_) => {
                                    println!("{}", config.theme.error("Public key is not valid hex"));
                                    continue;
                                }
                            },
                            None => {
                                println!("{}", config.theme.log("Note: no public key provided; identity will be verified via NL-ID hash + Ed25519 signature."));
                                Vec::new()
                            }
                        };

                        // Check if adding self
                        if nl_id == config.nl_id {
                            println!("{}", config.theme.error("Cannot add yourself."));
                            continue;
                        }

                        // Reject duplicate aliases (case-insensitive) on another contact.
                        if config::alias_taken(&config, &alias, Some(&nl_id)) {
                            println!("{}", config.theme.error(&format!("A contact with alias '{}' already exists", alias)));
                            continue;
                        }

                        // Check if contact already exists
                        if config.contacts.contains_key(&nl_id) {
                            println!("{}", config.theme.error(&format!("{} already exists. Update? (y/n)", alias)));
                            let choice = stdin_read_line(&want_tx, &got_rx)?;
                            if choice.trim().to_lowercase() != "y" {
                                continue;
                            }
                            if let Some(contact) = config.contacts.get_mut(&nl_id) {
                                contact.alias = alias.clone();
                                contact.tor_address = tor_address.clone();
                                if !public_key_bytes.is_empty() {
                                    contact.public_key = public_key_bytes.clone();
                                }
                            }
                        } else {
                            config.contacts.insert(nl_id.clone(), Contact {
                                nl_id: nl_id.clone(),
                                alias: alias.clone(),
                                tor_address: tor_address.clone(),
                                public_key: public_key_bytes,
                            });
                        }

                        // Validate Tor address
                        if !tor_address.ends_with(".onion:4444") && !tor_address.ends_with(".onion") {
                            println!("{}", config.theme.error(&format!("Warning: {} is not a .onion address. Insecure!", tor_address)));
                        }

                        config::save(&config)?;
                        println!("{}", config.theme.log(&format!("Contact added: {} ({})", alias, nl_id)));
                    }
                    ContactCommands::List => {
                        if config.contacts.is_empty() {
                            println!("{}", config.theme.log("No contacts added yet."));
                        } else {
                            println!("{}", config.theme.log("Contacts:"));
                            for (_, contact) in &config.contacts {
                                println!("{}", config.theme.log(&format!("  {} ({}) -> {}", contact.alias, contact.nl_id, contact.tor_address)));
                            }
                        }
                    }
                    ContactCommands::Delete { alias } => {
                        print!("{}", config.theme.log(&format!("Are you sure you want to delete {}? (y/n): ", alias)));
                        io::stdout().flush()?;
                        let choice = stdin_read_line(&want_tx, &got_rx)?;
                        if choice.trim().to_lowercase() != "y" {
                            continue;
                        }
                        match config::remove_contact_by_alias(&mut config, &alias) {
                            Ok(true) => {
                                config::save(&config)?;
                                println!("{}", config.theme.log(&format!("Contact {} deleted", alias)));
                            }
                            Ok(false) => {
                                println!("{}", config.theme.error(&format!("Contact {} not found", alias)));
                            }
                            Err(e) => println!("{}", config.theme.error(&format!("{}", e))),
                        }
                    }
                }
            }

            Some(Commands::ContactAdd { nl_id, alias, tor_address, public_key }) => {
                // Validate NL-ID format
                if !nl_id.starts_with("NL-") || nl_id.split('-').count() != 7 {
                    println!("{}", config.theme.error("Invalid NL-ID format. Use NL-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"));
                    continue;
                }

                let nl_id = nl_id.to_uppercase();

                // Optional contact public key for identity verification.
                let public_key_bytes = match public_key {
                    Some(pk_hex) => match hex::decode(&pk_hex) {
                        Ok(bytes) if bytes.len() == 32 => bytes,
                        Ok(_) => {
                            println!("{}", config.theme.error("Public key must be 32 bytes (Ed25519)"));
                            continue;
                        }
                        Err(_) => {
                            println!("{}", config.theme.error("Public key is not valid hex"));
                            continue;
                        }
                    },
                    None => {
                        println!("{}", config.theme.log("Note: no public key provided; identity will be verified via NL-ID hash + Ed25519 signature."));
                        Vec::new()
                    }
                };

                // Check if adding self
                if nl_id == config.nl_id {
                    println!("{}", config.theme.error("Cannot add yourself."));
                    continue;
                }

                // Reject duplicate aliases (case-insensitive) on another contact.
                if config::alias_taken(&config, &alias, Some(&nl_id)) {
                    println!("{}", config.theme.error(&format!("A contact with alias '{}' already exists", alias)));
                    continue;
                }

                // Check if contact already exists
                if config.contacts.contains_key(&nl_id) {
                    println!("{}", config.theme.error(&format!("{} already exists. Update? (y/n)", alias)));
                    let choice = stdin_read_line(&want_tx, &got_rx)?;
                    if choice.trim().to_lowercase() != "y" {
                        continue;
                    }
                    if let Some(contact) = config.contacts.get_mut(&nl_id) {
                        contact.alias = alias.clone();
                        contact.tor_address = tor_address.clone();
                        if !public_key_bytes.is_empty() {
                            contact.public_key = public_key_bytes.clone();
                        }
                    }
                } else {
                    config.contacts.insert(nl_id.clone(), Contact {
                        nl_id: nl_id.clone(),
                        alias: alias.clone(),
                        tor_address: tor_address.clone(),
                        public_key: public_key_bytes,
                    });
                }

                // Validate Tor address
                if !tor_address.ends_with(".onion:4444") && !tor_address.ends_with(".onion") {
                    println!("{}", config.theme.error(&format!("Warning: {} is not a .onion address. Insecure!", tor_address)));
                }

                config::save(&config)?;
                println!("{}", config.theme.log(&format!("Contact added: {} ({})", alias, nl_id)));
            }

            Some(Commands::ContactList) => {
                if config.contacts.is_empty() {
                    println!("{}", config.theme.log("No contacts added yet."));
                } else {
                    println!("{}", config.theme.log("Contacts:"));
                    for (_, contact) in &config.contacts {
                        println!("{}", config.theme.log(&format!("  {} ({}) -> {}", contact.alias, contact.nl_id, contact.tor_address)));
                    }
                }
            }

            Some(Commands::DeleteContact { alias }) => {
                print!("{}", config.theme.log(&format!("Are you sure you want to delete {}? (y/n): ", alias)));
                io::stdout().flush()?;
                let choice_status = stdin_read_line(&want_tx, &got_rx);
                match choice_status {
                    Ok(choice) => {
                        if choice.trim().to_lowercase() != "y" {
                            continue;
                        }
                    }
                    Err(e) => {
                        println!("{}", config.theme.error(&format!("{}", e)));
                        continue;
                    }
                }
                match config::remove_contact_by_alias(&mut config, &alias) {
                    Ok(true) => {
                        config::save(&config)?;
                        println!("{}", config.theme.log(&format!("Contact {} deleted", alias)));
                    }
                    Ok(false) => {
                        println!("{}", config.theme.error(&format!("Contact {} not found", alias)));
                    }
                    Err(e) => println!("{}", config.theme.error(&format!("{}", e))),
                }
            }

            Some(Commands::Ping { target }) => {
                // Check if already in a chat
                {
                    let state_guard = state.lock().await;
                    if let Some(session) = &state_guard.current_chat {
                        println!("{}", config.theme.log(&format!(
                            "{} wants to connect (currently chatting with {}). Leave that chat first.",
                            target, session.peer_alias
                        )));
                        continue;
                    }
                }

                // Check if trying to ping self
                if target == config.nl_id || target.to_uppercase() == config.nl_id {
                    println!("{}", config.theme.error("Cannot chat with yourself."));
                    continue;
                }

                // Find contact by alias or NL-ID
                let contact = config.contacts.values().find(|c|
                    c.alias.eq_ignore_ascii_case(&target) || c.nl_id.eq_ignore_ascii_case(&target)
                );

                match contact {
                    Some(contact) => {
                        println!("{}", config.theme.log(&format!("Connecting to {}...", contact.alias)));
                        match chat::send_connection_request(state.clone(), &config, contact, &identity).await {
                            Ok(()) => println!("{}", config.theme.log(&format!(
                                "Connection request sent to {}. Waiting for acceptance (see 'pending').",
                                contact.alias
                            ))),
                            Err(e) => println!("{}", config.theme.error(&format!(
                                "Could not connect to {}: {}", contact.alias, e
                            ))),
                        }
                    }
                    None => {
                        println!("{}", config.theme.error(&format!("Unknown contact or NL-ID: {}", target)));
                    }
                }
            }

            Some(Commands::Pending) => {
                let state_guard = state.lock().await;
                if state_guard.pending_connections.is_empty() {
                    println!("{}", config.theme.log("No pending connections"));
                } else {
                    println!("{}", config.theme.log("Pending connection requests:"));
                    for pending in &state_guard.pending_connections {
                        let direction = if pending.incoming { "incoming" } else { "outgoing" };
                        println!("{}", config.theme.log(&format!(
                            "  [{}] {} ({})", direction, pending.peer_alias, pending.peer_nl_id
                        )));
                    }
                }
            }

            Some(Commands::Accept { alias }) => {
                match chat::accept_pending(state.clone(), &config, &alias, &identity).await {
                    Ok(()) => {}
                    Err(e) => println!("{}", config.theme.error(&format!("{}", e))),
                }
            }

            Some(Commands::Reject { alias }) => {
                match chat::reject_pending(state.clone(), &alias).await {
                    Ok(()) => println!("{}", config.theme.log(&format!("Rejected connection from {}", alias))),
                    Err(e) => println!("{}", config.theme.error(&format!("{}", e))),
                }
            }

                        Some(Commands::SetDisplayName { name }) => {
                match validate_display_name(&name) {
                    Ok(()) => {
                        config.display_name = name.trim().to_string();
                        config::save(&config)?;
                        println!(
                            "{}",
                            config.theme.log(&format!(
                                "Display name updated to: {}",
                                config.display_name
                            ))
                        );
                    }
                    Err(msg) => {
                        println!("{}", config.theme.error(&format!("Invalid display name: {}", msg)));
                    }
                }
            }

            Some(Commands::Theme { name }) => {
                config.theme = match name.as_str() {
                    "default" => theme::Theme::Default,
                    "matrix" => theme::Theme::Matrix,
                    "nord" => theme::Theme::Nord,
                    "dracula" => theme::Theme::Dracula,
                    "mist" => theme::Theme::Mist,
                    _ => {
                        println!("{}", config.theme.error(&format!("Unknown theme: {}", name)));
                        continue;
                    }
                };
                println!("{}", config.theme.log(&format!("Theme set to: {:?}", config.theme)));
                config::save(&config)?;
            }

            Some(Commands::Help) => {
                println!("\n{}", config.theme.log("Commands:"));
                println!("  {} - Initialize/reinitialize your identity", "\x1B[37minit\x1B[0m");
                println!("  {} - Show your NL-ID and fingerprint", "\x1B[37mfingerprint\x1B[0m");
                println!("  {} <name> - Change your display name", "\x1B[37mset-display-name\x1B[0m");
                println!("  {} <theme> - Set theme (default/matrix/nord/dracula/mist)", "\x1B[37mtheme\x1B[0m");
                println!("  {} <nl-id> <alias> <tor-address> - Add a contact", "\x1B[37mcontact add\x1B[0m");
                println!("  {} <alias> - Delete a contact", "\x1B[37mcontact delete\x1B[0m");
                println!("  {} - List all contacts", "\x1B[37mcontact list\x1B[0m");
                println!("  {} <alias> or {} <alias> - Delete a contact", "\x1B[37mdel\x1B[0m", "\x1B[37mrm\x1B[0m");
                println!("  {} <alias> - Start a chat", "\x1B[37mping\x1B[0m");
                println!("  {} - List pending connection requests", "\x1B[37mpending\x1B[0m");
                println!("  {} <alias> - Accept a pending connection", "\x1B[37maccept\x1B[0m");
                println!("  {} <alias> - Reject a pending connection", "\x1B[37mreject\x1B[0m");
                println!("  {} - Show this help", "\x1B[37mhelp\x1B[0m");
                println!("  {} - Quit", "\x1B[37mexit\x1B[0m");
                println!("\n{}", config.theme.log("Chat Commands:"));
                println!("  {} - Leave current chat", "\x1B[37m/exit or /back\x1B[0m");
            }

            Some(Commands::Exit) => {
                println!("{}", config.theme.log("Goodbye!"));
                break;
            }

            None => {
                println!("{}", config.theme.error("Unknown command. Type 'help' for available commands."));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod display_name_tests {
    use super::validate_display_name;

    #[test]
    fn accepts_valid_display_names() {
        assert!(validate_display_name("alice").is_ok());
        assert!(validate_display_name("New Name").is_ok());
        assert!(validate_display_name("a-b_C d").is_ok());
        assert!(validate_display_name("  padded  ").is_ok(), "surrounding spaces are trimmed before validation");
        assert!(validate_display_name(&"a".repeat(32)).is_ok());
    }

    #[test]
    fn rejects_invalid_display_names() {
        assert!(validate_display_name("").is_err());
        assert!(validate_display_name("   ").is_err());
        assert!(validate_display_name("bad!name").is_err());
        assert!(validate_display_name("no@ats").is_err());
        let too_long = "a".repeat(33);
        assert!(validate_display_name(&too_long).is_err());
    }
}
#[cfg(test)]
mod cli_parse_tests {
    use super::{Cli, Commands, ContactCommands};
    use clap::Parser;

    #[test]
    fn parses_all_delete_variants() {
        // contact delete <alias>
        assert!(matches!(
            Cli::try_parse_from(["nite", "contact", "delete", "alice"]).unwrap().command,
            Some(Commands::Contact { command: ContactCommands::Delete { .. } })
        ));
        // contact remove <alias> (alias of delete)
        assert!(matches!(
            Cli::try_parse_from(["nite", "contact", "remove", "alice"]).unwrap().command,
            Some(Commands::Contact { command: ContactCommands::Delete { .. } })
        ));
        // del <alias>
        assert!(matches!(
            Cli::try_parse_from(["nite", "del", "alice"]).unwrap().command,
            Some(Commands::DeleteContact { .. })
        ));
        // rm <alias>
        assert!(matches!(
            Cli::try_parse_from(["nite", "rm", "alice"]).unwrap().command,
            Some(Commands::DeleteContact { .. })
        ));
    }

    #[test]
    fn parses_contact_add_and_list() {
        assert!(matches!(
            Cli::try_parse_from([
                "nite", "contact", "add", "NL-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG", "alice", "abc.onion:4444",
            ])
            .unwrap()
            .command,
            Some(Commands::Contact { command: ContactCommands::Add { .. } })
        ));
        assert!(matches!(
            Cli::try_parse_from(["nite", "contact", "list"]).unwrap().command,
            Some(Commands::Contact { command: ContactCommands::List })
        ));
    }
}
