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

/// Show NIGHTLINK ASCII art (used in main)
#[allow(dead_code)]
fn show_logo() {
    println!(
        r#"
  ███╗   ██╗    ██╗     ██████╗     ██╗  ██╗    ████████╗    ██╗         ██╗    ███╗   ██╗    ██╗  ██╗
  ████╗  ██║    ██║    ██╔════╝     ██║  ██║    ╚══██╔══╝    ██║         ██║    ████╗  ██║    ██║ ██╔╝
  ██╔██╗ ██║    ██║    ██║  ███╗    ███████║       ██║       ██║         ██║    ██╔██╗ ██║    █████╔╝
  ██║╚██╗██║    ██║    ██║   ██║    ██╔══██║       ██║       ██║         ██║    ██║╚██╗██║    ██╔═██╗
  ██║ ╚████║    ██║    ╚██████╔╝    ██║  ██║       ██║       ███████╗    ██║    ██║ ╚████║    ██║  ██╗
  ╚═╝  ╚═══╝    ╚═╝     ╚═════╝     ╚═╝  ╚═╝       ╚═╝       ╚══════╝    ╚═╝    ╚═╝  ╚═══╝    ╚═╝  ╚═╝
"#
    );
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
            None => {
                rpassword::prompt_password("[nite] Enter your passphrase to unlock your identity: ")?
            }
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
    Ping { target: String },
    Pending,
    Accept { alias: String },
    Reject { alias: String },
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
    println!("[nite] Waiting for Tor to bootstrap...");
    if let Err(e) = tor::wait_for_full_bootstrap().await {
        eprintln!("[nite] Error: {}", e);
        eprintln!("[nite] Error: Tor failed to start. Check your connection/firewall or restart the application.");
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

    // ===== PHASE 6: Interactive Shell =====
    start_shell(config, state, identity).await?;

    Ok(())
}

/// Start interactive shell
#[allow(clippy::too_many_arguments)]
async fn start_shell(
    mut config: types::Config,
    state: Arc<Mutex<AppState>>,
    mut identity: types::IdentityKeys,
) -> anyhow::Result<()> {
    loop {
        // Check if in chat mode
        let chat_with = {
            let state_guard = state.lock().await;
            state_guard
                .current_chat
                .as_ref()
                .map(|session| session.peer_alias.clone())
        };

        if let Some(chat_with) = &chat_with {
            print!("[nite~{}]: ", chat_with);
        } else {
            print!("{}", config.theme.prompt());
        }
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        // Check for chat exit commands
        if input == "/exit" || input == "/back" {
            chat::leave_chat(state.clone()).await;
            continue;
        }

        // If in chat mode, send the input as a network message
        if chat_with.is_some() {
            if let Err(e) = chat::send_message(state.clone(), input).await {
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
                if let Some(suggestion) = get_suggestion(input, &suggestions) {
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

                        // Check if contact already exists
                        if config.contacts.contains_key(&nl_id) {
                            println!("{}", config.theme.error(&format!("{} already exists. Update? (y/n)", alias)));
                            let mut choice = String::new();
                            io::stdin().read_line(&mut choice)?;
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

                // Check if contact already exists
                if config.contacts.contains_key(&nl_id) {
                    println!("{}", config.theme.error(&format!("{} already exists. Update? (y/n)", alias)));
                    let mut choice = String::new();
                    io::stdin().read_line(&mut choice)?;
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

            Some(Commands::Theme { name }) => {
                config.theme = match name.as_str() {
                    "default" => theme::Theme::Default,
                    "matrix" => theme::Theme::Matrix,
                    "nord" => theme::Theme::Nord,
                    "dracula" => theme::Theme::Dracula,
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
                println!("  {} <theme> - Set theme (default/matrix/nord/dracula)", "\x1B[37mtheme\x1B[0m");
                println!("  {} <nl-id> <alias> <tor-address> - Add a contact", "\x1B[37mcontact add\x1B[0m");
                println!("  {} - List all contacts", "\x1B[37mcontact list\x1B[0m");
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
