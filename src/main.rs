use std::process::Command;
use std::io::{self, Write};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use clap::{Parser, Subcommand};

mod types;
mod config;
mod crypto;
mod theme;
mod tor;
mod chat;

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

/// Load config or initialize (SILENTLY)
fn load_or_init_config() -> Result<types::Config, anyhow::Error> {
    let config_path = types::get_config_path();
    if config_path.exists() {
        for _ in 0..3 {
            match config::load() {
                Ok(c) => return Ok(c),
                Err(e) if e.to_string().contains("being used by another process") => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(e) => return Err(e),
            }
        }
        return Err(anyhow::anyhow!("Config file is locked. Close other instances."));
    } else {
        match config::initialize_silent() {
            Ok(c) => Ok(c),
            Err(e) => Err(e),
        }
    }
}

#[derive(Parser)]
#[command(name = "nite")]
#[command(about = "Tor-only P2P encrypted chat", long_about = None)]
#[command(disable_help_subcommand = true)]  // FIX: Disable clap's auto-help
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Fingerprint,
    ContactAdd { nl_id: String, alias: String, tor_address: String },
    ContactList,
    Ping { target: String },
    Pending,
    Accept { alias: String },
    Reject { alias: String },
    Theme { name: String },
    Help,
    Exit,
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
            eprintln!("[nite] Tor startup failed: {}", e);
            pause_and_exit(1);
        }
    };

    // ===== PHASE 2: Wait for Bootstrap =====
    println!("[nite] Waiting for Tor to bootstrap (this may take 1-2 minutes)...");
    if let Err(e) = tor::wait_for_full_bootstrap().await {
        eprintln!("[nite] Tor bootstrap failed: {}", e);
        pause_and_exit(1);
    }

    // ===== PHASE 3: Clear + Show UI =====
    clear_terminal();
    
    // ===== PHASE 4: Load/Init Config + Save Onion Address =====
    let mut config = match load_or_init_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[nite] Error: {}", e);
            pause_and_exit(1);
        }
    };
    config.tor_address = Some(format!("{}.onion:4444", onion_addr));
    config::save(&config)?;
    
    // Apply theme and show ASCII art
    config.theme.apply();
    println!("{}", config.theme.ascii_art());

    // ===== PHASE 5: Start Listener (SILENTLY) =====
    let state = Arc::new(Mutex::new(types::AppState {
        config: config.clone(),
        pending_connections: HashMap::new(),
    }));

    tokio::spawn({
        let state = state.clone();
        let nl_id = config.nl_id.clone();
        async move {
            if let Err(e) = listen_for_connections(state, nl_id).await {
                eprintln!("[nite] Listener error: {}", e);
            }
        }
    });

    // ===== PHASE 6: Interactive Shell =====
    start_shell(config, state).await?;

    Ok(())
}

/// Start interactive shell
async fn start_shell(mut config: types::Config, state: Arc<Mutex<types::AppState>>) -> anyhow::Result<()> {
    loop {
        // Apply theme colors
        print!("{}", config.theme.prompt());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        // FIX: Prepend program name for clap parsing
        let args = std::iter::once("nite").chain(input.split_whitespace());
        let cli = match Cli::try_parse_from(args) {
            Ok(cli) => cli,
            Err(e) => {
                println!("{}", config.theme.error(&e.to_string()));
                continue;
            }
        };
        match cli.command {
            Some(Commands::Init) => {
                let new_config = config::initialize_silent()?;
                println!("{}", config.theme.log(&format!("Re-initialized. Your NL-ID: {}", new_config.nl_id)));
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
                    println!("{}", config.theme.log("Tor address: Not generated (hidden service failed)"));
                }
            }
            Some(Commands::ContactAdd { nl_id, alias, tor_address }) => {
                let nl_id_clone = nl_id.clone();
                let alias_clone = alias.clone();
                let tor_address_clone = tor_address.clone();
                config::add_contact(&mut config.clone(), nl_id, alias, tor_address)?;
                println!("{}", config.theme.log(&format!("Contact added: {} ({}) -> {}", alias_clone, nl_id_clone, tor_address_clone)));
            }
            Some(Commands::ContactList) => {
                if config.contacts.is_empty() {
                    println!("{}", config.theme.log("No contacts"));
                } else {
                    println!("{}", config.theme.log("Contacts:"));
                    for (nl_id, contact) in &config.contacts {
                        println!("{}", config.theme.log(&format!("  {} ({}) -> {}", contact.alias, nl_id, contact.tor_address)));
                    }
                }
            }
            Some(Commands::Ping { target }) => {
                chat::start_chat(&config, &state, &target).await?;
            }
            Some(Commands::Pending) => {
                let pending = state.lock().await;
                if pending.pending_connections.is_empty() {
                    println!("{}", config.theme.log("No pending connections"));
                } else {
                    println!("{}", config.theme.log("Pending connections:"));
                    for (alias, _) in &pending.pending_connections {
                        println!("{}", config.theme.log(&format!("  - {}", alias)));
                    }
                }
            }
            Some(Commands::Accept { alias }) => {
                let mut state_lock = state.lock().await;
                if let Some(stream) = state_lock.pending_connections.remove(&alias) {
                    println!("{}", config.theme.log(&format!("Accepted connection from {}", alias)));
                    tokio::spawn(chat::handle_connection(
                        stream,
                        config.nl_id.clone(),
                        alias.clone(),
                    ));
                } else {
                    println!("{}", config.theme.log(&format!("No pending connection from {}", alias)));
                }
            }
            Some(Commands::Reject { alias }) => {
                let mut state_lock = state.lock().await;
                if state_lock.pending_connections.remove(&alias).is_some() {
                    println!("{}", config.theme.log(&format!("Rejected connection from {}", alias)));
                } else {
                    println!("{}", config.theme.log(&format!("No pending connection from {}", alias)));
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

/// Listen for incoming connections (SILENTLY)
async fn listen_for_connections(
    state: Arc<Mutex<types::AppState>>,
    my_nl_id: String,
) -> anyhow::Result<()> {
    let listener = tor::create_listener(4444).await?;
    while let Ok((mut stream, _)) = listener.accept().await {
        let state_clone = state.clone();
        let _my_nl_id_clone = my_nl_id.clone();
        tokio::spawn(async move {
            let peer_nl_id = match tor::read_nl_id_from_stream(&mut stream).await {
                Ok(id) => id,
                Err(_) => return,
            };
            let alias = config::get_alias_for_nl_id(&state_clone.lock().await.config, &peer_nl_id)
                .unwrap_or_else(|| peer_nl_id.clone());
            println!("[nite] {} wants to connect. Type 'accept {}' or 'reject {}'", alias, alias, alias);
            let mut state_lock = state_clone.lock().await;
            state_lock.pending_connections.insert(alias.clone(), stream);
        });
    }
    Ok(())
}