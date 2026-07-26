//! nite - CLI P2P Messenger
//!
//! Interactive console application.
//! Run without arguments for interactive mode, or pass commands directly.

use clap::{Parser, Subcommand};

mod chat;
mod config;
mod crypto;
mod p2p;
mod tor;
mod types;
mod voice;

use types::{get_config_dir, TransportMode};

#[derive(Parser)]
#[command(name = "nite")]
#[command(about = "P2P CLI messenger over Direct TCP and Tor")]
#[command(long_about = "NightLink - Peer-to-peer messenger\n\nRun without arguments for interactive mode.\nExamples:\n  nite --mode direct init\n  nite chat 192.168.1.5:4444\n  nite call alice")]
struct Cli {
    #[arg(short = 'm', long = "mode", default_value = "direct", value_parser = parse_transport_mode)]
    mode: TransportMode,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize nite (first-time setup)
    Init,
    /// Start an encrypted text chat with a peer
    Chat {
        /// Peer address, NL-ID, or alias
        peer: String,
    },
    /// Start a voice call with a peer
    Call {
        /// Peer address, NL-ID, or alias
        peer: String,
    },
    /// Listen for incoming connections
    Serve,
    /// Show your NightLink ID and fingerprint
    Fingerprint,
    /// Manage contacts
    Contact {
        #[command(subcommand)]
        action: ContactAction,
    },
    /// Exit (interactive mode only)
    Exit,
}

#[derive(Subcommand)]
enum ContactAction {
    /// Add a new contact
    Add {
        nl_id: String,
        #[arg(short, long)] alias: Option<String>,
        #[arg(short, long)] direct: Option<String>,
        #[arg(short, long)] tor: Option<String>,
    },
    /// List all contacts
    List,
}

fn parse_transport_mode(s: &str) -> Result<TransportMode, String> {
    match s.to_lowercase().as_str() {
        "direct" => Ok(TransportMode::Direct),
        "tor" => Ok(TransportMode::Tor),
        _ => Err(format!("Invalid transport mode '{}'. Use 'direct' or 'tor'.", s)),
    }
}

/// ANSI bold wrapper
fn bold(s: &str) -> String {
    format!("\x1b[1m{}\x1b[0m", s)
}

/// ANSI green text
fn green(s: &str) -> String {
    format!("\x1b[32m{}\x1b[0m", s)
}

/// ANSI yellow text
fn yellow(s: &str) -> String {
    format!("\x1b[33m{}\x1b[0m", s)
}

/// Print the NightLink banner
fn print_banner() {
    println!();
    println!("{}", bold("  :NightLink:"));
    println!("  {} P2P CLI Messenger", green("nite"));
    println!("  {} type 'help' for commands", yellow("?"));
    println!();
}

/// Print help message
fn print_help() {
    println!("{}", bold("Commands:"));
    println!("  init                        First-time setup / reinitialize");
    println!("  fingerprint                 Show your NightLink ID and key fingerprint");
    println!("  serve                       Start listening for incoming connections");
    println!("  chat <address|alias>        Start an encrypted text chat");
    println!("  call <address|alias>        Start a voice call");
    println!("  contact add <nl-id> [args]  Add a contact");
    println!("  contact list                List saved contacts");
    println!("  mode direct|tor             Switch transport mode");
    println!("  help                        Show this help");
    println!("  exit                        Quit NightLink");
    println!();
    println!("{}", bold("Examples:"));
    println!("  > init");
    println!("  > chat 192.168.1.5:4444");
    println!("  > mode tor");
    println!("  > call alice");
    println!();
}

/// Parse a line of input and execute the corresponding command
async fn execute_input(line: &str, current_mode: &mut TransportMode) -> anyhow::Result<bool> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(true); // continue
    }

    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(true);
    }

    match parts[0] {
        "help" | "?" => {
            print_help();
            Ok(true)
        }
        "exit" | "quit" | "q" => {
            println!("[nite] Goodbye.");
            Ok(false) // exit
        }
        "mode" => {
            if parts.len() > 1 {
                match parts[1] {
                    "direct" => {
                        *current_mode = TransportMode::Direct;
                        println!("[nite] Switched to direct mode");
                    }
                    "tor" => {
                        *current_mode = TransportMode::Tor;
                        println!("[nite] Switched to Tor mode");
                    }
                    _ => println!("[nite] Unknown mode '{}'. Use 'direct' or 'tor'.", parts[1]),
                }
            } else {
                println!("[nite] Current mode: {}", current_mode);
                println!("[nite] Usage: mode direct|tor");
            }
            Ok(true)
        }
        "init" => {
            if !get_config_dir().exists() {
                config::initialize(*current_mode)?;
            } else {
                println!("[nite] Re-initializing...");
                config::reinitialize(*current_mode)?;
                println!("[nite] Re-initialization complete.");
            }
            Ok(true)
        }
        "fingerprint" | "fp" | "whoami" => {
            config::print_fingerprint()?;
            Ok(true)
        }
        "serve" | "listen" => {
            let config = config::load()?;
            let addr = format!("0.0.0.0:{}", config.listen_port);
            println!("[nite] Listening on {} via {}", addr, current_mode);
            println!("[nite] Press Ctrl+C to stop serving");
            let listener = p2p::listen(&addr).await?;

            // Accept one connection, or return on Ctrl+C
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            println!("[nite] Incoming connection from {}", peer_addr);
                            handle_incoming(stream).await?;
                        }
                        Err(e) => eprintln!("[nite] Accept error: {}", e),
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("[nite] Stopped serving.");
                }
            }
            Ok(true)
        }
        "chat" => {
            if parts.len() > 1 {
                let peer = parts[1..].join(" ");
                let (nl_id, addr) = config::resolve_contact(&peer, *current_mode)
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                if addr == peer && !peer.contains('.') && !peer.contains(':') && !peer.ends_with(".onion") {
                    println!("[nite] Unknown contact '{}'. Add it first with 'contact add' or use a direct address.", peer);
                    return Ok(true);
                }
                println!("[nite] Starting chat with {} ({})", nl_id, addr);
                if let Err(e) = chat::start(&addr, *current_mode).await {
                    eprintln!("[nite] Chat failed: {}", e);
                }
            } else {
                println!("[nite] Usage: chat <address|alias>");
            }
            Ok(true)
        }
        "call" => {
            if parts.len() > 1 {
                let peer = parts[1..].join(" ");
                let (nl_id, addr) = config::resolve_contact(&peer, *current_mode)
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                if addr == peer && !peer.contains('.') && !peer.contains(':') && !peer.ends_with(".onion") {
                    println!("[nite] Unknown contact '{}'. Add it first with 'contact add' or use a direct address.", peer);
                    return Ok(true);
                }
                println!("[nite] Starting call with {} ({})", nl_id, addr);
                if let Err(e) = voice::start_call(&addr, *current_mode).await {
                    eprintln!("[nite] Call failed: {}", e);
                }
            } else {
                println!("[nite] Usage: call <address|alias>");
            }
            Ok(true)
        }
        "contact" => {
            if parts.len() > 1 {
                match parts[1] {
                    "add" => {
                        if parts.len() > 2 {
                            let nl_id = parts[2];
                            let mut alias = None;
                            let mut direct = None;
                            let mut tor = None;

                            let mut i = 3;
                            while i < parts.len() {
                                match parts[i] {
                                    "--alias" | "-a" => {
                                        if i + 1 < parts.len() {
                                            alias = Some(parts[i + 1].to_string());
                                            i += 2;
                                            continue;
                                        }
                                    }
                                    "--direct" | "-d" => {
                                        if i + 1 < parts.len() {
                                            direct = Some(parts[i + 1].to_string());
                                            i += 2;
                                            continue;
                                        }
                                    }
                                    "--tor" | "-t" => {
                                        if i + 1 < parts.len() {
                                            tor = Some(parts[i + 1].to_string());
                                            i += 2;
                                            continue;
                                        }
                                    }
                                    _ => {}
                                }
                                i += 1;
                            }

                            config::add_contact(nl_id, alias.as_deref(), direct.as_deref(), tor.as_deref())?;
                        } else {
                            println!("[nite] Usage: contact add <nl-id> [--alias <name>] [--direct <addr>] [--tor <addr>]");
                        }
                    }
                    "list" | "ls" => {
                        config::list_contacts()?;
                    }
                    _ => println!("[nite] Unknown contact command. Use: add, list"),
                }
            } else {
                println!("[nite] Usage: contact <add|list>");
            }
            Ok(true)
        }
        _ => {
            // Try to parse as a raw chat command: "chat <addr>" shorthand
            // or maybe it's just an address to chat with
            if parts[0].contains('.') || parts[0].contains(':') || parts[0].starts_with("NL-") || parts[0].ends_with(".onion") {
                // Treat as chat command
                let (nl_id, addr) = config::resolve_contact(line, *current_mode)?;
                println!("[nite] Starting chat with {} ({})", nl_id, addr);
                chat::start(&addr, *current_mode).await?;
            } else {
                println!("[nite] Unknown command: '{}'. Type 'help' for available commands.", parts[0]);
            }
            Ok(true)
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let mut transport = cli.mode;

    // If no subcommand given, enter interactive mode
    if cli.command.is_none() {
        // Auto-initialize if first run
        if !get_config_dir().exists() {
            println!("[nite] First run detected. Initializing...");
            config::initialize(transport)?;
        }

        print_banner();

        loop {
            // Show prompt: ":NightLink:" in bold
            let prompt = format!("{} ", bold(":NightLink:"));
            print!("{}", prompt);
            use std::io::Write;
            std::io::stdout().flush().ok();

            // Read input with Ctrl+C protection
            let mut input = String::new();
            let read_result = std::io::stdin().read_line(&mut input);

            match read_result {
                Ok(0) | Err(_) => {
                    // EOF or Ctrl+C (stdin returns error on Ctrl+C on Windows)
                    println!();
                    println!("[nite] Goodbye.");
                    break;
                }
                Ok(_) => {
                    let input = input.trim().to_string();
                    if input.is_empty() {
                        continue;
                    }
                    match execute_input(&input, &mut transport).await {
                        Ok(false) => break,
                        Ok(true) => {}
                        Err(e) => eprintln!("[nite] Error: {}", e),
                    }
                }
            }
        }

        Ok(())
    } else {
        // Non-interactive mode: execute the single command
        // Auto-initialize if first run (except for Init command)
        if !get_config_dir().exists() {
            match &cli.command {
                Some(Commands::Init) => {} // Init handles itself
                _ => {
                    println!("[nite] First run detected. Initializing...");
                    config::initialize(transport)?;
                }
            }
        }

        match cli.command.unwrap() {
            Commands::Init => {
                if !get_config_dir().exists() {
                    config::initialize(transport)?;
                } else {
                    println!("[nite] Re-initializing...");
                    config::reinitialize(transport)?;
                    println!("[nite] Re-initialization complete.");
                }
            }
            Commands::Chat { peer } => {
                let (nl_id, addr) = config::resolve_contact(&peer, transport)?;
                println!("[nite] Starting chat with {} ({})", nl_id, addr);
                chat::start(&addr, transport).await?;
            }
            Commands::Call { peer } => {
                let (nl_id, addr) = config::resolve_contact(&peer, transport)?;
                println!("[nite] Starting call with {} ({})", nl_id, addr);
                voice::start_call(&addr, transport).await?;
            }
            Commands::Serve => {
                let config = config::load()?;
                let addr = format!("0.0.0.0:{}", config.listen_port);
                println!("[nite] Listening on {} via {}", addr, transport);
                println!("[nite] Press Ctrl+C to stop serving");
                let listener = p2p::listen(&addr).await?;
                loop {
                    tokio::select! {
                        result = listener.accept() => {
                            match result {
                                Ok((stream, peer_addr)) => {
                                    println!("[nite] Incoming connection from {}", peer_addr);
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_incoming(stream).await {
                                            eprintln!("[nite] Connection handler error: {}", e);
                                        }
                                    });
                                }
                                Err(e) => eprintln!("[nite] Accept error: {}", e),
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            println!("[nite] Stopped serving.");
                            break;
                        }
                    }
                }
            }
            Commands::Fingerprint => config::print_fingerprint()?,
            Commands::Contact { action } => match action {
                ContactAction::Add { nl_id, alias, direct, tor } => {
                    config::add_contact(&nl_id, alias.as_deref(), direct.as_deref(), tor.as_deref())?;
                }
                ContactAction::List => config::list_contacts()?,
            },
            Commands::Exit => {
                println!("[nite] Goodbye.");
            }
        }
        Ok(())
    }
}

async fn handle_incoming(mut stream: tokio::net::TcpStream) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let peer_addr = stream.peer_addr()?;
    println!("[nite] Handling connection from {}", peer_addr);
    let config = config::load()?;
    let peer_public_key = p2p::exchange_public_keys(&mut stream, &config.public_key).await?;
    let passphrase = rpassword::prompt_password("[nite] Enter passphrase to decrypt private key: ")?;
    let private_key = crypto::decrypt_private_key(&config.private_key_encrypted, &passphrase, &config.salt, &config.nonce)?;
    let shared_secret = crypto::derive_shared_secret(&private_key, &peer_public_key)?;
    println!("[nite] Secure channel established with {}", peer_addr);
    let (mut read_half, mut write_half) = stream.into_split();
    let recv_task = tokio::spawn(async move {
        loop {
            match p2p::receive_message_read(&mut read_half).await {
                Ok(data) => {
                    match crypto::decrypt_message(&data, &shared_secret) {
                        Ok(plaintext) => match String::from_utf8(plaintext) {
                            Ok(msg) => println!("[remote] {}", msg),
                            Err(_) => println!("[nite] Received invalid UTF-8"),
                        },
                        Err(e) => println!("[nite] Decryption error: {}", e),
                    }
                }
                Err(e) => {
                    println!("[nite] Connection closed: {}", e);
                    break;
                }
            }
        }
    });
    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() { continue; }
        if line == "/quit" { break; }
        match crypto::encrypt_message(line.as_bytes(), &shared_secret) {
            Ok(encrypted) => {
                if let Err(e) = p2p::send_message_write(&mut write_half, &encrypted).await {
                    println!("[nite] Send error: {}", e);
                    break;
                }
                println!("[local] {}", line);
            }
            Err(e) => println!("[nite] Encryption error: {}", e),
        }
    }
    recv_task.abort();
    println!("[nite] Chat with {} ended.", peer_addr);
    Ok(())
}