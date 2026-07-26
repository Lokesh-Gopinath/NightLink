//! Text chat implementation for nite

use crate::types::TransportMode;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

pub async fn start(peer_addr: &str, transport: TransportMode) -> anyhow::Result<()> {
    println!("[nite] Connecting to {} via {}...", peer_addr, transport);

    let mut stream = crate::p2p::connect(peer_addr, transport).await?;
    println!("[nite] Connected to {}", peer_addr);
    println!("[nite] Type your messages below. Press Ctrl+C or type /quit to exit.");

    let config = crate::config::load()?;
    println!("[nite] Exchanging encryption keys...");
    let peer_public_key = crate::p2p::exchange_public_keys(&mut stream, &config.public_key).await?;

    let passphrase = rpassword::prompt_password("[nite] Enter passphrase to decrypt private key: ")?;
    let private_key = crate::crypto::decrypt_private_key(
        &config.private_key_encrypted, &passphrase, &config.salt, &config.nonce,
    )?;
    let shared_secret = crate::crypto::derive_shared_secret(&private_key, &peer_public_key)?;
    println!("[nite] Secure channel established (AES-256-GCM)");

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
    let (mut read_half, mut write_half) = stream.into_split();

    let display_task = tokio::spawn(async move {
        loop {
            match crate::p2p::receive_message_read(&mut read_half).await {
                Ok(data) => match crate::crypto::decrypt_message(&data, &shared_secret) {
                    Ok(plaintext) => match String::from_utf8(plaintext) {
                        Ok(msg) => println!("[remote] {}", msg),
                        Err(_) => println!("[nite] Received invalid UTF-8 message"),
                    },
                    Err(e) => println!("[nite] Decryption error: {}", e),
                },
                Err(e) => { println!("[nite] Connection lost: {}", e); break; }
            }
        }
    });

    let tx_clone = tx.clone();
    let stdin_task = tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim().to_string();
            if line.is_empty() { continue; }
            if line == "/quit" { break; }
            match crate::crypto::encrypt_message(line.as_bytes(), &shared_secret) {
                Ok(encrypted) => {
                    if tx_clone.blocking_send(encrypted).is_err() { break; }
                    println!("[local] {}", line);
                }
                Err(e) => println!("[nite] Encryption error: {}", e),
            }
        }
    });

    while let Some(encrypted) = rx.recv().await {
        if let Err(e) = crate::p2p::send_message_write(&mut write_half, &encrypted).await {
            println!("[nite] Failed to send message: {}", e);
            break;
        }
    }

    stdin_task.abort();
    display_task.abort();
    println!("[nite] Chat ended.");
    Ok(())
}