use crate::types::{Config, NLID};
use crate::crypto;
use crate::tor;
use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use std::io::{self, BufRead};

pub async fn start_chat(config: &Config, state: &Arc<Mutex<crate::types::AppState>>, target: &str) -> Result<(), Error> {
    let (nl_id, tor_address) = match config.contacts.get(target) {
        Some(contact) => (contact.alias.clone(), contact.tor_address.clone()),
        None if target.starts_with("NL-") => {
            if let Some(contact) = config.contacts.values().find(|c| c.alias == target) {
                (contact.alias.clone(), contact.tor_address.clone())
            } else {
                return Err(anyhow::anyhow!("Unknown contact or NL-ID: {}", target));
            }
        }
        _ => return Err(anyhow::anyhow!("Unknown contact or NL-ID: {}", target)),
    };

    let mut stream = tor::connect_via_tor(&tor_address).await?;
    tor::send_nl_id(&mut stream, &config.nl_id).await?;

    let peer_nl_id = tor::read_nl_id_from_stream(&mut stream).await?;
    if peer_nl_id != nl_id && peer_nl_id != target {
        return Err(anyhow::anyhow!("NL-ID mismatch! Expected {}, got {}", nl_id, peer_nl_id));
    }

    let (reader, mut writer) = tokio::io::split(stream);
    let peer_alias = nl_id.clone();

    tokio::spawn(async move {
        let mut reader = BufReader::new(reader);
        let mut buf = vec![0u8; 1024];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => break,
            };
            let msg = String::from_utf8_lossy(&buf[..n]);
            println!("[{}]: {}", peer_alias, msg);
        }
    });

    let mut stdin = io::BufReader::new(io::stdin());
    let mut line = String::new();
    loop {
        print!("> ");
        io::Write::flush(&mut io::stdout())?;
        line.clear();
        stdin.read_line(&mut line)?;
        if line.trim() == "/quit" {
            break;
        }
        writer.write_all(line.as_bytes()).await?;
        writer.flush().await?;
    }
    Ok(())
}

pub async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    my_nl_id: NLID,
    peer_alias: String,
) -> Result<(), Error> {
    tor::send_nl_id(&mut stream, &my_nl_id).await?;
    let peer_nl_id = tor::read_nl_id_from_stream(&mut stream).await?;

    let (reader, mut writer) = tokio::io::split(stream);

    tokio::spawn(async move {
        let mut reader = BufReader::new(reader);
        let mut buf = vec![0u8; 1024];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => break,
            };
            let msg = String::from_utf8_lossy(&buf[..n]);
            println!("[{}]: {}", peer_alias, msg);
        }
    });

    let mut stdin = io::BufReader::new(io::stdin());
    let mut line = String::new();
    loop {
        print!("> ");
        io::Write::flush(&mut io::stdout())?;
        line.clear();
        stdin.read_line(&mut line)?;
        if line.trim() == "/quit" {
            break;
        }
        writer.write_all(line.as_bytes()).await?;
        writer.flush().await?;
    }
    Ok(())
}

pub async fn prepare_incoming(stream: tokio::net::TcpStream, config: &Config) -> Result<IncomingConnection, Error> {
    let mut stream = stream;
    let _peer_nl_id = tor::read_nl_id_from_stream(&mut stream).await?;
    
    let shared_secret_vec = crypto::derive_session_key(&config.private_key_encrypted, &config.public_key);
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&shared_secret_vec);
    
    Ok(IncomingConnection {
        peer_nl_id: _peer_nl_id,
        shared_secret,
        stream,
    })
}

pub struct IncomingConnection {
    pub peer_nl_id: String,
    pub shared_secret: [u8; 32],
    pub stream: tokio::net::TcpStream,
}
