//! Network layer of NightLink.
//!
//! All traffic goes through the Tor SOCKS5 proxy at 127.0.0.1:9050. Inbound
//! connections arrive via the hidden service on the local listener, outbound
//! ones are opened with `tor::connect_via_tor`.
//!
//! Wire protocol — every message is a length-prefixed frame
//! (`u32` big-endian length + payload). Payloads:
//! ```text
//!   CONNECT <nl-id> <alias> <ed25519-pub-hex> <static-x25519-hex> <eph-x25519-hex> <eph-sig-hex>
//!   ACCEPT <nl-id> <ed25519-pub-hex> <static-x25519-hex> <eph-x25519-hex> <eph-sig-hex>
//!   REJECT <nl-id>
//!   MSG <hex of nonce||ciphertext>   (ChaCha20-Poly1305 sealed)
//!   BYE
//! ```
//!
//! After CONNECT/ACCEPT both peers derive the session key from X25519 ECDH
//! over the ephemeral and static key pairs (see `crypto`), so every `MSG`
//! frame is encrypted end-to-end.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use ed25519_dalek::{Signature, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto;
use crate::tor;
use crate::types::{AppState, ChatSession, Config, Contact, IdentityKeys, PendingConnection};

/// Local address the Tor hidden service forwards to.
pub const LISTEN_ADDR: &str = "127.0.0.1:4444";
/// Maximum accepted frame size (guards against malicious length prefixes).
const MAX_FRAME: usize = 1024 * 1024;
/// How long to wait for an ACCEPT/REJECT reply before giving up.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);

// ============================ framing ============================

/// Write `data` as a length-prefixed frame.
pub async fn write_frame<W>(writer: &mut W, data: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if data.len() > MAX_FRAME {
        return Err(anyhow!("Frame too large: {} bytes", data.len()));
    }
    writer.write_all(&(data.len() as u32).to_be_bytes()).await?;
    writer.write_all(data).await?;
    Ok(())
}

/// Read a length-prefixed frame. Returns an error if the payload is
/// incomplete (peer disconnected mid-frame).
pub async fn read_frame<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(anyhow!("Frame too large: {} bytes", len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

// ============================ protocol helpers ============================

/// Parsed `CONNECT` handshake from a peer.
struct ConnectInfo {
    nl_id: String,
    alias: String,
    ed25519_public: [u8; 32],
    static_public: PublicKey,
    ephemeral_public: PublicKey,
    ephemeral_signature: Vec<u8>,
}

/// Parse `CONNECT <nl-id> <alias...> <ed25519-hex> <static-hex> <eph-hex> <sig-hex>`.
/// The alias may contain spaces, so the four trailing tokens are key material.
fn parse_connect(payload: &str) -> Option<ConnectInfo> {
    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.len() < 7 || !parts[0].eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let nl_id = parts[1];
    let alias = parts[2..parts.len() - 4].join(" ");
    if nl_id.is_empty() || alias.is_empty() {
        return None;
    }

    let ed25519_bytes = hex::decode(parts[parts.len() - 4]).ok()?;
    if ed25519_bytes.len() != 32 {
        return None;
    }
    let mut ed25519_public = [0u8; 32];
    ed25519_public.copy_from_slice(&ed25519_bytes);

    let static_public = parse_public_key(parts[parts.len() - 3]).ok()?;
    let ephemeral_public = parse_public_key(parts[parts.len() - 2]).ok()?;
    let ephemeral_signature = hex::decode(parts[parts.len() - 1]).ok()?;
    if ephemeral_signature.len() != 64 {
        return None;
    }

    Some(ConnectInfo {
        nl_id: nl_id.to_string(),
        alias,
        ed25519_public,
        static_public,
        ephemeral_public,
        ephemeral_signature,
    })
}

/// Parse `ACCEPT <nl-id> <ed25519-hex> <static-hex> <eph-hex> <sig-hex>`.
/// Returns (nl-id, ed25519-public, static, ephemeral, signature).
fn parse_accept(payload: &str) -> Option<(String, [u8; 32], PublicKey, PublicKey, Vec<u8>)> {
    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.len() < 6 || !parts[0].eq_ignore_ascii_case("ACCEPT") {
        return None;
    }
    let ed25519_bytes = hex::decode(parts[2]).ok()?;
    if ed25519_bytes.len() != 32 {
        return None;
    }
    let mut ed25519_public = [0u8; 32];
    ed25519_public.copy_from_slice(&ed25519_bytes);
    let static_public = parse_public_key(parts[3]).ok()?;
    let ephemeral_public = parse_public_key(parts[4]).ok()?;
    let ephemeral_signature = hex::decode(parts[5]).ok()?;
    if ephemeral_signature.len() != 64 {
        return None;
    }
    Some((
        parts[1].to_string(),
        ed25519_public,
        static_public,
        ephemeral_public,
        ephemeral_signature,
    ))
}

/// Authenticate a peer's handshake claim:
/// 1. their Ed25519 public key must hash to the claimed NL-ID,
/// 2. it must match the stored contact public key (when available),
/// 3. their signature over the ephemeral X25519 key must verify.
fn verify_peer_identity(
    claimed_nl_id: &str,
    claimed_ed25519: &[u8],
    stored_public_key: &[u8],
    ephemeral_public: &PublicKey,
    signature_bytes: &[u8],
) -> Result<()> {
    if claimed_ed25519.len() != 32 {
        return Err(anyhow!("invalid Ed25519 public key length"));
    }
    // 1. Pubkey must hash to the claimed NL-ID.
    let expected_nl_id = crate::types::format_nl_id(claimed_ed25519);
    if !expected_nl_id.eq_ignore_ascii_case(claimed_nl_id) {
        return Err(anyhow!(
            "public key does not hash to NL-ID {}",
            claimed_nl_id
        ));
    }
    // 2. If we have a stored key for this contact, it must match exactly.
    if !stored_public_key.is_empty() && stored_public_key != claimed_ed25519 {
        return Err(anyhow!(
            "public key does not match the key stored for this contact"
        ));
    }
    // 3. Signature over the ephemeral X25519 public key.
    let verifying_key = VerifyingKey::from_bytes(
        claimed_ed25519
            .try_into()
            .expect("checked length above"),
    )
    .map_err(|e| anyhow!("invalid Ed25519 public key: {}", e))?;
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|e| anyhow!("invalid signature: {}", e))?;
    if !crypto::verify_signature(&verifying_key, &ephemeral_public.to_bytes(), &signature) {
        return Err(anyhow!("Ed25519 signature verification failed"));
    }
    Ok(())
}

fn parse_public_key(hex_str: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(anyhow!("invalid X25519 public key length"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey::from(arr))
}

fn frame_text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).trim().to_string()
}

/// Print a message from a background (spawned) task. A leading newline keeps
/// the message on its own line instead of gluing onto the shell's active
/// prompt line or leaving a dangling blank cursor line.
fn bg_print(msg: &str) {
    println!("\n{}", msg);
}

// ============================ listener / incoming ============================

/// Bind the listener on the hidden-service port and accept CONNECT requests.
/// Runs forever; returns only on a fatal bind error.
pub async fn start_listener(state: Arc<Mutex<AppState>>) -> Result<()> {
    let listener = TcpListener::bind(LISTEN_ADDR)
        .await
        .with_context(|| format!("could not bind {}", LISTEN_ADDR))?;

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("[nite] Listener error: {}", e);
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_incoming_connection(stream, state).await {
                eprintln!("[nite] Connection error: {}", e);
            }
        });
    }
}

/// Read a CONNECT frame, validate it, and queue it as a pending request.
async fn handle_incoming_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<AppState>>,
) -> Result<()> {
    let payload = read_frame(&mut stream).await?;
    let text = frame_text(&payload);
    let info = parse_connect(&text).ok_or_else(|| anyhow!("expected CONNECT, got {:?}", text))?;

    {
        let mut guard = state.lock().await;
        // One chat at a time and no duplicates.
        if let Some(session) = &guard.current_chat {
            if session.peer_nl_id == info.nl_id {
                return Err(anyhow!("already chatting with {}", info.alias));
            }
        }
        if guard
            .pending_connections
            .iter()
            .any(|p| p.peer_nl_id == info.nl_id)
        {
            return Err(anyhow!("duplicate connection from {}", info.alias));
        }
        guard.pending_connections.push(PendingConnection {
            peer_nl_id: info.nl_id.clone(),
            peer_alias: info.alias.clone(),
            incoming: true,
            stream: Some(stream),
            peer_ephemeral_public: Some(info.ephemeral_public),
            peer_static_public: Some(info.static_public),
            peer_ed25519_public: Some(info.ed25519_public.to_vec()),
            peer_eph_signature: Some(info.ephemeral_signature),
        });
    }

    bg_print(&format!(
        "[nite] {} wants to connect. Type 'accept {}' or 'reject {}'",
        info.alias, info.alias, info.alias
    ));
    Ok(())
}

// ============================ outgoing ping ============================

/// Connect to a contact through Tor, exchange X25519 keys in the CONNECT
/// frame, then spawn a watcher that builds the encrypted session once the
/// peer replies.
pub async fn send_connection_request(
    state: Arc<Mutex<AppState>>,
    config: &Config,
    contact: &Contact,
    identity: &IdentityKeys,
) -> Result<()> {
    let (ephemeral_secret, ephemeral_public) = crypto::generate_ephemeral();
    let signature = crypto::sign_message(&identity.signing_key, &ephemeral_public.to_bytes());

    let mut stream = tor::connect_via_tor(&contact.tor_address).await?;
    let request = format!(
        "CONNECT {} {} {} {} {} {}",
        config.nl_id,
        config.display_name,
        hex::encode(identity.verifying_key.to_bytes()),
        hex::encode(identity.static_public.to_bytes()),
        hex::encode(ephemeral_public.to_bytes()),
        hex::encode(signature.to_bytes()),
    );
    write_frame(&mut stream, request.as_bytes()).await?;

    {
        let mut guard = state.lock().await;
        if guard
            .pending_connections
            .iter()
            .any(|p| p.peer_nl_id == contact.nl_id)
        {
            return Err(anyhow!("a connection with this contact is already pending"));
        }
        guard.pending_connections.push(PendingConnection {
            peer_nl_id: contact.nl_id.clone(),
            peer_alias: contact.alias.clone(),
            incoming: false,
            stream: Some(stream),
            peer_ephemeral_public: None,
            peer_static_public: None,
            peer_ed25519_public: None,
            peer_eph_signature: None,
        });
    }

    let state = state.clone();
    let nl_id = contact.nl_id.clone();
    let alias = contact.alias.clone();
    let static_owned = identity.static_secret.clone();
    let stored_public_key = contact.public_key.clone();
    tokio::spawn(watch_ping_response(
        state,
        nl_id,
        alias,
        stored_public_key,
        ephemeral_secret,
        static_owned,
    ));
    Ok(())
}

/// Wait for ACCEPT/REJECT on an outgoing request, verify the peer's identity
/// key, derive the session cipher, and promote the connection to a chat.
async fn watch_ping_response(
    state: Arc<Mutex<AppState>>,
    peer_nl_id: String,
    peer_alias: String,
    stored_public_key: Vec<u8>,
    ephemeral_secret: x25519_dalek::EphemeralSecret,
    static_secret: StaticSecret,
) {
    // The pending entry stays visible in `pending` while we wait; the stream
    // itself is taken out so reads do not block the state lock.
    let stream = {
        let mut guard = state.lock().await;
        match guard
            .pending_connections
            .iter_mut()
            .find(|p| !p.incoming && p.peer_nl_id == peer_nl_id)
        {
            Some(entry) => entry.stream.take(),
            None => return,
        }
    };
    let Some(mut stream) = stream else { return };

    let reply = tokio::time::timeout(RESPONSE_TIMEOUT, read_frame(&mut stream)).await;

    match reply {
        Err(_) => {
            bg_print(&format!("[nite] No response from {} (timeout).", peer_alias));
            remove_pending(state.clone(), &peer_nl_id).await;
        }
        Ok(Err(e)) => {
            bg_print(&format!("[nite] Connection to {} failed: {}", peer_alias, e));
            remove_pending(state, &peer_nl_id).await;
        }
        Ok(Ok(payload)) => {
            let text = frame_text(&payload);
            if let Some((their_nl_id, their_ed25519, their_static, their_ephemeral, their_sig)) =
                parse_accept(&text)
            {
                if !their_nl_id.eq_ignore_ascii_case(&peer_nl_id) {
                    bg_print(&format!(
                        "[nite] Security: {} replied with an unexpected NL-ID. Aborting.",
                        peer_alias
                    ));
                    remove_pending(state, &peer_nl_id).await;
                    return;
                }
                if let Err(e) = verify_peer_identity(
                    &peer_nl_id,
                    &their_ed25519,
                    &stored_public_key,
                    &their_ephemeral,
                    &their_sig,
                ) {
                    bg_print(&format!(
                        "[nite] Security: rejected unverified reply from {}: {}",
                        peer_alias, e
                    ));
                    remove_pending(state, &peer_nl_id).await;
                    return;
                }
                let cipher = crypto::derive_session_key(
                    ephemeral_secret,
                    &their_ephemeral,
                    &static_secret,
                    &their_static,
                );
                begin_session(
                    state.clone(),
                    stream,
                    peer_nl_id.clone(),
                    peer_alias.clone(),
                    cipher,
                    their_static,
                )
                .await;
                remove_pending(state, &peer_nl_id).await;
                bg_print(&format!(
                    "[nite] {} accepted your connection. Now chatting (encrypted) with {}. Use /exit or /back to leave.",
                    peer_alias, peer_alias
                ));
            } else if text.starts_with("REJECT") {
                bg_print(&format!("[nite] {} rejected your connection request.", peer_alias));
                remove_pending(state, &peer_nl_id).await;
            } else {
                bg_print(&format!("[nite] Unexpected reply from {}: {}", peer_alias, text));
                remove_pending(state, &peer_nl_id).await;
            }
        }
    }
}

async fn remove_pending(state: Arc<Mutex<AppState>>, nl_id: &str) {
    let mut guard = state.lock().await;
    guard.pending_connections.retain(|p| p.peer_nl_id != nl_id);
}

// ============================ accept / reject ============================

/// Accept a queued incoming request: verify the peer's NL-ID is a known
/// contact, exchange X25519 keys, and open an encrypted session.
pub async fn accept_pending(
    state: Arc<Mutex<AppState>>,
    config: &Config,
    target: &str,
    identity: &IdentityKeys,
) -> Result<()> {
    let pending = {
        let mut guard = state.lock().await;
        if guard.current_chat.is_some() {
            return Err(anyhow!("You are already in a chat. Use /exit or /back first."));
        }
        let idx = guard.pending_connections.iter().position(|p| {
            p.incoming
                && (p.peer_alias.eq_ignore_ascii_case(target)
                    || p.peer_nl_id.eq_ignore_ascii_case(target))
        });
        match idx {
            Some(i) => guard.pending_connections.remove(i),
            None => return Err(anyhow!("No pending connection from {}", target)),
        }
    };

    // Security: only accept peers whose NL-ID is a contact of ours.
    let Some(contact) = config
        .contacts
        .values()
        .find(|c| c.nl_id.eq_ignore_ascii_case(&pending.peer_nl_id))
    else {
        let mut stream = pending.stream.expect("incoming pending owns its stream");
        let reject = format!("REJECT {}", pending.peer_nl_id);
        let _ = write_frame(&mut stream, reject.as_bytes()).await;
        return Err(anyhow!(
            "Rejected {}: NL-ID {} is not in your contacts.",
            pending.peer_alias,
            pending.peer_nl_id
        ));
    };

    // Security: verify the claimed Ed25519 key + signature before accepting.
    let verification = {
        let their_ed25519 = pending
            .peer_ed25519_public
            .as_deref()
            .ok_or_else(|| anyhow!("Missing peer identity key"))?;
        let their_signature = pending
            .peer_eph_signature
            .as_deref()
            .ok_or_else(|| anyhow!("Missing peer signature"))?;
        let their_ephemeral = pending
            .peer_ephemeral_public
            .ok_or_else(|| anyhow!("Missing peer ephemeral key"))?;
        verify_peer_identity(
            &pending.peer_nl_id,
            their_ed25519,
            &contact.public_key,
            &their_ephemeral,
            their_signature,
        )
    };
    if let Err(e) = verification {
        let mut stream = pending.stream.expect("incoming pending owns its stream");
        let reject = format!("REJECT {}", pending.peer_nl_id);
        let _ = write_frame(&mut stream, reject.as_bytes()).await;
        return Err(anyhow!("Rejected incoming connection from {}: {}", pending.peer_alias, e));
    }

    let mut stream = pending.stream.expect("incoming pending owns its stream");
    let their_ephemeral = pending
        .peer_ephemeral_public
        .ok_or_else(|| anyhow!("Missing peer ephemeral key"))?;
    let their_static = pending
        .peer_static_public
        .ok_or_else(|| anyhow!("Missing peer static key"))?;

    let (ephemeral_secret, ephemeral_public) = crypto::generate_ephemeral();
    let signature = crypto::sign_message(&identity.signing_key, &ephemeral_public.to_bytes());

    let cipher = crypto::derive_session_key(
        ephemeral_secret,
        &their_ephemeral,
        &identity.static_secret,
        &their_static,
    );

    let accept = format!(
        "ACCEPT {} {} {} {} {}",
        config.nl_id,
        hex::encode(identity.verifying_key.to_bytes()),
        hex::encode(identity.static_public.to_bytes()),
        hex::encode(ephemeral_public.to_bytes()),
        hex::encode(signature.to_bytes()),
    );
    write_frame(&mut stream, accept.as_bytes())
        .await
        .context("failed to send ACCEPT (peer may have disconnected)")?;

    let peer_nl_id = pending.peer_nl_id.clone();
    let peer_alias = pending.peer_alias.clone();
    begin_session(
        state.clone(),
        stream,
        peer_nl_id,
        peer_alias.clone(),
        cipher,
        their_static,
    )
    .await;
    println!(
        "[nite] Accepted (verified) connection from {}. Now chatting (encrypted) with {}. Type your messages below. Use /exit or /back to leave.",
        peer_alias, peer_alias
    );
    Ok(())
}

/// Send REJECT on a queued incoming request.
pub async fn reject_pending(state: Arc<Mutex<AppState>>, target: &str) -> Result<()> {
    let pending = {
        let mut guard = state.lock().await;
        let idx = guard.pending_connections.iter().position(|p| {
            p.incoming
                && (p.peer_alias.eq_ignore_ascii_case(target)
                    || p.peer_nl_id.eq_ignore_ascii_case(target))
        });
        match idx {
            Some(i) => guard.pending_connections.remove(i),
            None => return Err(anyhow!("No pending connection from {}", target)),
        }
    };

    let mut stream = pending.stream.expect("incoming pending owns its stream");
    let reject = format!("REJECT {}", pending.peer_nl_id);
    let _ = write_frame(&mut stream, reject.as_bytes()).await; // best effort
    Ok(())
}

// ============================ chat session ============================

/// Turn a live stream into an encrypted session: split it, store the write
/// half and cipher, and spawn a background reader for incoming frames.
async fn begin_session(
    state: Arc<Mutex<AppState>>,
    stream: TcpStream,
    peer_nl_id: String,
    peer_alias: String,
    cipher: chacha20poly1305::ChaCha20Poly1305,
    peer_static_public: PublicKey,
) {
    let (read_half, write_half) = stream.into_split();
    let session = ChatSession {
        peer_nl_id: peer_nl_id.clone(),
        peer_alias: peer_alias.clone(),
        write: Arc::new(Mutex::new(write_half)),
        cipher: cipher.clone(),
        peer_static_public,
    };
    {
        let mut guard = state.lock().await;
        if guard.current_chat.is_some() {
            bg_print(&format!("[nite] {} connected, but you are already in a chat.", peer_alias));
            return; // halves dropped => connection closed
        }
        guard.current_chat = Some(session);
    }
    spawn_message_reader(state, read_half, peer_nl_id, peer_alias, cipher);
}

/// Send one encrypted chat message on the active session.
pub async fn send_message(state: Arc<Mutex<AppState>>, message: &str) -> Result<()> {
    let guard = state.lock().await;
    let session = guard
        .current_chat
        .as_ref()
        .ok_or_else(|| anyhow!("Not currently in a chat"))?;
    let encrypted = crypto::encrypt_message(&session.cipher, message.as_bytes())?;
    let mut write = session.write.lock().await;
    let frame = format!("MSG {}", hex::encode(&encrypted));
    write_frame(&mut *write, frame.as_bytes()).await?;
    Ok(())
}

/// Leave the current chat, notifying the peer with a BYE frame.
pub async fn leave_chat(state: Arc<Mutex<AppState>>) {
    let alias = {
        let guard = state.lock().await;
        let Some(session) = guard.current_chat.as_ref() else {
            println!("[nite] You are not in a chat.");
            return;
        };
        let alias = session.peer_alias.clone();
        let mut write = session.write.lock().await;
        let _ = write_frame(&mut *write, b"BYE").await; // best effort
        alias
    };
    {
        let mut guard = state.lock().await;
        guard.current_chat = None;
    }
    println!("[nite] You have left the chat with {}.", alias);
}

/// Background task: decrypt and print incoming MSG frames; clean up on BYE/EOF.
fn spawn_message_reader(
    state: Arc<Mutex<AppState>>,
    mut read_half: OwnedReadHalf,
    peer_nl_id: String,
    peer_alias: String,
    cipher: chacha20poly1305::ChaCha20Poly1305,
) {
    tokio::spawn(async move {
        let mut peer_left = false;
        loop {
            let payload = match read_frame(&mut read_half).await {
                Ok(payload) => payload,
                Err(_) => break,
            };
            let text = frame_text(&payload);
            if text == "BYE" {
                peer_left = true;
                break;
            }
            if let Some(hex_str) = text.strip_prefix("MSG ") {
                let decrypted = hex::decode(hex_str)
                    .ok()
                    .and_then(|blob| crypto::decrypt_message(&cipher, &blob).ok())
                    .and_then(|plaintext| String::from_utf8(plaintext).ok());
                match decrypted {
                    Some(message) => bg_print(&format!("[{}]: {}", peer_alias, message)),
                    None => bg_print(&format!(
                        "[nite] Could not decrypt a message from {} (key mismatch or tampering).",
                        peer_alias
                    )),
                }
            } else {
                bg_print(&format!("[{}]: {}", peer_alias, text));
            }
        }

        // If this session is still the active one, clear it.
        let mut guard = state.lock().await;
        let clear = guard
            .current_chat
            .as_ref()
            .map(|s| s.peer_nl_id == peer_nl_id)
            .unwrap_or(false);
        if clear {
            guard.current_chat = None;
            if peer_left {
                bg_print(&format!("[nite] {} left the chat. Returned to main prompt.", peer_alias));
            } else {
                bg_print(&format!("[nite] Connection with {} closed. Returned to main prompt.", peer_alias));
            }
        }
    });
}

// ============================ tests ============================

#[cfg(test)]
mod tests {
    use super::*;

    fn zeros_hex() -> String {
        "00".repeat(32)
    }

    #[tokio::test]
    async fn frame_round_trip() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"hello nightlink").await.unwrap();
        let mut slice = wire.as_slice();
        let frame = read_frame(&mut slice).await.unwrap();
        assert_eq!(frame, b"hello nightlink");
    }

    #[tokio::test]
    async fn frame_handles_binary_payload() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &[0u8, 1, 2, 254, 255]).await.unwrap();
        let mut slice = wire.as_slice();
        let frame = read_frame(&mut slice).await.unwrap();
        assert_eq!(frame, vec![0u8, 1, 2, 254, 255]);
    }

    #[tokio::test]
    async fn frame_rejects_huge_length() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut slice = wire.as_slice();
        let err = read_frame(&mut slice).await.expect_err("must fail");
        assert!(err.to_string().contains("Frame too large"));
    }

    #[tokio::test]
    async fn frame_detects_truncated_payload() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"this payload is longer").await.unwrap();
        wire.truncate(8);
        let mut slice = wire.as_slice();
        assert!(read_frame(&mut slice).await.is_err());
    }

    #[test]
    fn parses_connect_with_aliases_containing_spaces() {
        let z = zeros_hex();
        let sig = "00".repeat(64);
        let info = parse_connect(&format!(
            "CONNECT NL-ABCD-1234 my friend {} {} {} {}",
            z, z, z, sig
        ))
        .unwrap();
        assert_eq!(info.nl_id, "NL-ABCD-1234");
        assert_eq!(info.alias, "my friend");
        assert_eq!(hex::encode(info.ed25519_public), z);
        assert_eq!(hex::encode(info.static_public.to_bytes()), z);
        assert_eq!(hex::encode(info.ephemeral_public.to_bytes()), z);
        assert_eq!(hex::encode(&info.ephemeral_signature), sig);
    }

    #[test]
    fn parses_connect_rejects_bad_input() {
        assert!(parse_connect("CONNECT NL-ABC alice nothex nothex nothex nothex").is_none());
        assert!(parse_connect("CONNECT NL-ABC alice").is_none());
        assert!(parse_connect("MSG hello").is_none());
    }

    #[test]
    fn parses_accept_with_keys() {
        let z = zeros_hex();
        let sig = "00".repeat(64);
        let (nl, ed, sp, ep, sg) =
            parse_accept(&format!("ACCEPT NL-ABC {} {} {} {}", z, z, z, sig)).unwrap();
        assert_eq!(nl, "NL-ABC");
        assert_eq!(hex::encode(ed), z);
        assert_eq!(hex::encode(sp.to_bytes()), z);
        assert_eq!(hex::encode(ep.to_bytes()), z);
        assert_eq!(hex::encode(&sg), sig);
        assert!(parse_accept("ACCEPT only-one").is_none());
    }

    #[test]
    fn identity_verification_blocks_impersonation() {
        // Signer A: valid identity.
        let (signing_key, verifying_key) = crypto::generate_keypair();
        let ed_pub = verifying_key.to_bytes();
        let nl_id = crate::types::format_nl_id(&ed_pub);
        let (eph_secret, eph_pub) = crypto::generate_ephemeral();
        let sig = crypto::sign_message(&signing_key, &eph_pub.to_bytes());
        let sig_bytes = sig.to_bytes();
        let _ = eph_secret;

        // Honest peer passes all checks.
        assert!(
            verify_peer_identity(&nl_id, &ed_pub, &[], &eph_pub, &sig_bytes).is_ok(),
            "honest handshake should verify"
        );

        // Claimed key doesn't hash to the NL-ID -> rejected.
        assert!(
            verify_peer_identity("NL-FFFF-FFFF-FFFF", &ed_pub, &[], &eph_pub, &sig_bytes).is_err()
        );

        // Stored contact key mismatch -> rejected.
        assert!(
            verify_peer_identity(&nl_id, &ed_pub, &[9u8; 32], &eph_pub, &sig_bytes).is_err()
        );

        // Attacker re-signs with a different identity -> rejected.
        let (attacker_signing, _) = crypto::generate_keypair();
        let forged_sig = crypto::sign_message(&attacker_signing, &eph_pub.to_bytes());
        assert!(
            verify_peer_identity(&nl_id, &ed_pub, &[], &eph_pub, &forged_sig.to_bytes()).is_err()
        );

        // Tampered signature bytes -> rejected.
        let mut tampered = sig_bytes;
        tampered[0] ^= 0xff;
        assert!(
            verify_peer_identity(&nl_id, &ed_pub, &[], &eph_pub, &tampered).is_err()
        );
    }

    #[test]
    fn frame_text_strips_framing_noise() {
        assert_eq!(frame_text(b"  hello \r\n"), "hello");
    }
}