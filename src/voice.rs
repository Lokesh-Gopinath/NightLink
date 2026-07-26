//! Voice call implementation for nite
//!
//! Note: Requires the "voice" feature and Opus C library installed.
//! Build with: `cargo build --features voice`
//! Or simply: `cargo build` (voice is a default feature)

#![cfg_attr(not(feature = "voice"), allow(unused_imports, dead_code, unused_variables))]

use crate::types::TransportMode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::mpsc as sync_mpsc;

struct CallState {
    muted: AtomicBool,
    held: AtomicBool,
}

pub async fn start_call(peer_addr: &str, transport: TransportMode) -> anyhow::Result<()> {
    #[cfg(not(feature = "voice"))]
    {
        let _ = (peer_addr, transport);
        return Err(anyhow::anyhow!(
            "Voice calls require the 'voice' feature. Install Opus C library and rebuild."
        ));
    }

    #[cfg(feature = "voice")]
    actual_start_call(peer_addr, transport).await
}

#[cfg(feature = "voice")]
async fn actual_start_call(peer_addr: &str, transport: TransportMode) -> anyhow::Result<()> {
    println!("[nite] Connecting voice call to {} via {}...", peer_addr, transport);
    let mut stream = crate::p2p::connect(peer_addr, transport).await?;
    println!("[nite] Voice call connected to {}", peer_addr);
    println!("[nite] Controls: [m] mute/unmute  [h] hold/unhold  [q] hang up");

    let config = crate::config::load()?;
    let peer_public_key = crate::p2p::exchange_public_keys(&mut stream, &config.public_key).await?;

    let passphrase = rpassword::prompt_password("[nite] Enter passphrase to decrypt private key: ")?;
    let private_key = crate::crypto::decrypt_private_key(
        &config.private_key_encrypted, &passphrase, &config.salt, &config.nonce,
    )?;
    let shared_secret = crate::crypto::derive_shared_secret(&private_key, &peer_public_key)?;
    println!("[nite] Secure voice channel established (AES-256-GCM + Opus)");

    let (reader, mut writer) = stream.into_split();
    let state = Arc::new(CallState { muted: AtomicBool::new(false), held: AtomicBool::new(false) });
    let (audio_tx, audio_rx) = sync_mpsc::channel::<Vec<f32>>(32);

    let state_stdin = state.clone();
    let stdin_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1];
        loop {
            match stdin.read_exact(&mut buf).await {
                Ok(()) => match buf[0] as char {
                    'm' | 'M' => {
                        let new = !state_stdin.muted.load(Ordering::SeqCst);
                        state_stdin.muted.store(new, Ordering::SeqCst);
                        println!("[nite] {}", if new { "Mic muted" } else { "Mic unmuted" });
                    }
                    'h' | 'H' => {
                        let new = !state_stdin.held.load(Ordering::SeqCst);
                        state_stdin.held.store(new, Ordering::SeqCst);
                        println!("[nite] {}", if new { "Call on hold" } else { "Call resumed" });
                    }
                    'q' | 'Q' => { println!("[nite] Hanging up..."); break; }
                    _ => {}
                },
                Err(_) => break,
            }
        }
    });

    let state_cap = state.clone();
    let audio_tx_clone = audio_tx.clone();
    let capture_task = tokio::task::spawn_blocking(move || {
        let _ = run_audio_capture(&state_cap, audio_tx_clone);
    });

    let state_send = state.clone();
    let ss_send = shared_secret.clone();
    let send_task = tokio::spawn(async move {
        let _ = run_audio_send(&mut writer, &state_send, &ss_send, audio_rx).await;
    });

    let ss_recv = shared_secret.clone();
    let recv_task = tokio::spawn(async move {
        let _ = run_audio_receive(reader, &ss_recv).await;
    });

    tokio::select! {
        _ = stdin_task => {},
        _ = send_task => {},
        _ = recv_task => {},
    }

    capture_task.abort();
    send_task.abort();
    recv_task.abort();
    println!("[nite] Call ended.");
    Ok(())
}

#[cfg(feature = "voice")]
fn run_audio_capture(state: &CallState, audio_tx: sync_mpsc::Sender<Vec<f32>>) -> anyhow::Result<()> {
    let host = cpal::default_host();
    let device = host.default_input_device().ok_or_else(|| anyhow::anyhow!("No input device"))?;
    let config = device.default_input_config()?;
    println!("[nite] Audio input: {} ({} Hz)", device.name()?, config.sample_rate().0);

    let tx = audio_tx.clone();
    let err_fn = |e| eprintln!("[nite] Audio input error: {}", e);
    let stream = device.build_input_stream(&config.into(), move |data: &[f32], _: &cpal::InputCallbackInfo| {
        let _ = tx.send(data.to_vec());
    }, err_fn)?;
    stream.play()?;
    loop { std::thread::sleep(std::time::Duration::from_secs(1)); }
}

#[cfg(feature = "voice")]
async fn run_audio_send(
    writer: &mut tokio::net::OwnedWriteHalf,
    state: &CallState,
    shared_secret: &[u8],
    audio_rx: sync_mpsc::Receiver<Vec<f32>>,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let sr = 48000;
    let mut enc = opus::Encoder::new(sr, opus::Channels::Mono, opus::Application::Voip)?;
    enc.set_bitrate(opus::Bitrate::Bits(24000))?;
    const FRAME: usize = 960;
    let mut out = vec![0u8; 4000];
    loop {
        let mut samples = Vec::with_capacity(FRAME);
        while samples.len() < FRAME {
            match audio_rx.recv() {
                Ok(d) => {
                    if state.muted.load(Ordering::SeqCst) {
                        samples.extend(std::iter::repeat(0.0f32).take(d.len()));
                    } else {
                        samples.extend(d);
                    }
                }
                Err(_) => return Ok(()),
            }
        }
        samples.truncate(FRAME);
        if let Ok(size) = enc.encode_float(&samples, &mut out) {
            if let Ok(encrypted) = crate::crypto::encrypt_message(&out[..size], shared_secret) {
                let len = (encrypted.len() as u32).to_be_bytes();
                let _ = writer.write_all(&len).await;
                let _ = writer.write_all(&encrypted).await;
            }
        }
    }
}

#[cfg(feature = "voice")]
async fn run_audio_receive(
    reader: tokio::net::OwnedReadHalf,
    shared_secret: &[u8],
) -> anyhow::Result<()> {
    use tokio::io::AsyncRead;
    use std::pin::Pin;
    let sr = 48000;
    let mut dec = opus::Decoder::new(sr, opus::Channels::Mono)?;

    let host = cpal::default_host();
    let device = host.default_output_device().ok_or_else(|| anyhow::anyhow!("No output device"))?;
    let config = device.default_output_config()?;
    println!("[nite] Audio output: {} ({} Hz)", device.name()?, config.sample_rate().0);

    let (ptx, prx) = sync_mpsc::sync_channel::<Vec<f32>>(8);
    let err_fn = |e| eprintln!("[nite] Audio output error: {}", e);
    let stream = device.build_output_stream(&config.into(), move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
        if let Ok(audio) = prx.try_recv() {
            let len = data.len().min(audio.len());
            data[..len].copy_from_slice(&audio[..len]);
            for s in data[len..].iter_mut() { *s = 0.0; }
        } else {
            for s in data.iter_mut() { *s = 0.0; }
        }
    }, err_fn)?;
    stream.play()?;

    let mut out_buf = vec![0.0f32; 1920];
    loop {
        let mut len_buf = [0u8; 4];
        if Pin::new(&reader).read_exact(&mut len_buf).await.is_err() { break; }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; len];
        if Pin::new(&reader).read_exact(&mut data).await.is_err() { break; }
        if let Ok(pt) = crate::crypto::decrypt_message(&data, shared_secret) {
            if let Ok(samples) = dec.decode_float(&pt, &mut out_buf, false) {
                let _ = ptx.send(out_buf[..samples].to_vec());
            }
        }
    }
    Ok(())
}