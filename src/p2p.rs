//! P2P connection handling for nite

use crate::types::TransportMode;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedWriteHalf, OwnedReadHalf};

pub async fn connect(addr: &str, transport: TransportMode) -> anyhow::Result<TcpStream> {
    match transport {
        TransportMode::Direct => connect_direct(addr).await,
        TransportMode::Tor => connect_tor(addr).await,
    }
}

async fn connect_direct(addr: &str) -> anyhow::Result<TcpStream> {
    let stream = TcpStream::connect(addr).await
        .map_err(|e| anyhow::anyhow!("Failed to connect to {}: {}", addr, e))?;
    Ok(stream)
}

async fn connect_tor(addr: &str) -> anyhow::Result<TcpStream> {
    crate::tor::connect_via_tor(addr).await
}

pub async fn listen(addr: &str) -> anyhow::Result<tokio::net::TcpListener> {
    let listener = tokio::net::TcpListener::bind(addr).await
        .map_err(|e| anyhow::anyhow!("Failed to listen on {}: {}", addr, e))?;
    Ok(listener)
}

pub async fn send_message(stream: &mut TcpStream, data: &[u8]) -> anyhow::Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    Ok(())
}

pub async fn receive_message(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

pub async fn send_message_write(stream: &mut OwnedWriteHalf, data: &[u8]) -> anyhow::Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    Ok(())
}

pub async fn receive_message_read(stream: &mut OwnedReadHalf) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

pub async fn exchange_public_keys(stream: &mut TcpStream, our_public_key: &[u8]) -> anyhow::Result<Vec<u8>> {
    send_message(stream, our_public_key).await?;
    receive_message(stream).await
}