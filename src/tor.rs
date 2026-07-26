//! Tor SOCKS5 proxy connection for nite
//!
//! Provides functions to connect to a peer's onion address via a local
//! Tor daemon's SOCKS5 proxy (typically on 127.0.0.1:9050).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::net::SocketAddr;

/// Default Tor SOCKS5 proxy address
pub const TOR_PROXY_ADDR: &str = "127.0.0.1:9050";

/// Connect to a peer via Tor SOCKS5 proxy
pub async fn connect_via_tor(onion_address: &str) -> anyhow::Result<TcpStream> {
    let (host, port) = parse_onion_address(onion_address)?;

    let proxy_addr: SocketAddr = TOR_PROXY_ADDR.parse()
        .map_err(|e| anyhow::anyhow!("Invalid proxy address {}: {}", TOR_PROXY_ADDR, e))?;

    let stream = TcpStream::connect(proxy_addr).await
        .map_err(|e| anyhow::anyhow!("Failed to connect to Tor proxy at {}: {}", TOR_PROXY_ADDR, e))?;

    socks_handshake(stream, &host, port).await
}

/// Parse an onion address into host and port
fn parse_onion_address(address: &str) -> anyhow::Result<(String, u16)> {
    if let Some((host, port_str)) = address.rsplit_once(':') {
        let port: u16 = port_str.parse()
            .map_err(|_| anyhow::anyhow!("Invalid port in address: {}", address))?;
        Ok((host.to_string(), port))
    } else {
        Ok((address.to_string(), 4444))
    }
}

/// Perform SOCKS5 handshake to establish a connection through Tor
async fn socks_handshake(
    mut stream: TcpStream,
    host: &str,
    port: u16,
) -> anyhow::Result<TcpStream> {
    // Step 1: Send greeting (SOCKS5, no auth)
    let greeting = [0x05, 0x01, 0x00];
    stream.write_all(&greeting).await?;

    // Step 2: Read server response
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(anyhow::anyhow!("SOCKS5 handshake failed: proxy rejected no-auth"));
    }

    // Step 3: Send connect request (domain name type)
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(anyhow::anyhow!("Hostname too long for SOCKS5"));
    }

    let mut connect_request = Vec::with_capacity(7 + host_bytes.len());
    connect_request.push(0x05);
    connect_request.push(0x01);
    connect_request.push(0x00);
    connect_request.push(0x03);
    connect_request.push(host_bytes.len() as u8);
    connect_request.extend_from_slice(host_bytes);
    connect_request.extend_from_slice(&port.to_be_bytes());

    stream.write_all(&connect_request).await?;

    // Step 4: Read server response
    let mut connect_response = [0u8; 4];
    stream.read_exact(&mut connect_response).await?;

    if connect_response[0] != 0x05 {
        return Err(anyhow::anyhow!("SOCKS5: invalid version in response"));
    }
    if connect_response[1] != 0x00 {
        let status = connect_response[1];
        let err_msg = match status {
            0x01 => "general SOCKS server failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(anyhow::anyhow!("SOCKS5 connection failed: {} (code {})", err_msg, status));
    }

    // Read the rest of the response based on address type
    let addr_type = connect_response[3];
    match addr_type {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let domain_len = len_buf[0] as usize;
            let mut rest = vec![0u8; domain_len + 2];
            stream.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await?;
        }
        _ => {
            return Err(anyhow::anyhow!("SOCKS5: unsupported address type in response"));
        }
    }

    Ok(stream)
}

/// Check if Tor is available by attempting to connect to the SOCKS5 proxy
pub async fn check_tor_status() -> Result<bool, anyhow::Error> {
    let proxy_addr: SocketAddr = TOR_PROXY_ADDR.parse()?;
    match TcpStream::connect(proxy_addr).await {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_onion_address_with_port() {
        let (host, port) = parse_onion_address("abc123.onion:4444").unwrap();
        assert_eq!(host, "abc123.onion");
        assert_eq!(port, 4444);
    }

    #[test]
    fn test_parse_onion_address_without_port() {
        let (host, port) = parse_onion_address("abc123.onion").unwrap();
        assert_eq!(host, "abc123.onion");
        assert_eq!(port, 4444);
    }

    #[test]
    fn test_parse_onion_address_invalid_port() {
        let result = parse_onion_address("abc123.onion:notaport");
        assert!(result.is_err());
    }
}