use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use std::fs;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tracing::{info, error, warn};

pub const TOR_PROXY_ADDR: &str = "127.0.0.1:9050";

/// Get path to tor.exe (same dir > %APPDATA%)
pub fn get_tor_path() -> PathBuf {
    if std::path::Path::new("./tor.exe").exists() {
        return PathBuf::from("./tor.exe");
    }
    let mut path = crate::types::get_config_dir();
    path.push("tor/tor.exe");
    if path.exists() {
        return path;
    }
    PathBuf::from("tor.exe")
}

/// Check if Tor SOCKS5 is open
pub async fn is_tor_ready() -> bool {
    match TcpStream::connect("127.0.0.1:9050").await {
        Ok(_) => true,
        Err(e) => {
            warn!("Tor SOCKS5 not ready: {}", e);
            false
        }
    }
}

/// Check if Tor is already running
pub fn is_tor_running() -> bool {
    use std::net::TcpStream;
    TcpStream::connect("127.0.0.1:9050").is_ok()
}

/// Start Tor daemon + create hidden service, returns (hs_dir, onion_address)
pub fn start_tor_daemon() -> Result<(PathBuf, String), anyhow::Error> {
    // FIX: Check if Tor is already running
    if is_tor_running() {
        let hs_dir = crate::types::get_config_dir().join("tor/hidden_service/hostname");
        if hs_dir.exists() {
            let onion_addr = std::fs::read_to_string(&hs_dir)?.trim().to_string();
            return Ok((hs_dir.parent().unwrap().to_path_buf(), onion_addr));
        }
        return Err(anyhow::anyhow!("Tor is running but no hidden service found"));
    }

    let tor_path = get_tor_path();
    if !tor_path.exists() {
        return Err(anyhow::anyhow!(
            "tor.exe not found in:\n  1. Same folder as nite.exe\n  2. %APPDATA%\\nite\\tor\\"
        ));
    }

    let data_dir = crate::types::get_config_dir().join("tor");
    let hs_dir = data_dir.join("hidden_service");
    fs::create_dir_all(&hs_dir)?;

    let data_dir_str = data_dir.to_str().unwrap().replace("\\", "/");
    let cache_dir_str = data_dir.join("cache").to_str().unwrap().replace("\\", "/");
    let hs_dir_str = hs_dir.to_str().unwrap().replace("\\", "/");

    info!("Starting Tor daemon with hidden service...");
    
    let mut command = Command::new(tor_path);
    command.args(&[
        "--SocksPort", "9050",
        "--DataDirectory", &data_dir_str,
        "--CacheDirectory", &cache_dir_str,
        "--HiddenServiceDir", &hs_dir_str,
        "--HiddenServicePort", "4444",
        "--HiddenServiceVersion", "3",
        "--ClientOnly", "1",
        "--AvoidDiskWrites", "1",
        "--UseBridges", "0",
        "--Log", "notice stdout",
    ]);
    command.stderr(Stdio::inherit());
    
    command.spawn()?;

    // Wait for hostname file (contains .onion address)
    let hostname_path = hs_dir.join("hostname");
    for _ in 0..60 {
        if hostname_path.exists() {
            let onion_addr = fs::read_to_string(&hostname_path)?
                .trim()
                .to_string();
            info!("Hidden service created: {}", onion_addr);
            return Ok((hs_dir, onion_addr));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    
    error!("Failed to generate .onion address");
    Err(anyhow::anyhow!("Failed to generate .onion address. Check %APPDATA%\\nite\\tor\\hidden_service\\ for errors."))
}

/// Wait for FULL bootstrap (7 minutes)
pub async fn wait_for_full_bootstrap() -> Result<(), anyhow::Error> {
    info!("Waiting for Tor to bootstrap (this may take 1-2 minutes)...");
    for i in 0..420 {
        if is_tor_ready().await {
            if i > 60 && i % 30 == 0 {
                info!("Still waiting for Tor... ({}s elapsed)", i);
            }
            if is_tor_fully_bootstrapped().await {
                info!("Tor fully bootstrapped!");
                return Ok(());
            }
        }
        sleep(Duration::from_secs(1)).await;
    }
    error!("Tor failed to bootstrap within 7 minutes");
    Err(anyhow::anyhow!(
        "Tor failed to bootstrap.\n\
        🔍 DEBUG INFO:\n\
        1. Check if tor.exe is in the same folder as nite.exe\n\
        2. Run `tor.exe --version` manually to verify it works\n\
        3. Check %APPDATA%\\nite\\tor\\notices.log for Tor errors\n\
        4. Try on a different network (some ISPs block Tor)\n\
        5. Allow 'tor.exe' through Windows Firewall"
    ))
}

/// Check if Tor can build circuits
pub async fn is_tor_fully_bootstrapped() -> bool {
    match connect_via_tor("check.torproject.org:443").await {
        Ok(_) => true,
        Err(e) => {
            warn!("Tor circuit test failed: {}", e);
            false
        }
    }
}

fn parse_address(address: &str) -> anyhow::Result<(String, u16)> {
    if let Some((host, port_str)) = address.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| anyhow::anyhow!("Invalid port in address: {}", address))?;
        Ok((host.to_string(), port))
    } else {
        Ok((address.to_string(), 4444))
    }
}

pub async fn connect_via_tor(address: &str) -> anyhow::Result<TcpStream> {
    start_tor_daemon()?;

    let (host, port) = parse_address(address)?;
    let proxy_addr: SocketAddr = TOR_PROXY_ADDR.parse()?;

    let mut stream = TcpStream::connect(proxy_addr).await?;

    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response != [0x05, 0x00] {
        return Err(anyhow::anyhow!("SOCKS5 proxy rejected no-auth connection"));
    }

    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(anyhow::anyhow!("Hostname too long for SOCKS5"));
    }

    let mut request = Vec::with_capacity(7 + host_bytes.len());
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Err(anyhow::anyhow!("SOCKS5 proxy returned an invalid response"));
    }
    if header[1] != 0x00 {
        return Err(anyhow::anyhow!("SOCKS5 connection failed with code {}", header[1]));
    }

    match header[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await?;
        }
        _ => return Err(anyhow::anyhow!("SOCKS5 response used an unsupported address type")),
    }

    Ok(stream)
}