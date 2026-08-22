use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
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
    // Tor writes its own logs to stdout/stderr. Suppress them so raw notices
    // (e.g. timeout recalibration) never interleave with the NightLink UI.
    // Failures still surface through our own timeouts and error messages.
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    
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

/// Maximum time we are willing to wait for Tor to reach full bootstrap.
pub const BOOTSTRAP_TIMEOUT_SECS: u64 = 600;

/// Wait until Tor can actually build circuits (full bootstrap), printing
/// friendly progress updates to the console. Gives slow/unstable networks a
/// full 10 minutes instead of failing early.
pub async fn wait_for_full_bootstrap() -> Result<(), anyhow::Error> {
    let timeout = Duration::from_secs(BOOTSTRAP_TIMEOUT_SECS);
    let started = Instant::now();
    let mut last_reported: u64 = 0;

    while started.elapsed() < timeout {
        // Completion check: SOCKS port open AND a real circuit works.
        if is_tor_ready().await && is_tor_fully_bootstrapped().await {
            println!(
                "[nite] Tor connected successfully ({}s).",
                started.elapsed().as_secs()
            );
            return Ok(());
        }

        let elapsed = started.elapsed().as_secs();
        if elapsed >= last_reported + 30 {
            last_reported = elapsed;
            println!("[nite] Still bootstrapping... {}s elapsed.", elapsed);
        }
        sleep(Duration::from_secs(1)).await;
    }

    Err(anyhow::anyhow!(
        "Tor did not finish bootstrapping within 10 minutes.\n\
         Common causes:\n\
         1. Your network or firewall is blocking Tor\n\
         2. Your internet connection is unstable\n\
         3. Your system clock is incorrect\n\
         Please check your connection and restart NightLink."
    ))
}

/// Check if Tor can build circuits (single attempt; used by bootstrap polling)
pub async fn is_tor_fully_bootstrapped() -> bool {
    match connect_via_tor_once("check.torproject.org:443").await {
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

/// Connect through the local Tor SOCKS5 proxy, retrying transient failures
/// up to 3 times before giving up.
pub async fn connect_via_tor(address: &str) -> anyhow::Result<TcpStream> {
    start_tor_daemon()?;
    connect_with_retries(address, 3).await
}

/// Single-attempt variant used by internal health probes (retrying there
/// would slow down bootstrap polling).
pub async fn connect_via_tor_once(address: &str) -> anyhow::Result<TcpStream> {
    start_tor_daemon()?;
    connect_with_retries(address, 1).await
}

async fn connect_with_retries(
    address: &str,
    max_attempts: u32,
) -> anyhow::Result<TcpStream> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=max_attempts {
        match try_connect_via_socks(address).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last_err = Some(e);
                if attempt < max_attempts {
                    crate::chat::bg_print(&format!(
                        "[nite] Tor connection unstable. Retrying (attempt {}/{}).",
                        attempt + 1,
                        max_attempts
                    ));
                    sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }
    Err(anyhow::anyhow!(
        "Tor connection failed after {} attempts: {}. \
         Check your network/firewall or restart NightLink.",
        max_attempts,
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

/// One SOCKS5 connection attempt through the local Tor proxy.
async fn try_connect_via_socks(address: &str) -> anyhow::Result<TcpStream> {
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
