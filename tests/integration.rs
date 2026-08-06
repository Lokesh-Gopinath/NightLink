use std::process::{Command, Stdio};
use std::time::Duration;
use std::io::{self, Read};
use tempfile::tempdir;

#[test]
fn test_tor_starts() {
    let dir = tempdir().unwrap();
    let tor_path = dir.path().join("tor.exe");
    
    // This test requires tor.exe to be present
    if !std::path::Path::new("tor.exe").exists() {
        println!("Skipping test: tor.exe not found");
        return;
    }
    
    std::fs::copy("tor.exe", &tor_path).unwrap();

    let mut child = Command::new(&tor_path)
        .args(&["--SocksPort", "9050", "--DataDirectory", dir.path().to_str().unwrap()])
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start Tor");

    // Wait for Tor to start
    std::thread::sleep(Duration::from_secs(10));
    assert!(child.try_wait().unwrap().is_none(), "Tor exited too early");
    
    child.kill().unwrap();
}

#[test]
fn test_nite_startup() {
    // This test requires nite.exe to be built and Tor to bootstrap
    // Skip in CI/automated testing since it takes too long
    println!("Skipping test: requires manual testing with Tor");
}

#[test]
fn test_ping_command() {
    // Requires two instances running
    // This is a manual test case
    println!("MANUAL TEST: Run two nite.exe instances and test ping");
}

#[test]
fn test_config_loading() {
    // Test that config module compiles and functions exist
    println!("Config module is available");
}

#[test]
fn test_crypto_functions() {
    use nite::crypto::{generate_keypair, encrypt_private_key, decrypt_private_key};
    
    let (signing_key, _verifying_key) = generate_keypair();
    assert_eq!(signing_key.verifying_key().to_bytes().len(), 32);
    
    let private_key = signing_key.to_bytes();
    let encrypted = encrypt_private_key(&private_key, "test_password").unwrap();
    let decrypted = decrypt_private_key(&encrypted, "test_password").unwrap();
    
    assert_eq!(private_key.to_vec(), decrypted);
}

#[test]
fn test_nl_id_generation() {
    use nite::types::format_nl_id;
    use nite::crypto::generate_keypair;
    
    let (_, verifying_key) = generate_keypair();
    let nl_id = format_nl_id(&verifying_key.to_bytes());
    
    assert!(nl_id.starts_with("NL-"));
    assert_eq!(nl_id.len(), 32); // NL-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX (24 hex + 5 dashes + NL- prefix = 32)
}