# NightLink - Tor-Based P2P Encrypted Chat

A minimal, privacy-focused chat application that runs exclusively over the Tor network.

## Features
✅ Tor-only (no direct mode)
✅ End-to-end encrypted chat
✅ Auto-generated NL-ID
✅ Contact management
✅ Connection notifications (accept/reject)
✅ Fast Tor bootstrap (~30-60s)
✅ Debug mode for troubleshooting
✅ Comprehensive test suite

## Installation
1. Download the latest release from GitHub
2. Extract the ZIP to any folder
3. Ensure `tor.exe` is in the same folder as `nite.exe`

## Usage

### First Time Setup
1. Double-click `nite.exe`
2. Tor will bootstrap (takes ~1-2 minutes on first run)
3. Enter a passphrase when prompted
4. Your NL-ID and Tor address will be generated

### Share Your Info
Give friends:
- Your **NL-ID** (e.g., `NL-5AC6-37C8-CB21`)
- Your **Tor address** (e.g., `abc123.onion:4444`)

### Add a Friend
```bash
contact add <their-NL-ID> <nickname> <their-tor-address>
```
Example:
```bash
contact add NL-A1B2-C3D4-E5F6 alice xyz789.onion:4444
```

### Start a Chat
```bash
ping <nickname>
```
Example:
```bash
ping alice
```

### Accept Incoming Chats
When someone pings you:
```bash
[nite] alice wants to connect. Type 'accept alice' or 'reject alice'
```
Type: `accept alice`

## Commands
| Command | Description |
|---------|-------------|
| `init` | Initialize your identity |
| `fingerprint` | Show your NL-ID and Tor address |
| `contact add` | Add a contact |
| `contact list` | List contacts |
| `ping` | Start a chat |
| `pending` | Show pending connections |
| `accept` | Accept a chat request |
| `reject` | Reject a chat request |
| `help` | Show this help |
| `exit` | Quit |

## Debug Mode

### Enable Debug Logging
```bash
# Windows
set RUST_LOG=debug
nite.exe

# Linux/macOS
RUST_LOG=debug ./nite
```

### Debug Output Levels
| Level | Purpose |
|-------|---------|
| `ERROR` | Critical failures (e.g., Tor not found) |
| `WARN` | Non-critical issues (e.g., slow bootstrap) |
| `INFO` | Normal operations (e.g., "Starting Tor") |
| `DEBUG` | Detailed info (e.g., connection attempts) |
| `TRACE` | Low-level details (e.g., packet data) |

## Common Errors & Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `tor.exe not found` | Missing tor.exe | Place tor.exe in same folder as nite.exe |
| `Bootstrap failed` | Firewall/ISP blocking | Allow tor.exe in firewall or try different network |
| `Config file locked` | Multiple instances | Close other nite.exe processes |
| `Connection refused` | Tor not ready | Wait for 100% bootstrap |
| `No such file or directory` | Missing data dir | Check %APPDATA%\nite\tor\ permissions |

## Building from Source

### Prerequisites
- Rust 1.70+
- tor.exe (from https://www.torproject.org)

### Build Steps
```bash
# Clone the repo
git clone https://github.com/yourusername/nite
cd nite

# Download tor.exe
# Get from: https://www.torproject.org/dist/v0.4.8.10/tor-win32-0.4.8.10.zip
# Extract Tor/tor.exe to the project root

# Build release
cargo build --release

# Run tests
cargo test

# Create ZIP for distribution
zip nite-portable.zip target/release/nite.exe tor.exe
```

## Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_crypto_functions

# Run with output
cargo test -- --nocapture
```

## Test Cases
| Test | Description |
|------|-------------|
| `test_tor_starts` | Verifies Tor daemon starts correctly |
| `test_nite_startup` | Verifies ASCII art and prompt appear |
| `test_crypto_functions` | Verifies encryption/decryption works |
| `test_nl_id_generation` | Verifies NL-ID format |
| `test_ping_command` | Manual test for chat functionality |

## Requirements
- Windows 7+
- Tor daemon (`tor.exe` included in release)
- Internet connection (for Tor bootstrap)

## License
GPL-3.0

## Contributing
Pull requests are welcome. Please ensure all tests pass before submitting.