# nite

**CLI P2P Messenger** -- Encrypted text chat and voice calls over Direct TCP or Tor.

## Features

- End-to-end encrypted text chat (AES-256-GCM)
- Opus-based voice calls with mute/hold/disconnect controls
- Dual transport modes: Direct TCP (low latency) or Tor (anonymous)
- NightLink ID system (NL-ID) for contact management
- Contact address book with aliases
- Zero metadata leakage in Tor mode

## Installation

### Prerequisites

- Rust toolchain (https://rustup.rs)

```bash
git clone https://github.com/yourusername/nite
cd nite
cargo build --release
```

### Voice call support (optional)

Voice requires the Opus C library:

- **Windows**: `vcpkg install opus`
- **Linux**: `apt install libopus-dev`
- **macOS**: `brew install opus`

Then build with voice support:

```bash
cargo build --release --features voice
```

## Usage

### First run (creates your identity)

```bash
nite -m direct init
# or
nite -m tor init
```

This generates your NightLink ID (e.g. `NL-A1B2-C3D4-E5F6`) and keys.

### Start listening for connections

```bash
nite -m direct serve
```

### Add a contact

```bash
nite contact add <NL-ID> --alias alice --direct 192.168.1.5:4444
nite contact list
```

### Start a text chat

```bash
nite -m direct chat 192.168.1.5:4444
nite -m direct chat alice    # using alias
nite -m tor chat abc123.onion:4444
```

### Voice call

```bash
nite -m direct call 192.168.1.5:4444
```

**Call controls:**
- `m` - Mute/unmute microphone
- `h` - Hold/unhold call
- `q` - Hang up

### Show your identity

```bash
nite fingerprint
```

## Architecture

```
User types message -> AES-GCM encrypt -> TcpStream (direct or Tor)
                  <- TcpStream <- AES-GCM decrypt <- display
```

- **Direct mode**: Raw TCP sockets, no dependencies, minimal latency
- **Tor mode**: Routes through local Tor SOCKS5 proxy (127.0.0.1:9050)
- **Encryption**: Ed25519 for identity, AES-256-GCM for messages, SHA256-based key derivation

## Security

- All traffic encrypted end-to-end with AES-256-GCM
- Ed25519 keypairs for identity
- Private keys encrypted at rest with SHA256-derived key (Argon2-ready)
- Tor mode routes all traffic through the Tor network
- No message metadata logged

## License

GPL-3.0