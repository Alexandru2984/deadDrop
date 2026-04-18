# 💀 Dead Drop

Anonymous, end-to-end encrypted, self-destructing peer-to-peer chat.

No accounts. No servers storing messages. No trace left behind.

## Architecture

```
┌──────────┐   WebSocket    ┌─────────────┐   WebSocket    ┌──────────┐
│  Peer A  │ ◄────────────► │  Signaling  │ ◄────────────► │  Peer B  │
│ (Browser)│                │   Server    │                │ (Browser)│
└────┬─────┘                └─────────────┘                └────┬─────┘
     │                                                          │
     │            WebRTC Data Channel (direct P2P)              │
     │◄────────────────────────────────────────────────────────►│
     │                                                          │
     │  1. ECDH key exchange (P-256)                            │
     │  2. AES-256-GCM encrypted messages                      │
     │  3. TTL + burn-after-reading self-destruct               │
     └──────────────────────────────────────────────────────────┘
```

**The signaling server only relays WebRTC connection data.** It never sees encryption keys or message content.

### Layers

| Layer | Location | Purpose |
|---|---|---|
| **Networking** | `internal/signaling/` | Go WebSocket hub, room management, peer relay |
| **P2P** | `web/js/peer.js` | WebRTC data channel setup and management |
| **Encryption** | `web/js/crypto.js` | ECDH key exchange + AES-256-GCM |
| **Messages** | `web/js/messages.js` | TTL timers, burn-after-reading, bilateral deletion |
| **App** | `web/js/app.js` | Orchestrates all layers, manages UI |

## Quick Start

### Prerequisites

- **Go 1.21+**

### Build & Run

```bash
# Build
cd /path/to/deaddrop
go build -o deaddrop ./cmd/server/

# Run (defaults to port 8088, auto-finds available port)
./deaddrop

# Or specify a port
PORT=9000 ./deaddrop
```

### Two-Peer Chat (Local Test)

1. Start the server:
   ```bash
   ./deaddrop
   ```
2. Open **two browser tabs** at the URL shown (e.g., `http://localhost:8088`)
3. In tab 1: click **Create Room** → copy the 6-character room code
4. In tab 2: paste the code → click **Join**
5. Once the status shows 🔒 **End-to-end encrypted**, start chatting

## Features

### Encryption
- **ECDH P-256** ephemeral key exchange (new keys per connection)
- **AES-256-GCM** symmetric encryption for all messages
- Keys exchanged over WebRTC data channel (signaling server never sees them)
- Nonce-based replay attack protection
- All key material destroyed on disconnect

### Self-Destruct
- **TTL timer**: messages auto-delete after 10s / 30s / 1min / 5min
- **Burn after reading**: message destroyed 2s after the peer reads it
- Deletion is **bilateral** — both peers' copies are destroyed
- Burn animation on destruction

### Privacy
- No accounts, no login
- Random peer ID generated per session
- No message persistence (in-memory only)
- No logs of message content
- Minimal metadata (room code + peer ID, both ephemeral)

## Project Structure

```
deaddrop/
├── cmd/server/main.go          # Entry point + port detection
├── internal/signaling/
│   ├── hub.go                  # Channel-based room manager
│   ├── peer.go                 # WebSocket peer + message relay
│   └── signaling_test.go       # Integration tests
├── web/
│   ├── index.html              # UI
│   ├── css/style.css           # Dark minimal theme
│   └── js/
│       ├── app.js              # Main orchestrator
│       ├── crypto.js           # Encryption layer
│       ├── peer.js             # WebRTC P2P layer
│       ├── messages.js         # Self-destruct lifecycle
│       └── util.js             # Shared helpers
├── go.mod
├── go.sum
└── .gitignore
```

## Security Notes

- ✅ All messages encrypted before transmission (never plaintext on the wire)
- ✅ Ephemeral keys — no long-term key storage
- ✅ Crypto-secure random for IDs, nonces, room codes
- ✅ Replay protection via nonce tracking
- ✅ Signaling server is metadata-minimal (relays opaque blobs)
- ⚠️ STUN server (`stun.l.google.com:19302`) used for NAT traversal — Google sees IP addresses
- ⚠️ No TURN fallback — peers behind symmetric NAT may not connect

## Future Work

- [ ] Multi-peer mesh rooms
- [ ] File transfer with self-destruct
- [ ] Onion-style multi-hop relay
- [ ] Custom STUN/TURN servers
- [ ] Screenshot detection (best-effort)
- [ ] Burn confirmation animation effects
- [ ] Mobile-optimized UI
