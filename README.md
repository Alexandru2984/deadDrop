# 💀 Dead Drop

Anonymous, end-to-end encrypted, self-destructing peer-to-peer chat.

Invite-only handles (no email, zero-knowledge login). No message storage. No
third-party services. No trace left behind.

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
     │  1. Hybrid key exchange: ECDH P-256 + ML-KEM-768 (PQ)    │
     │  2. AES-256-GCM sealed, length-padded envelopes          │
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

# Run (defaults to port 8088; hunts for a free port only when PORT is unset)
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
3. In tab 1: click **Create Room** → copy the room code
4. In other tabs (up to 5 more): paste the code → click **Join**
5. Once the status shows 🔒 **End-to-end encrypted**, start chatting. In a group,
   verify each peer's safety code row separately.

## Features

### Encryption
- **Hybrid post-quantum key exchange**: ephemeral **ECDH P-256 + ML-KEM-768**
  (FIPS 203) — breaking a recorded session requires breaking both primitives
- **AES-256-GCM** symmetric encryption for all messages
- **Everything is sealed**: typing notices, read receipts, deletes, call
  signaling and file chunks travel in encrypted envelopes **padded to size
  buckets**, so an observer can't tell a typing notice from a short message
- Keys exchanged over WebRTC data channel (signaling server never sees them)
- Nonce-based replay attack protection
- All key material destroyed on disconnect

### Group chat (mesh)
- Rooms hold **up to 6 people**. There is **no group key** — the room is a full
  mesh of **pairwise** end-to-end sessions, each with its own hybrid handshake,
  safety code and ratchet. A member only ever holds key material for their own
  pairs, and every message is encrypted separately for each recipient.
- The safety-code bar shows **one row per peer** — verify each independently
  (emoji or QR). Peers are identified by an ephemeral ID label, not a username
  (the signaling server never learns who is who).
- Voice/video **calls stay 1:1** — offered only in a two-person room.

### Self-Destruct
- **TTL timer**: messages auto-delete after 10s / 30s / 1min / 5min
- **Burn after reading**: message destroyed 2s after the peer reads it
- Deletion is **bilateral** — every peer's copy is destroyed
- Burn animation on destruction

### Privacy
- No accounts, no login
- Random peer ID generated per session
- No message persistence (in-memory only)
- No logs of message content
- Minimal metadata (room code + peer ID, both ephemeral)
- **Cover traffic** (opt-in 🕶️): each session emits constant decoy packets,
  padded to the same size as real messages, so a network observer — or the
  TURN relay in "max anonymity" mode — can't tell when, or whether, you're
  actually chatting

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

- ✅ End-to-end encrypted: AES-256-GCM over a hybrid **ECDH-P256 + ML-KEM-768**
  exchange → HKDF-SHA256 — post-quantum "harvest now, decrypt later" resistant
- ✅ Authenticated key exchange (ZRTP-style commit-reveal) + key confirmation +
  a 6-emoji safety code — verifiable by a **full 128-bit QR scan** — to detect MitM
- ✅ Forward secrecy: the session DH-ratchets every ~10 min (PQ root mixed into
  every epoch) and destroys old keys
- ✅ Traffic-analysis resistance on the channel: all control traffic is encrypted
  and padded to fixed buckets
- ✅ Zero-knowledge login (SRP-6a) — the password never reaches the server or Cloudflare,
  and is stretched with PBKDF2-SHA256 (600k iterations) so even a stolen verifier
  database resists offline cracking
- ✅ Self-hosted STUN/TURN (coturn) with ephemeral credentials — no third-party (Google) STUN
- ✅ "Max anonymity" relay-only mode hides peer IPs from each other
- ✅ Reachable as a Tor v3 onion service (Cloudflare-free, no DNS leak)
- ✅ Invite-only registration, login lockout keyed by account+IP (no lockout DoS),
  strict same-origin + CSP without any 'unsafe-inline'
- ✅ Optional duress (decoy) password; nothing in the API or UI betrays a decoy session
- ✅ No third-party analytics, no message storage, PII-free server logs

See the in-app **Security & Privacy** page (`/about.html`) for the full, honest
threat model — including what Dead Drop does **not** protect against.

## Testing

```bash
go test ./...                      # server (incl. SRP JS↔Go interop vectors)
node test/crypto.selftest.mjs      # hybrid handshake + sealing + ratchet
node test/mlkem.selftest.mjs       # vendored ML-KEM-768 sanity
node test/srp.selftest.mjs         # SRP client↔server (legacy + PBKDF2 kdf)
node test/srp.e2e.mjs              # live SRP against a running server
```

## Deployment

Production setup (systemd, nginx, coturn, Tor, invites) is documented in
[`DEPLOY.md`](DEPLOY.md).

## Future Work

- [ ] Larger rooms (the N² mesh keeps them small today)
