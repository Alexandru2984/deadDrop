# 💀 Dead Drop

Browser-based, peer-to-peer chat with mutually verified end-to-end encryption.
Conversation content is not stored by the server. Dead Drop is pseudonymous, not
anonymous by default: the service and its network providers can observe metadata,
and deletion from another person's device can never be guaranteed.

## Security model at a glance

Dead Drop protects message/file content against passive network observers and the
signaling/TURN service when all of the following are true:

- both people received the intended client code on uncompromised browsers;
- both confirm the same safety code over a separate trusted channel (or scan the
  full QR token); and
- neither endpoint is compromised while plaintext or keys are in use.

It does not hide account, IP, room-membership, timing, or traffic-volume metadata
from every party. It also cannot stop a peer from copying plaintext or a server
from delivering malicious JavaScript on a future visit. This custom protocol has
extensive automated tests, but has not had an independent professional
cryptographic audit.

## Architecture

```text
┌──────────┐  authenticated WebSocket  ┌─────────────┐  authenticated WebSocket  ┌──────────┐
│ Browser A│ ◄────────────────────────► │ Signaling   │ ◄────────────────────────► │ Browser B│
└────┬─────┘                            │ server      │                            └────┬─────┘
     │                                  └─────────────┘                                 │
     │                  WebRTC (direct, or through self-hosted TURN)                   │
     │◄────────────────────────────────────────────────────────────────────────────────►│
     │  hybrid P-256 + ML-KEM-768 handshake → mutually checked safety code             │
     │  AES-256-GCM application envelopes; DTLS-SRTP media bound to that session       │
     └───────────────────────────────────────────────────────────────────────────────────┘
```

The Go server relays bounded SDP/ICE signaling; it does not receive application
encryption keys or plaintext. At runtime it can nevertheless associate an
authenticated handle/session with a source IP, room code, peer ID, other room
members, timing, and the SDP/ICE candidates it relays. With TURN, the VPS also
sees both clients' network endpoints and traffic volume.

The browser bundle is embedded in the Go binary. Loose files under `web/` are
not read at runtime, preventing an accidental or unauthorized live file edit from
changing the client served by an already-built binary.

## Protocol and implementation

### Pairwise content encryption

- Protocol v4 combines ephemeral P-256 ECDH and ML-KEM-768, then uses
  HKDF-SHA256 to derive independent AES-256-GCM keys for each direction and
  content class.
- A commit/reveal transcript, key confirmation, protocol/epoch AAD, strict field
  lengths, and per-epoch replay tracking bind and authenticate the handshake.
- Application traffic remains locked until both users confirm the safety code.
  The six emoji encode 36 bits; QR verification compares the full 128-bit token.
- Rooms contain at most six people and form a mesh of independent pairwise
  sessions. There is no group key; each peer must be verified separately.
- The initiator performs an authenticated fresh-ECDH rekey about every ten
  minutes. The current and two previous epochs are retained for in-flight data.
  This gives limited key-evolution/forward-secrecy properties, not a formally
  verified Double Ratchet guarantee. JavaScript can drop key references but
  cannot prove physical memory erasure by the browser or OS.
- ML-KEM is intended to resist harvest-now/decrypt-later attacks if the primitive,
  vendored implementation, browser runtime, and hybrid construction remain sound;
  “post-quantum” is a design goal, not a promise against future cryptanalysis.

### Calls

Voice/video uses WebRTC DTLS-SRTP rather than the application AES envelope. The
exact DTLS fingerprint set is exchanged over the encrypted session and a call is
unlocked only after mutual safety-code verification. A mismatch closes the pair.

### Padding and cover packets

Application envelopes are padded to fixed buckets, which hides exact plaintext
length within a bucket and makes some short control messages resemble short chat
messages. It does not hide packet timing, counts, bucket transitions, large files,
calls, or total volume. Optional cover packets are occasional randomized decoys
(roughly every 4–16 seconds), not constant-rate traffic shaping.

## Data and privacy

- The server persists handles, SRP salts/verifiers/KDF labels, optional duress
  verifiers, invites, and one local anti-enumeration secret. It does not persist
  rooms, peer IDs, chat messages, files, calls, or session cookies across restart.
- Messages/files exist in browser memory and may be downloaded. TTL, burn, and
  bilateral-delete notices are cooperative UI behavior; a peer, extension,
  modified client, screenshot, crash dump, or OS can retain plaintext.
- The panic action clears this tab's in-memory state, closes connections, and
  logs out on a best-effort basis. It cannot wipe the peer, infrastructure logs,
  browser/OS forensic traces, or anything already copied.
- “Relay-only” hides each endpoint's network address from the other peer when
  TURN works. The TURN/VPS operator still sees both endpoint IPs and timing.
- The Go application deliberately omits handles, room codes, peer IDs, and
  message content from its logs. nginx, systemd/journald, Cloudflare, coturn, the
  VPS host, and upstream networks may still record IP/request/traffic metadata.
- There are no third-party browser assets, analytics, or public STUN services.
  The clearnet production path does use Cloudflare; the onion path avoids
  Cloudflare for page/API/signaling delivery, but WebRTC/TURN has separate paths.

### Authentication and duress

Accounts use SRP-6a with PBKDF2-SHA256 (currently 600,000 iterations), so the
password is never sent — there is no endpoint that accepts one, which means no
server response can talk a client into revealing it. A stolen verifier still
permits offline password guesses; PBKDF2 raises their cost but does not make weak
passwords safe.

The optional duress password gives a normal-looking decoy session to the person
using the browser. The server necessarily knows whether a successful proof opened
a primary or duress session, and active coercion/forensics can defeat the illusion;
this is not a cryptographically deniable-authentication protocol.

## Build and local test

Prerequisites: Go 1.25.12+ and Node 22+ for the browser self-tests. The minimum
Go patch level is security-sensitive because the server uses the standard
library for HTTP, cookies, cryptography, and rooted private-file operations.

```bash
go build -o deaddrop ./cmd/server/

# Development only: local WebSocket origins and open registration.
ALLOW_LOCAL_ORIGINS=1 OPEN_REGISTRATION=1 ./deaddrop
```

Open two tabs at the displayed loopback URL, register test handles, create/join a
room, compare the safety code over a separate trusted path, and have both tabs
confirm it. Messaging, files, and calls stay locked until mutual confirmation.

## Project structure

```text
deaddrop/
├── assets.go                    # embeds web/ into the server binary
├── cmd/server/main.go           # server, API routes, runtime validation
├── internal/auth/               # SRP, sessions, credentials, invites
├── internal/signaling/          # bounded WebSocket room/signaling relay
├── internal/srp/                # server-side SRP math
├── internal/strictjson/         # unambiguous protocol JSON decoder
├── internal/turn/               # short-lived coturn REST credentials
├── web/js/crypto.js             # pairwise key schedule and AEAD
├── web/js/handshake.js          # authenticated hybrid handshake
├── web/js/peer.js               # WebRTC, media binding, rekey transport
└── scripts/deploy.sh            # fail-closed test/build/preflight/rollback
```

## Verifying a build

`web/SHA256SUMS` records every served browser asset and entry scripts/styles use
SRI. After changing `web/`, regenerate and review the result:

```bash
node scripts/gen-integrity.mjs
node scripts/gen-integrity.mjs --check
```

The in-app `/verify.html` page can compare the served manifest with the public
repository. An in-page check cannot prove the integrity of code already executing,
cannot detect a targeted response by itself, and cannot make a compromised server
trustworthy. Independent retrieval/pinning or an installed, signed client is
required against that threat.

## Tests

```bash
go vet ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.27.1 -exclude-generated \
  -nosec-require-rules -nosec-require-justification ./...
go run github.com/zricethezav/gitleaks/v8@v8.30.1 git --no-banner --redact .
node test/crypto.selftest.mjs
node test/lifecycle.selftest.mjs
node test/mlkem.selftest.mjs
node test/srp.selftest.mjs
node test/fingerprint.selftest.mjs
node test/config.selftest.mjs
node test/manifest.selftest.mjs
node scripts/gen-integrity.mjs --check
```

The live SRP migration test is `node test/srp.e2e.mjs` against a disposable local
server. Production setup and the required pre-deploy configuration changes are in
[`DEPLOY.md`](DEPLOY.md).
