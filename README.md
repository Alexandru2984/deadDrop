# 💀 Dead Drop

Browser-based, peer-to-peer chat with mutually verified end-to-end encryption.
Conversation content is not stored by the server. Dead Drop is pseudonymous, not
anonymous by default: the service and its network providers can observe metadata,
and deletion from another person's device can never be guaranteed.

The landing page and the security model are indexable; the live verifier and
error pages are not. Nothing on any page is loaded from another origin — no
analytics, no CDN font, no verification script — and `test/seo.selftest.mjs`
fails the build if one appears. The preview card is rendered by
`scripts/render-og-image.mjs` and served from here, so unfurling a link to Dead
Drop involves no third party.

A fork should change the host in `web/robots.txt`, `web/sitemap.xml` and the
canonical/`og:` tags. Those are static because the bundle is hashed: a server
that rewrote them per deployment would no longer match its own manifest.

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

- Protocol v6 combines ephemeral P-256 ECDH and ML-KEM-768, then uses
  HKDF-SHA256 to derive independent AES-256-GCM keys for each direction and
  content class.
- A commit/reveal transcript, key confirmation, protocol/epoch AAD, strict field
  lengths, and per-epoch replay tracking bind and authenticate the handshake.
- Application traffic remains locked until both users confirm the safety code.
  The six emoji encode 36 bits; QR verification compares the full 128-bit token.
- The safety code is a hash of the committed reveals only. The KEM ciphertext is
  chosen after both reveals, so it is kept out of the code: otherwise whoever
  encapsulates — including a man in the middle — could re-encapsulate until the
  emoji matched, and 2^36 attempts is hardware, not luck.
- Every sealed envelope carries its position in that direction's stream, inside
  the AEAD. The data channel is reliable and ordered, so a gap or a reordering
  is someone between the peers removing traffic, and it ends the session.
- Rooms contain at most six people and form a mesh of independent pairwise
  sessions. There is no group key; each peer must be verified separately.
- Saved contacts are optional and off by default. While off, nothing that
  outlives a session is generated or presented, and the identity field in the
  handshake is a fixed all-zero block — two conversations with the same person
  are not linkable to each other by either side, and each needs its own
  safety-code comparison.
- Turning them on mints a non-extractable ECDSA P-256 identity key held in
  IndexedDB. It is covered by the handshake commitment and transcript, so the
  safety code already authenticates it, and the peer proves possession with a
  signature over that session's transcript before it can ever be pinned. A
  recognised contact then unlocks without a fresh comparison.
- The trade is explicit: a peer who has seen your identity key can tell two of
  your sessions apart. That is what makes pinning possible and what costs
  unlinkability. A panic wipe destroys the key and every pin.
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

A call is voice or video by the caller's choice, and a video call can be
answered with voice only: the camera is never switched on just by accepting.
An unanswered call stops ringing after 45 seconds. The ring is a tone made in
the page, and can be turned off in the privacy options.

### Padding and cover packets

Application envelopes are padded to fixed buckets, which hides exact plaintext
length within a bucket and makes some short control messages resemble short chat
messages. It does not hide packet timing, counts, bucket transitions, large files,
calls, or total volume. Optional cover packets are occasional randomized decoys
(roughly every 4–16 seconds), not constant-rate traffic shaping.

## Data and privacy

- Sessions live in memory only and die at whichever bound comes first: 30 minutes
  idle, or 12 hours absolute. A primary password change closes every session for
  the account and rotates the changing browser's own token.
- The server persists handles, SRP salts/verifiers/KDF labels, optional duress
  verifiers, invites (single-use, expiring after 14 days by default), and one
  local anti-enumeration secret. It does not persist
  rooms, peer IDs, chat messages, files, calls, or session cookies across restart.
- Messages/files exist in browser memory and may be downloaded. TTL, burn, and
  bilateral-delete notices are cooperative UI behavior; a peer, extension,
  modified client, screenshot, crash dump, or OS can retain plaintext.
- Cooperative removal runs in one direction only when it makes sense. A read
  receipt destroys the sender's copy of a message that was sent to burn, and
  nothing else — a peer cannot fabricate receipts for ordinary messages to erase
  the other side of a conversation while keeping its own. Between two people, a
  peer that burns or deletes its copy still withdraws it from the sender; that
  is the feature, it is announced on screen rather than silent, and a modified
  client can use it to remove messages from your view. In a room of three or
  more it does not apply at all: every other member would keep the message, so
  the only person who lost it would be whoever wrote it.
- A message timer removes only the copy it runs on. Each side runs the same
  timer — the reader's from when the message can be seen, or ten minutes after
  it arrived unseen, whichever is first — so the sender's clock does not take
  the reader's copy before it is read.
- The sender can delete their own message or file for everyone: their copy
  goes, and every verified peer is told to drop theirs, in a room of any size.
  It relies on the peers' clients cooperating like every removal here.
- A reply names the message it answers and never repeats its words: each
  side quotes its own copy, and the quote is wiped when that copy goes, so a
  reply cannot keep a timed or burned message alive.
- A sent message is ticked ✓ once every recipient's client says it arrived —
  that it reached them, not that it was read.
- A file can be stopped by its sender or refused by a receiver while it is
  still on its way; each side drops what had arrived.
- Copying a message takes it back out of the clipboard a minute later, as
  copying a room link does. A picture shown full screen closes with its
  message, and when the privacy screen comes up.
- A burn-after-reading message starts burning only once it can be seen — the
  tab in front and the privacy screen lifted — and the read receipt waits for
  the same moment. Reading time grows with the text, two to thirty seconds;
  a received file gets fifteen. Timed messages, the idle lock and the
  clipboard clear keep wall-clock time, so a phone that slept catches up as
  soon as the page is back.
- The panic action, and the idle lock when set, clear this tab's in-memory
  state, delete the saved identity and pinned contacts, close connections,
  and end the session on the server — logout is never rate limited, so it
  cannot be refused. They cannot wipe the peer, infrastructure logs,
  browser/OS forensic traces, or anything already copied.
- “Relay-only” hides each endpoint's network address from the other peer when
  TURN works. The TURN/VPS operator still sees both endpoint IPs and timing.
- Rate limiting and login lockout key on an HMAC of the source address under a
  per-process secret that is never persisted, so those in-memory maps are not a
  standing list of who used the service. This is not a defence against an
  attacker who already holds full process memory.
- Routes that need a session — rooms, TURN credentials, signalling — are
  limited per account rather than per address, so people behind one carrier NAT
  do not share an allowance. An account holds at most 20 sessions, real and
  decoy counted apart.
- Sign-in holds up against floods and distributed guessing without locking the
  owner out. A source holds at most eight pending SRP challenges and a full
  table sheds the busiest source's oldest one. Past 100 failures in an hour
  from all sources, an account takes a sign-in from an unfamiliar source once
  every ten seconds; a source it signed in from in the last day is exempt,
  which means the server keeps, in memory for a day, the HMAC of the addresses
  each account signed in from.
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

The browser's SRP exponentiation uses JavaScript BigInt, which offers no
constant-time primitives; the modular exponentiation is therefore not
constant-time with respect to the password-derived exponent. Observing that
requires code already running in the victim's browser.

Changing a credential, setting a duress password, and deleting an account each
require a fresh SRP proof of the password the session was opened with, so a
borrowed session cookie cannot by itself rekey, alter, or destroy an account. A
decoy session can only re-prove the duress password, and still receives the same
responses a primary session would.

The optional duress password gives a normal-looking decoy session to the person
using the browser. The server necessarily knows whether a successful proof opened
a primary or duress session, and active coercion/forensics can defeat the illusion;
this is not a cryptographically deniable-authentication protocol.

## Build and local test

Prerequisites: Go 1.26.10+ and Node 22+ for the browser self-tests. The minimum
Go patch level is security-sensitive because the server uses the standard
library for HTTP, cookies, cryptography, and rooted private-file operations —
`os.Root` containment in particular has had escapes fixed across 1.26 patches,
so `govulncheck` is a release gate rather than an advisory.

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

`web/SHA256SUMS` records every served browser asset. Entry scripts and styles use
SRI, and an import map on each page pins a hash for every JavaScript module, so
the browser refuses any module — imported statically or loaded later — whose
bytes differ, rather than only checking the entry point. The server adds that
import map's own hash to the CSP, the only inline script the policy admits. After changing `web/`, regenerate and review the result:

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
for t in crypto lifecycle mlkem srp fingerprint config manifest callsignal \
         ice-grace seo property; do node "test/$t.selftest.mjs"; done
node scripts/gen-integrity.mjs --check
```

The browser suites drive a real Chromium (Firefox and WebKit for their own
files) against a running server. Each wants a fresh server and its own invite
codes, since a suite's failed-login checks count against the per-IP lockout:

```bash
ALLOW_LOCAL_ORIGINS=1 PORT=8100 ./deaddrop &
DD_URL=http://127.0.0.1:8100 DD_INVITE=$(./deaddrop invite) \
  DD_INVITE2=$(./deaddrop invite) DD_INVITE3=$(./deaddrop invite) \
  DD_REQUIRE_BROWSER=1 node test/browser.smoke.mjs
```

The same goes for `browser.{a11y,support,pair,group,call,hostile,integrity}.mjs`.
`DD_SCREENSHOT_DIR=dir` keeps the smoke suite's phone-size screenshots.

The live SRP migration test is `node test/srp.e2e.mjs` against a disposable local
server. Production setup and the required pre-deploy configuration changes are in
[`DEPLOY.md`](DEPLOY.md).
