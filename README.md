# 💀 Dead Drop

Browser-based, peer-to-peer chat with mutually verified end-to-end encryption.
Conversation content is not stored by the server. Dead Drop is pseudonymous, not
anonymous by default: the service and its network providers can observe metadata,
and deletion from another person's device can never be guaranteed.

The landing page, the security model and the guide to what a file gives away
are indexable; the live verifier and error pages are not. Nothing on any page
is loaded from another origin — no analytics, no CDN font, no verification
script — and `test/seo.selftest.mjs` fails the build if one appears. The preview card is rendered by
`scripts/render-og-image.mjs` and served from here, so unfurling a link to Dead
Drop involves no third party.

To run your own instance — Docker, one script, HTTPS and a call relay
included — see [`INSTALL.md`](INSTALL.md). It serves this same client, byte for
byte.

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
- Files go as an offer, numbered parts and an end marker. Each 64 KB part is
  sealed on its own, with the file it belongs to, its position and the total
  number of parts bound into its authentication, so a part cannot be moved to
  another file or place and a file cannot be cut short and still check out.
  The sender reads the file from disk a part at a time and the receiver hands
  what it decrypts to the browser as it goes; neither holds the whole file in
  script memory. Files go up to 1 GB.
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

Either side can show its screen during a call, on desktop browsers. The
screen travels on the call's own picture channel — the one bound to the safety
code — in place of the camera, which is switched off while the screen is shown
and comes back afterwards. Nothing is negotiated again to do it, and nothing a
peer sends can start a capture: only the button, and then the browser's own
picker. The person sharing is told so for as long as it lasts, because a
screen shows whatever is on it — notifications and other windows included.

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
- “Sign out everywhere else” ends every other session of the account after
  re-proving the password, so a stolen cookie cannot use it to throw the
  owner out. From a decoy session it ends only other decoy sessions and
  answers the same way. A browser whose session its owner ended — this, a
  password change, deleting the account — is told so within seconds and
  closes the conversations it still has open; one whose session merely
  expired keeps them, as direct conversations do not need the server. The
  server remembers which sessions were ended, by hash, until each would have
  expired anyway.
- A guest link lets one person into one room without an account. Whoever is in
  the room asks for it; the link carries a one-time pass in its fragment, good
  for 15 minutes and only while the session that made it lasts. Redeeming it
  gives a session with no name, held in memory for at most two hours, that can
  join that room and ask for relay settings — it cannot open rooms, make
  passes or reach any account route, and the room limit is enforced where the
  join happens rather than by the page. The pass is a bearer token and proves
  nothing about who holds it: a guest compares the safety code like anyone
  else, and a guest's browser does not present its saved-contact key. The
  server learns that an account vouched for a guest in a room; it keeps that
  in memory with the session and writes none of it down.
- Two saved contacts can leave each other messages while the other is
  offline. The keys are handed over in a verified session, never through the
  server: each side gives the other the start of a hash chain for its inbox,
  and every message is sealed with the next key in it under a name derived
  from that key, after which the key is forgotten. Two messages for the same
  person share no name, and a browser seized later cannot open anything
  already collected. A new inbox is opened at every meeting. The server keeps
  the sealed box — padded to one of three sizes, one file each in
  `data/drops/`, never in backups — until it is collected or its hour, day or
  week runs out. It sees which account left a box and when, and which account
  asked after it and collected it; who left it is held in memory only, to cap
  an account at 50 waiting boxes. Once opened, a message is shown until closed
  or for 30 seconds or 5 minutes, and is not kept anywhere.
- The server persists handles, SRP salts/verifiers/KDF labels, optional duress
  verifiers, invites (single-use, expiring after 14 days by default), and one
  local anti-enumeration secret, and the sealed boxes of messages left for
  someone offline until they are collected or expire. It does not persist
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
- Nothing of a file larger than 25 MB is sent until the receiver accepts it,
  so nobody has a gigabyte pushed at them over mobile data unasked; an offer
  nobody answers lapses after ten minutes. Smaller files arrive as before.
  A large received file is held by the browser, which may keep it in a
  temporary file on disk, until the conversation ends.
- Metadata stripping, on by default, runs on the sender's device before
  encryption. JPEG photos lose EXIF, XMP and anything appended after the
  picture without re-encoding, keeping only the orientation; PNG, WebP and
  GIF keep only the blocks it takes to draw them, animation included; HEIC, AVIF
  and TIFF are re-encoded as JPEG; MP4/MOV/M4A files have their
  location, device and time boxes blanked in place. Word, Excel, PowerPoint and
  OpenDocument files have their property parts emptied — author, last editor,
  company, template path, times, editing time, custom properties — and every
  part's archive timestamp set to 1980. What names the person out of sight
  goes too: Word's template and mail merge paths keep only their file name,
  Excel's note of the folder it saved in is dropped, comment authors' work
  e-mail or Microsoft account becomes what Office writes for someone signed
  out, and the printer's name and its driver's own data are zeroed, in
  Office's and LibreOffice's copies alike. Identifiers kept through every
  copy, which match a copy to its original, are taken out: Word's and
  LibreOffice's editing-session IDs (rsids), Word's document IDs, Excel's
  document, sheet, table and column IDs, and PowerPoint's last-client
  record; paragraph, comment, slide and shape IDs, which other parts point
  at, are replaced by new random ones, consistently. A document from
  SharePoint or OneDrive loses the library's record in its custom XML — the
  document ID, the address naming the organisation and site, the people it
  was shared with — and a cover page its company address, phone and e-mail.
  The content, including comments and tracked changes with their authors,
  is left as written; a document that still has either — or hidden text,
  sheets or slides, LibreOffice's hidden sections and fields among them, or
  a PDF with comments or a redaction never applied — is
  sent only once the person confirms, after being told whose names they
  carry, or has them taken out: comments go from Word, PowerPoint,
  LibreOffice and PDF files, tracked changes in Word and LibreOffice are
  accepted, Word's hidden text dropped, and a PDF's comments blanked and
  unlisted in place. Hidden sheets and slides, LibreOffice's hidden text,
  Excel comments, a spreadsheet's tracked changes and unapplied redactions
  are only ever sent as they are, or not at all. A PDF's information
  dictionary (in every revision) and XMP streams become spaces in place, so
  the file keeps its length and every offset. Photos inside documents and
  PDFs — kept as the original JPEG, GPS included — have their EXIF, XMP, IPTC
  and comment segments blanked in place, keeping only the orientation, and
  anything a phone appended after the picture (a motion photo's video) cut
  off; PNGs inside lose their text, EXIF and time chunks. A PDF that keeps
  its information dictionary in a compressed object stream, as Ghostscript,
  qpdf and reduced-size saves do, has that stream inflated, blanked and
  compressed back into the bytes it had. A file that cannot be read —
  encrypted, or an object stream that cannot be written back — or one that is
  digitally signed, which any change would break, is sent only if the person
  agrees. Other files go as chosen.
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
  state, delete the saved identity, pinned contacts and preferences, close connections,
  and request server logout. Local clearing does not wait for the network;
  logout is never rate limited, but a network failure can prevent revocation.
  They cannot wipe the peer, infrastructure logs,
  browser/OS forensic traces, or anything already copied.
- “Relay-only” hides each endpoint's network address from the other peer when
  TURN works. Missing or expired relay configuration blocks a new connection
  while this option is on; direct transport requires explicitly turning it off.
  The TURN/VPS operator still sees both endpoint IPs and timing.
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

Prerequisites: Go 1.26.11+ and Node 22+ for the browser self-tests. The minimum
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
For local development without TURN, explicitly turn off “Hide IP from peer” in
both tabs before creating or joining a room. The default never falls back to direct.

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
├── internal/drop/               # sealed boxes left for an offline contact
├── web/js/app.js                # the app: rooms, signaling, sessions, messages
├── web/js/app-*.js              # its other parts: auth, verify, files, calls, drops
├── web/js/crypto.js             # pairwise key schedule and AEAD
├── web/js/handshake.js          # authenticated hybrid handshake
├── web/js/peer.js               # WebRTC, media binding, rekey transport
├── scripts/deploy.sh            # fail-closed test/build/preflight/rollback
├── Dockerfile                   # static binary on a distroless base
└── install/                     # compose stack + setup script (INSTALL.md)
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

Release binaries are built by `.github/workflows/release.yml` from the tagged
commit and attested through Sigstore; `gh attestation verify deaddrop-linux-amd64
--repo Alexandru2984/deadDrop` (gh 2.49 or later) checks one, and rebuilding the tag with the flags
in the release notes gives the same bytes. Release tags cannot be moved or
deleted, and published releases cannot change.

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
for t in crypto lifecycle drops mlkem srp fingerprint config manifest callsignal \
         ice-grace scrub seo property; do node "test/$t.selftest.mjs"; done
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

The same goes for `browser.{a11y,support,pair,group,call,hostile,integrity,guest,drops}.mjs`.
`DD_SCREENSHOT_DIR=dir` keeps the smoke suite's phone-size screenshots.

The live SRP migration test is `node test/srp.e2e.mjs` against a disposable local
server. Production setup and the required pre-deploy configuration changes are in
[`DEPLOY.md`](DEPLOY.md); the containerised install for anyone else is in
[`INSTALL.md`](INSTALL.md).
