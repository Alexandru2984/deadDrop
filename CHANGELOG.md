# Changelog

What changed, and whether it matters for your safety. Entries marked
**security** fix something that could have been used against a user; the rest is
everything else worth naming.

To check what you are running: `./deaddrop version` prints the release and the
SHA-256 of the client it serves. The build is reproducible, so the same commit
yields the same binary on any machine with the same Go version — rebuild and
compare rather than take a hash on trust.

## 0.3.0

### Security

- **Call setup no longer trusts a frame that arrives at the wrong moment.** A
  peer whose safety code you had confirmed could start your camera and speaker
  without you accepting — and again seconds after you declined. Media
  negotiation is now reachable from one state per side and no other.
- **A peer can no longer erase your side of a conversation.** Read receipts were
  honoured for any message, so a modified client could fabricate them for
  ordinary messages and wipe the sender's history while keeping its own copy.
  Receipts now only burn what was actually sent to burn.
- **Cooperative delete is limited to two people.** In a room, a member who was
  not the author could withdraw a message from the author's screen while
  everyone else kept it.
- **A renegotiated call must keep the certificate that was attested**, so media
  cannot move to a DTLS session nobody vouched for.
- **The integrity manifest now covers every module.** Its required-path list had
  six entries while the bundle grew to twenty-three, leaving `srp.js` — which
  turns a password into an SRP proof — and the whole post-quantum implementation
  unguarded against a trimmed manifest.
- **Browsers that cannot run the cryptography are refused** rather than handed a
  password box, with the missing primitive named.
- **Escape no longer wipes your session when you meant to close a dialog.**

### Fixed

- **Dead Drop did not work on Firefox at all.** A key-exchange message arriving
  before the data channel's open event was dropped, so no session could be
  established on Gecko. Found by running the client on a second engine for the
  first time.
- Secondary text sat below the WCAG AA contrast threshold.
- Eighteen messages were hardcoded English in a bilingual app, including
  "do not trust this connection".
- A call that failed mid-negotiation left "Connecting…" on screen for good.

### Added

- Opt-in saved contacts: a long-term identity key, presented only if you ask for
  it, so a peer you verified once is recognised later without comparing again.
  It costs unlinkability between sessions, which is why it is off by default.
- Accessible names, live regions and dialog semantics throughout; the app is
  usable without a mouse or sight.
- An introduction on the sign-in page saying what this is — and what it is not.
- Daily backups of account state, verified by restoring each archive.
- `deaddrop doctor`: configuration, the served bundle, hub liveness, whether the
  deploy matches the source, whether the edge delivers it unchanged, and backup
  freshness.
- `deaddrop version`, and this file.

### Verified

- The vendored post-quantum code is byte-for-byte upstream's, checked on every
  push, and its ML-KEM-768 reproduces NIST's published ACVP vectors — sizes and
  round trips only prove an implementation agrees with itself.
- The client runs on Chromium, Gecko and WebKit, with a Safari-to-Chrome session
  in CI.
- Parsers that read attacker-controlled bytes are fuzzed; the signalling hub is
  checked for leaks under two hundred concurrent sessions.

## 0.2.0 and earlier

Protocol v5: hybrid P-256 + ML-KEM-768 handshake with a commit/reveal
transcript, SRP-6a authentication with no password reaching the server, duress
credentials, invite-only registration, Tor onion access, and the embedded,
integrity-manifested browser bundle. Released before this file existed; the git
history is the record.
