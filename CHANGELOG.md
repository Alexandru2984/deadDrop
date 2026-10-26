# Changelog

What changed, and whether it matters for your safety. Entries marked
**security** fix something that could have been used against a user; the rest is
everything else worth naming.

To check what you are running: `./deaddrop version` prints the release and the
SHA-256 of the client it serves. The build is reproducible, so the same commit
yields the same binary on any machine with the same Go version — rebuild and
compare rather than take a hash on trust.

## Unreleased

### Security

- **Built with Go 1.26.10.** 1.26.9 carries GO-2026-6809 in crypto/x509, which
  govulncheck reports as reachable from the server.
- **Camera and microphone are never left running for something that is
  over.** Media granted after a call had already ended was adopted anyway —
  live, with the call overlay back on screen. A camera granted after the QR
  dialog closed scanned out of sight until the tab closed. Leaving a room, or
  the other side leaving, while recording kept the microphone live for up to
  two minutes, with the stop button disabled; a double tap opened a second
  microphone stream nothing could stop.
- **The panic button always ends the session on the server.** Its logout
  shared the sign-in rate limit; after a burst of sign-ins from the same
  address it was refused, the tab reloaded as if wiped, and the session
  stayed alive. Logout is no longer rate limited, on any listener.
- **One account can no longer lock everyone out of signing in.** The session
  table had only a global bound, and every sign-in adds a session; one account
  signing in again and again could fill it. An account now holds at most 20
  sessions, its least recently used dropped first, real and decoy apart.
- **A flood of sign-in challenges no longer turns everyone away.** The server
  holds at most 4,096 pending challenges and refused every sign-in once they
  were all taken, which anyone with enough addresses could arrange without an
  account: an IPv6 /48 is 65,536 rate-limit sources. A source now holds at most
  eight, a full table sheds the oldest challenge of whichever source holds the
  most, and challenges last a minute rather than two. A real sign-in, answered
  in seconds, finds a slot; what gets pushed out is the flood.
- **Guessing one account's password from many addresses no longer goes
  faster than from one.** The lockout counted failures per account and
  address, so each address had its own allowance. After 100 failures in an
  hour from all sources together, an account now takes a new sign-in from an
  unfamiliar address once every ten seconds. Addresses it signed in from in
  the last day are never held up, so the guessing cannot lock out the owner.
- **The idle lock keeps time while a phone sleeps.** Timers stop with the
  phone, so a five-minute lock was still waiting the next morning; it now
  checks the wall clock whenever the page comes back. It is also armed after
  a reload, and disarmed by signing out — before, it went on to wipe the
  identity and contacts of someone who had already left.
- **Timed messages expire on time after sleep too**, instead of staying on
  screen until the paused timer caught up. So does the copied room link,
  which is taken back out of the clipboard a minute after copying.
- **A received message's timer starts when it can be seen.** With the
  thirty-second default, a message to someone in another tab ran out before
  it was ever read — and the sender's copy expiring took the reader's with
  it. The reader's timer now starts when the message is on screen, or ten
  minutes after it arrived unseen, and each timer removes only its own copy.
- **Burn after reading waits for a reader.** A message that arrived in a
  background tab, or behind the privacy screen, burned two seconds later in
  front of nobody, and its read receipt took the sender's copy at arrival.
  Both now wait until the message can be seen, and the time to read it grows
  with its length; a received file gets fifteen seconds.
- **Answering a call no longer switches the camera on by itself.** Every
  call was a video call, and Accept turned the callee's camera on. 📞 now
  offers a voice call or a video call, and a video call can be answered with
  voice only; a voice call never asks for the camera.
- **A message that arrives while you read back is not burned out of view.**
  Every new line pulled someone who had scrolled up back to the end, and a
  burning or timed message at the end ran out where it could not be seen.
  The conversation now stays where it is, with a *New messages* button; what
  arrives meanwhile counts as seen once the end is in view.
- **The idle lock no longer wipes the tab in the middle of a call.** Nobody
  touches the screen while they talk, so a five-minute lock ended a call — and
  wiped the identity — five minutes in. A call now counts as someone being
  there, and the clock starts over when it ends.
- **A link with a user name in it is no longer clickable.** In
  `https://bank.example@elsewhere.example` everything before the @ is a user
  name, there to be read as the host; the link goes to elsewhere.example. Such
  addresses are now left as plain text.

### Added

- **Pictures open full screen** at a tap. The view closes by itself when the
  picture's timer runs out, when it burns or is deleted, and when the privacy
  screen comes up — it never keeps showing what the conversation no longer
  has.
- **Copy a message** (📋). As with a room link, the text is taken back out of
  the clipboard a minute later, so a clipboard manager or a synced clipboard
  does not keep it after the message is gone.
- **Stop a file on its way.** ✕ beside the progress of a file being sent
  stops it and withdraws it as a delete for everyone does; each peer drops
  the part that had already arrived and is told the sender stopped it.
- **Switch camera during a call** (🔄, on devices with more than one): the
  front camera to the back and back again, without interrupting the call. The
  self-view of the front camera is mirrored, as in every camera app.
- **Delivered ✓.** A sent message or file is ticked once every recipient's
  client says it arrived. Sending meant only that it had left the tab; on a
  link that dropped a moment later it may have reached nobody. The tick says
  nothing about reading.
- **Reply to a message.** Tap a message, then ↩️; the reply shows which one
  it answers, and tapping the quote goes back to it. Only which message
  travels, never its words: each side quotes its own copy, and the quote is
  wiped when that copy goes — by its timer, a burn or a delete for everyone.
  On a touch screen, swiping a message to the right does the same.
- **Incoming calls ring and vibrate.** A call arrived in silence, so one to a
  tab in the background went unanswered. The tone is generated in the page
  and quiet; *Ring and vibrate for calls* in the privacy options turns it off
  for anyone whose phone must not make a sound.
- **An unanswered call stops ringing.** It used to ring for as long as both
  tabs stayed open. After 45 seconds the caller is told there was no answer,
  and the other side sees a missed call — as it does when the caller hangs up
  first.
- **Delete for everyone.** Tap one of your messages or files, then 🗑️, and it
  is taken off every verified peer's screen as well as yours. The protocol
  could always do this — timers and burn-after-reading use it — but nothing
  let a person withdraw something they had sent. As with every removal here,
  it relies on the other side's client cooperating.

### Changed

- **Back no longer ends a conversation at a touch.** A room lives only in
  the page, and the back button — or a phone's edge swipe — left it, keys and
  all. Back now closes what is open over the conversation, then asks for a
  second press within three seconds.
- **The screen stays on through a call or a file transfer.** A phone that
  dimmed and locked suspended the tab: video froze for the other side and a
  transfer stalled until it failed. The lock is let go as soon as nothing
  needs it.
- **Rooms, TURN credentials and connections are limited per account**, not
  per address, so people behind one carrier NAT or office address no longer
  share — and cannot spend — each other's allowance.
- **A message or call that arrives while the tab is away marks the tab
  title**, and a ring is announced on the privacy screen instead of hidden
  under it — that someone is calling, not who.
- **The typing indicator follows each person in a room**, so one member's
  message no longer hides another still typing.
- **Waiting alone in a room survives the phone sleeping.** The server drops
  a tab that stops answering after a minute; on waking it now joins the same
  room again, instead of sitting in a room the server no longer had it in.
- **The invitation and the room status follow a language switch**, instead
  of staying in the language they were first drawn in.
- **A second tap on Create or Join is ignored** while the first is still
  waiting on the network, so a slow connection cannot end up showing one
  room's invitation while connected to another.

- **Tor Browser is told why Dead Drop stops.** It turns WebRTC off on purpose,
  and the refusal used to suggest "a current Firefox" to someone already in one.
  It now says WebRTC is switched off, and that the WebRTC connection would not
  go through Tor in any case.
- **Account actions say what happened, and keep saying it.** Results used to
  flash through the button label for two seconds, unannounced to screen
  readers; a too-short decoy password showed nothing at all, and a failed
  delete that was not a wrong password signed out as if the account were gone.
  Each section now has its own status line.
- **A voice recording can be discarded** — stopping it was the only way out,
  and stopping sent it. Safari's recordings are named `.m4a`, not `.webm`.
- **Files show their progress to the sender too**, and as a percentage on both
  sides rather than a count of transfer chunks.
- **A refused copy says so**, with the link or code selected for a manual copy,
  instead of looking copied.
- **The decoy password follows the real password's strength rule and cannot
  equal it.** The server only holds verifiers, so the browser is the one place
  the two can be compared.
- The burn badge is translated, the timer menu says "No timer" instead of "No
  TTL", the message field's hint stays on one line on small phones, and the
  language button is a full-size touch target.

### Development

- govulncheck runs daily and in `deploy.sh`, not only on push. CI actions are
  pinned by commit and off the deprecated Node 20 runtime.

## 0.5.0 — 2026-10-19

**Update when you can.** Your messages no longer tell the other person your
device's clock, photos and voice notes no longer carry the moment they were
made in their names, and the server can no longer end a running conversation.
No protocol change: a tab on 0.4.0 and one on 0.5.0 talk to each other.

### Security

- **Messages no longer carry the sender's clock.** Every encrypted envelope,
  text body and file description held `Date.now()` to the millisecond. The
  receiver never used it, but it handed the other person this device's clock
  skew — enough to recognise the same device in a later room, which sessions
  without saved contacts promise cannot be done.
- **Voice notes and photos no longer name the moment they were made.** Voice
  notes went out as `voice-<milliseconds>.webm`; they are `voice.webm` now and
  shown as a voice message. With photo metadata stripping on, a camera- or
  screenshot-generated name (`IMG_20261014_153212.jpg`, `Screenshot 2026-…`)
  is replaced by `photo.jpg`, since it carried the capture time EXIF did. Names
  a person chose are kept.
- **The server can no longer end a running conversation.** When anyone's
  signaling socket closed, the server's "peer left" made the other side tear
  down a verified, still-open direct session. A server — which the design does
  not trust — could end any conversation by saying so, and one phone switching
  networks ended it for both.

- **Lookalike link hosts are shown for what they are.** Addresses in messages
  became links in this release; one whose host uses another script — `аpple.com`
  with a Cyrillic а — is shown in punycode (`xn--pple-43d.com`) instead of as
  the name it imitates.

### Fixed

- A network change no longer ends a conversation: an interrupted direct
  connection has ten seconds to recover, and the same session and safety code
  carry on if it does.
- Losing the server while alone in a room rejoins it automatically, with
  backoff; during a conversation the room says it continues directly and that
  nobody new can join until the server is back.
- Typing a room code nobody else is in no longer sits on "Joining room…"
  forever: the server confirms a join, and the room shows that it is waiting,
  with the invitation.
- On a phone with the keyboard open the message field was 30px wide.
- With the account panel open, the account and logout buttons were pushed
  above the top of the screen, out of reach.
- Server errors, connection states, tooltips and the call screens are now
  translated; the Romanian ring said "call in progress" for an unanswered call.
- The QR and call dialogs are modal for the keyboard too: Tab past their last
  control used to reach the message field and panic button hidden behind them.
- The notes under the privacy switches were drawn at 3.5:1 contrast; they now
  meet WCAG AA, and the contrast check measures painted opacity on every view.

### Changed

- The safety-code bar folds to one line once everyone is verified, uses icons
  for route and method in groups, and stays within half the screen.
- The side that has not confirmed yet is told when the other has, worded to
  send them back to the code rather than to the button.
- Incoming calls name the caller; a live call shows who it is with and for how
  long; recording a voice note shows a live microphone and a timer.
- The privacy switches fold into one section that turns amber when IP hiding
  is off; the account panel is grouped, with deletion set apart.
- Received files are a compact row with a Save button; a desktop conversation
  keeps to a readable column; the invitation is centred in an empty room and
  can be sent through the phone's share sheet.
- Messages can have more than one line (Shift+Enter, or the return key on a
  phone), never sent mid-IME composition; web addresses become links that open
  without a referrer and are never previewed; a screenshot pasted into the
  message field is sent as an image, while pasted text stays text.
- The client is served gzip-compressed and its module graph is preloaded: the
  first load went from about 436 KB to 157 KB, and startup on a 150 ms link
  from about 1.33 s to 0.95 s. Pages stay no-store, so no visit is cached.
- The security page and the code verifier are published in Romanian, and the
  security page describes protocol v6 and what the other person learns from
  what you send. The 404 page reads in both languages.

## 0.4.0 — 2026-10-13

**Update now.** The emoji safety code could be steered by whoever relays the
handshake, which is the attack the code exists to stop. Protocol v6; a tab
still running 0.3.0 cannot connect to one running 0.4.0 and must reload.

### Security

- **The emoji safety code can no longer be steered by a man in the middle.**
  It was derived from the full key exchange, including the KEM ciphertext — a
  value the encapsulating side picks after seeing everything else. Someone
  relaying the handshake could make itself the encapsulator and keep
  re-encapsulating until both of its sessions showed the same six emoji: 2^36
  attempts, within reach of rented GPUs while two people wait for a code. The
  code is now a hash of the committed values alone. Protocol v6; a tab still
  running v5 is refused and must reload.
- **A removed or reordered message ends the session.** Each envelope was
  authentic on its own, so whoever terminates the DTLS transport could delete a
  message — a burn notice, the last thing someone said — without either side
  seeing a thing. Envelopes now carry their stream position inside the
  encryption.
- **A received file can no longer run as a page on this origin.** The peer's
  declared type was kept, so a file labelled `text/html` or `image/svg+xml`,
  opened from its link in a new tab, was a document at Dead Drop's own address.
  Only raster images and plain audio/video keep their type now; everything else
  is an opaque download. File names lose bidirectional overrides and invisible
  characters, so `invoice‮fdp.exe` cannot pass for a PDF.
- **Rotating IPv6 addresses no longer resets the login lockout.** Limits were
  kept per address, and anyone with IPv6 holds at least 2^64 of them. They are
  now kept per /64, the block a provider actually hands out.
- The unauthenticated endpoints (`/api/health`, `/api/me`, `/api/config`) are
  rate limited; each health probe parks a goroutine on the hub.
- **One onion visitor can no longer lock everyone else out.** All onion
  traffic shared one rate-limit bucket and one login lockout per account. With
  tor's circuit IDs (`ONION_PROXY_PROTOCOL=1`), limits apply per circuit under a
  shared ceiling, and tor's proof-of-work defence is on.
- **Every JavaScript module is hash-checked by the browser**, not just the
  entry script. Before, `crypto.js`, the handshake and the ML-KEM code were
  trusted because they arrived; anything in the path could have replaced them
  while the page's own hashes still held.
- **Session cookies are not held in memory**, only their SHA-256. A memory dump
  holds nothing a browser could present.
- **Built with Go 1.26.9.** 1.26.7 carries eleven standard-library advisories
  (net/http, net/textproto, crypto/tls, os) that govulncheck now reports.

### Added

- **Photos lose their metadata before they leave.** JPEG, PNG and WebP are
  re-encoded on the device, so GPS position, capture time and camera details
  never reach the other person. On by default; if a photo cannot be cleaned it
  is not sent rather than sent as it was.
- **Hiding your IP from the other person is now the default** whenever a relay
  is configured. Without one the app falls back to a direct connection and says
  so in the conversation.

- **Change your password from the account panel.** It re-proves the current
  password and signs out every other session.
- **Copied room codes and links leave the clipboard after a minute**, and at
  once on a panic wipe. Clipboard managers keep history and some systems sync it
  between devices.
- **New passwords need at least 12 characters**, may not contain the handle, and
  may not be one of the shapes every guessing list tries first. Existing
  passwords still log in.

- **The safety-code row says how each person was checked**: QR (all 128
  bits), emoji (36 bits, with a nudge towards the QR), or a saved contact. The
  confirmation prompt recommends the QR too.
- **Each person's row says whether they can see your IP address**, from the
  ICE pair the browser actually selected: through the relay (hidden) or direct
  (visible). It is re-read every fifteen seconds, since ICE can switch.
- **Generate a passphrase**: six words from the EFF short list, about 62 bits,
  drawn without modulo bias, shown so it can be written down, on registration
  and in the password-change panel.
- **Wipe the tab when idle.** After 5, 15, 30 or 60 minutes without a key or
  tap, the tab does what the panic button does; it warns in the conversation
  thirty seconds before. Off by default.
- **Typing notices can be switched off**, so the other person never learns
  when you are composing.
- The disappearing-message timer keeps the last lifetime you chose instead of
  resetting to thirty seconds in every room.
- **Settings are remembered** between visits — only switches, never people or
  rooms, and a damaged entry reads as the protective default rather than off.
  The panic wipe clears them.
- The privacy screen now also covers the conversation when the window loses
  focus, which is when a phone's app switcher takes its snapshot.
- **Tor Browser is offered the onion service.** The clearnet site sends
  `Onion-Location`, derived from the onion origin already in `ALLOWED_ORIGINS`,
  so a Tor user can load the app without Cloudflare in the path.

### Operations

These live on the server, not in the binary; DEPLOY.md describes each.

- The TURN relay keeps no logs, refuses every special-purpose address range,
  and has 840 relay ports instead of 41. journald keeps seven days.
- Onion visitors are limited per Tor circuit, with tor's proof-of-work defence
  on.
- `deaddrop doctor` runs hourly, compares every delivered file rather than
  two, and fails if the relay starts logging again.
- nginx no longer swaps in a host-wide `robots.txt` or names its version.

### Fixed

- **Every message in a two-person room showed the word "null"** above its
  text, since the Trusted Types refactor on 30 August. The DOM's `append()`
  prints a null child instead of skipping it; the tests only ever read the text
  node.
- **`/verify.html` told every visitor not to trust the page.** It refuses
  redirects, and the server answers `/index.html` with one, so the file that
  carries every other hash always showed "fetch failed". A host-wide
  `robots.txt` that nginx swapped in made a second mismatch. Both are fixed, and
  `doctor` now compares every file in the manifest, not two.
- On phones between 420 and 600px wide, the header's call and panic buttons
  were painted over the room code.
- Phone layout: the safety code no longer breaks across lines, the bar shrinks
  once everyone is verified, a phone on its side keeps the composer on one row
  so the conversation has room, and the attach and record buttons get the
  44px touch width the rest already had.
- Voice notes arrived as a generic file instead of a player: the recorder's
  type carries a codec parameter, which the old type check rejected.

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
