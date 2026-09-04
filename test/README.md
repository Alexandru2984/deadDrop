# Tests

## Crypto / handshake self-test

A two-party simulation that runs the real `web/js/crypto.js` and
`web/js/handshake.js` through an in-memory data channel — no browser needed.

It verifies: the commit-reveal handshake, full transcript binding, directional
and context-separated traffic keys, SAS agreement, mutual verification gating,
AES-GCM message + file round-trips, replay/tamper rejection, authenticated rekey,
old-epoch pruning, and rejection of malformed or manipulated handshakes.

```bash
node test/crypto.selftest.mjs
```

Exits non-zero on any failure. Requires Node 18+ (uses the WebCrypto API).

## Lifecycle / resource-bound self-test

`node test/lifecycle.selftest.mjs` checks peer-scoped message/file IDs, strict
chunk validation, receiver allocation limits, cleanup on disconnect, ordered
outbound delivery, and non-broadcast destruction of another peer's message.

## Call-signaling state machine self-test

`node test/callsignal.selftest.mjs` enumerates every call frame against every
call state and role. The property it pins down: media negotiation is reachable
from exactly one state per side. A peer whose safety code was confirmed can
still be running a patched client, and an offer accepted at the wrong moment
turns on a camera nobody agreed to.

## Vendored cryptography

`node scripts/verify-vendor.mjs` proves the vendored post-quantum code is
upstream noble's, byte for byte. It fetches the pinned npm tarballs, applies the
two documented rewrites (bare specifiers to relative paths, and the `utils.js`
renames the flat vendor directory forced), and diffs. `--offline` reuses a
previously fetched cache.

`test/mlkem.selftest.mjs` then runs NIST's published ACVP vectors. This matters
more than it sounds: an implementation that dropped the implicit-rejection seed
passes every round-trip and size check — verified, it does — and fails all 25
key-generation vectors.

## Parser fuzzing and property tests

The Go parsers that read attacker-controlled bytes are fuzzed natively:

```bash
go test -fuzz FuzzDecodeObject -fuzztime 30s ./internal/strictjson/
```

Targets cover the strict JSON decoder (every API body and WebSocket frame), the
invite-file parser, the DNS hostname validator, the relay envelope, and room
codes. They assert invariants rather than hunting for panics — the one that
matters for the JSON decoder is that its duplicate-key scan and encoding/json
never disagree about what a body says, since that disagreement is the shape of
an auth bypass. Seed corpora run as ordinary `go test`; CI explores 30s per
target on each push.

`node test/property.selftest.mjs` is the browser-side equivalent, since Node has
no fuzzer: it generates structurally plausible garbage for `sanitizeIceConfig`
and `extractFingerprints` and checks the properties that must hold for every
input. `DD_SEED` makes a failure reproducible; CI varies it per run.

## ICE configuration self-test

`node test/config.selftest.mjs` checks that only bounded STUN/TURN URL shapes
and correctly shaped, short-lived coturn REST credentials reach WebRTC.

## Browser suites

`browser.smoke.mjs` (one page), `browser.pair.mjs` (two peers, one real WebRTC
session), `browser.group.mjs` (three peers, a full mesh) and `browser.call.mjs`
(one audio/video call, with the DTLS fingerprint binding checked against the
certificates actually in use) drive headless Chrome over the DevTools Protocol.
## Third engine — WebKit

`webkit.boot.mjs` (one Safari session) and `webkit.cross.mjs` (Safari on one side,
Chrome on the other) run on macOS over classic W3C WebDriver
(`test/lib/webdriver.mjs`). WebKit is the engine every browser on iOS uses, and
the one that cannot be driven from Linux — Safari has no port, and WebKitGTK
ships no driver on the distributions here.

It is not two Safaris because it cannot be: macOS runs one, and its driver
refuses to pair a second session with it. That turned out better. Two peers on
one browser is already covered three times over; someone on an iPhone talking to
someone on a laptop is the case that actually happens.

The driver client was built and checked against `chromedriver`, which speaks the
same protocol, so the only thing CI is trying for the first time is Safari
itself. Locally:

```bash
DD_WEBDRIVER_A=/path/to/chromedriver DD_CAPABILITIES_A='{"browserName":"chrome", ...}' \
DD_WEBDRIVER_B=/path/to/chromedriver DD_CAPABILITIES_B='{"browserName":"chrome", ...}' \
DD_URL=… DD_INVITE=… DD_INVITE2=… node test/webkit.cross.mjs
```

Separate jobs on purpose: the boot check answers whether the client runs on
WebKit at all, and should not be buried by anything the cross-engine run hits.

Safari 26.5.2 passes the boot check — the app starts, every required primitive
is present, nothing is degraded, an account registers, a room opens, and the
vendored ML-KEM agrees with itself there.

## Second engine

`firefox.pair.mjs` runs the core two-peer session on Gecko over WebDriver BiDi
(`test/lib/firefox.mjs` — Firefox dropped CDP, so the suites cannot share a
driver). Everything else here drives Chrome, which on its own only ever says the
app works on Blink, and the client is the whole security product.

It found the app completely broken on Firefox: no session could be established
at all, because a key-exchange message arriving before the data channel's open
event was silently dropped.

```bash
FIREFOX_PATH=/path/to/firefox DD_URL=… DD_INVITE=… DD_INVITE2=… \
  node test/firefox.pair.mjs
```

It skips when no Firefox is present; CI sets `DD_REQUIRE_FIREFOX=1`.

## Browser suites, continued

`browser.a11y.mjs` asks whether this can be used without a mouse and without
seeing it. Checked in a browser rather than by reading markup, because the
answer depends on what the accessibility tree ends up holding — the HTML, the
translations applied at runtime, and whatever the app does to the DOM after.
Every control on the chat screen is an emoji, and one without a name is
announced by its Unicode name: the panic button, which wipes the tab and logs
you out, read as "skull".

`browser.support.mjs` breaks one required crypto primitive at a time and checks
the app refuses to start rather than hand a password box to a browser that
cannot protect it — and that an optional capability going missing degrades a
feature instead of blocking the session.

`browser.hostile.mjs` adds a peer that does not follow the protocol: its bundle
is rewritten on the way into the browser so it can emit any frame at any moment
over a real, properly encrypted, safety-code-confirmed session. Every assertion
in it is about what the *stock* client on the other side refuses to do. Shared plumbing lives in `lib/browser.mjs`. They need no
npm packages — Node 22 has a built-in WebSocket client.

The server allows ten auth requests a minute per address, and one registration
costs several — a room, a TURN config and a session check on top of the
registration itself. Several suites run back to back from one address will trip
that, which is the limiter working rather than a bug: the suites wait for the
bucket to refill and carry on. In CI each suite gets its own runner and its own
server, so it never comes up.

Both skip when no Chromium is on the box, so a developer without one still gets
a green run; CI sets `DD_REQUIRE_BROWSER=1` so a missing browser fails loudly
instead of quietly never running.

If Chromium is present but refuses to start on missing shared libraries, they
can be staged without installing anything system-wide:

```bash
mkdir -p /tmp/chromelibs/debs && cd /tmp/chromelibs/debs
apt-get download libasound2t64 libatk-bridge2.0-0t64 libatspi2.0-0t64 \
                 libatk1.0-0t64 libxres1
for d in *.deb; do dpkg -x "$d" ../root/; done
export LD_LIBRARY_PATH=/tmp/chromelibs/root/usr/lib/x86_64-linux-gnu
```

Then point `CHROME_PATH` at the binary and run the suite. Nothing is installed,
and `rm -rf /tmp/chromelibs` undoes it.
