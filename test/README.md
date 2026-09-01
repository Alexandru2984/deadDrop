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

## ICE configuration self-test

`node test/config.selftest.mjs` checks that only bounded STUN/TURN URL shapes
and correctly shaped, short-lived coturn REST credentials reach WebRTC.

## Browser suites

`browser.smoke.mjs` (one page), `browser.pair.mjs` (two peers, one real WebRTC
session), `browser.group.mjs` (three peers, a full mesh) and `browser.call.mjs`
(one audio/video call, with the DTLS fingerprint binding checked against the
certificates actually in use) drive headless Chrome over the DevTools Protocol.
`browser.hostile.mjs` adds a peer that does not follow the protocol: its bundle
is rewritten on the way into the browser so it can emit any frame at any moment
over a real, properly encrypted, safety-code-confirmed session. Every assertion
in it is about what the *stock* client on the other side refuses to do. Shared plumbing lives in `lib/browser.mjs`. They need no
npm packages — Node 22 has a built-in WebSocket client.

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
