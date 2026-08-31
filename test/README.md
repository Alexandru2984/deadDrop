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

## ICE configuration self-test

`node test/config.selftest.mjs` checks that only bounded STUN/TURN URL shapes
and correctly shaped, short-lived coturn REST credentials reach WebRTC.

## Browser suites

`browser.smoke.mjs` (one page), `browser.pair.mjs` (two peers, one real WebRTC
session) and `browser.group.mjs` (three peers, a full mesh) drive headless
Chrome over the DevTools Protocol. Shared plumbing lives in `lib/browser.mjs`. They need no
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
