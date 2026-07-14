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
