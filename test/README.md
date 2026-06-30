# Tests

## Crypto / handshake self-test

A two-party simulation that runs the real `web/js/crypto.js` and
`web/js/handshake.js` through an in-memory data channel — no browser needed.

It verifies: the commit-reveal handshake, transcript-bound key derivation, SAS
agreement, AES-GCM message + file round-trips, replay/tamper rejection, the rekey
ratchet, forward secrecy (old epoch keys are destroyed), and that a reveal which
does not match its commitment is rejected as a possible MitM.

```bash
node test/crypto.selftest.mjs
```

Exits non-zero on any failure. Requires Node 18+ (uses the WebCrypto API).
