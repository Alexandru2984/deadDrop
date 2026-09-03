# Vendored noble cryptography (MIT, © Paul Miller)

ML-KEM-768 (FIPS 203, post-quantum KEM) and its minimal dependency closure,
vendored so Dead Drop stays free of package managers, bundlers and third-party
origins (CSP `script-src 'self'`).

| File | Source package | Original path |
|---|---|---|
| `ml-kem.js` | `@noble/post-quantum@0.6.1` | `ml-kem.js` |
| `_crystals.js` | `@noble/post-quantum@0.6.1` | `_crystals.js` |
| `pq-utils.js` | `@noble/post-quantum@0.6.1` | `utils.js` |
| `sha3.js` | `@noble/hashes@2.2.0` | `sha3.js` |
| `hash-utils.js` | `@noble/hashes@2.2.0` | `utils.js` |
| `_u64.js` | `@noble/hashes@2.2.0` | `_u64.js` |
| `fft.js` | `@noble/curves@2.2.0` | `abstract/fft.js` |

Two modifications, both mechanical:

1. Bare import specifiers become relative paths (`@noble/hashes/sha3.js` →
   `./sha3.js`), so the files load as plain same-origin ES modules under a CSP
   that allows no other origin.
2. Two packages each ship a `utils.js`, so this flat directory renames them
   (`pq-utils.js`, `hash-utils.js`) and the relative specifiers pointing at them
   follow.

Nothing else changes, and that is checked rather than trusted:

```bash
node scripts/verify-vendor.mjs
```

It fetches the pinned tarballs from the registry, applies exactly those two
rewrites — on real import statements only, never inside comments — and compares
byte for byte. CI runs it on every push, so a modified copy fails the build
instead of waiting for someone to remember to diff.

`test/mlkem.selftest.mjs` covers the other half. Dimensions, round trips,
implicit rejection and wrong-key behaviour only establish that the
implementation agrees with itself: one that dropped the implicit-rejection seed
passes every one of them. So it also runs NIST's published ACVP vectors
(`test/vectors/ml-kem-768.json`, rebuilt by `scripts/fetch-mlkem-vectors.mjs`),
which pin the exact key pair, ciphertext and shared secret FIPS 203 requires.

To upgrade: change the pins here and in `scripts/verify-vendor.mjs`, re-copy the
files, and let the verifier tell you whether the copy is clean.
