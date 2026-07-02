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

The ONLY modification is rewriting bare import specifiers
(`@noble/hashes/sha3.js` → `./sha3.js`, etc.) to relative paths so the files
load as plain same-origin ES modules; code is otherwise byte-identical to the
published npm artifacts. Verified by `test/mlkem.selftest.mjs`.

To upgrade: `npm pack` the three packages, re-copy these files, re-apply the
specifier rewrites, rerun the selftest.
