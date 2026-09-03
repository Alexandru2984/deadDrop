# Vendored third-party code

Everything the browser runs is served from this origin: the CSP allows no other,
and the whole bundle is compiled into the server binary. That keeps package
managers, bundlers and CDNs out of the trust chain — but it moves the supply
chain from "a tool resolves this at build time" to "somebody copied these files
once", which is only an improvement if the copy is checked.

| File | Package | Version | Modification |
|---|---|---|---|
| `noble/*` | `@noble/post-quantum`, `@noble/hashes`, `@noble/curves` | 0.6.1, 2.2.0, 2.2.0 | import specifiers → relative paths; `utils.js` renamed (see `noble/README.md`) |
| `jsqr.js` | `jsqr` | 1.4.0 | three provenance comment lines prepended |
| `qrcode.js` | `qrcode-generator` | 1.5.2 | `export default qrcode;` appended |

```bash
node scripts/verify-vendor.mjs      # fetch the pinned tarballs and diff
node scripts/verify-vendor.mjs --offline
```

It applies exactly the modification declared for each file and compares byte for
byte. CI runs it on every push, so a modified copy fails the build rather than
waiting for someone to remember to diff.

## Notes

`jsqr.js` decodes camera frames during safety-code verification, so it is the
one vendored file that parses input an attacker can put in front of the lens. It
is loaded lazily, only when the user opens QR verify.

`qrcode-generator`'s `qrcode.js` is byte-identical across 1.4.4, 1.5.0 and
1.5.2; the pin names the newest of those. The 2.x line restructured the package
and ships no `qrcode.js` at the root, so moving to it is a real change rather
than a version bump.

The ML-KEM implementation is additionally checked against NIST's published ACVP
vectors — see `noble/README.md`, and `test/mlkem.selftest.mjs` for why sizes and
round trips are not enough.

Checked for known advisories via the GitHub advisory database and `npm audit`
against these exact versions: none, as of 2026-09-03.
