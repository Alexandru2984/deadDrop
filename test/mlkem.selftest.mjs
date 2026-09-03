/**
 * The vendored ML-KEM-768 (web/js/vendor/noble/), checked two ways.
 *
 *   node test/mlkem.selftest.mjs
 *
 * The first half is self-consistency: the ESM loads without a bundler, the sizes
 * are FIPS 203's, encapsulate and decapsulate agree, a tampered ciphertext
 * decapsulates to a *different* secret rather than throwing (so the handshake's
 * key confirmation is what must catch it), and the wrong key does not work.
 *
 * None of that proves the implementation computes the standard. An ML-KEM that
 * drew its shared secret from sixteen bytes of entropy, or seeded itself
 * predictably, would satisfy every one of those assertions — they only say the
 * thing agrees with itself. So the second half runs NIST's own published
 * vectors: given the official d/z, the exact key pair; given the official
 * ek/m, the exact ciphertext and shared secret; given the official dk/c, the
 * exact secret back.
 */

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { ml_kem768 } from '../web/js/vendor/noble/ml-kem.js';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

console.log('ML-KEM-768 vendored self-test');

const { publicKey, secretKey } = ml_kem768.keygen();
ok(publicKey.length === 1184, 'public key is 1184 bytes (FIPS 203)');
ok(secretKey.length === 2400, 'secret key is 2400 bytes (FIPS 203)');

const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
ok(cipherText.length === 1088, 'ciphertext is 1088 bytes (FIPS 203)');
ok(sharedSecret.length === 32, 'shared secret is 32 bytes');

const decapsulated = ml_kem768.decapsulate(cipherText, secretKey);
ok(Buffer.from(decapsulated).equals(Buffer.from(sharedSecret)),
   'decapsulate(encapsulate(pk)) yields the same shared secret');

// Tampered ciphertext → implicit rejection (different secret, no throw).
const tampered = Uint8Array.from(cipherText);
tampered[0] ^= 0x01;
const rejected = ml_kem768.decapsulate(tampered, secretKey);
ok(!Buffer.from(rejected).equals(Buffer.from(sharedSecret)),
   'tampered ciphertext yields a different secret (implicit rejection)');

// Different keypair must not decapsulate to the same secret.
const other = ml_kem768.keygen();
const cross = ml_kem768.decapsulate(cipherText, other.secretKey);
ok(!Buffer.from(cross).equals(Buffer.from(sharedSecret)),
   'wrong secret key yields a different secret');

/* ── Known answers (NIST ACVP, FIPS 203) ── */

console.log('\nagainst NIST\'s published vectors');

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/ml-kem-768.json', import.meta.url), 'utf8'));
const hex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const toHex = (b) => Buffer.from(b).toString('hex');
const sha256 = (b) => createHash('sha256').update(Buffer.from(b)).digest('hex');

let bad = 0;
for (const v of vectors.keyGen) {
  const seed = new Uint8Array(64);
  seed.set(hex(v.d), 0);
  seed.set(hex(v.z), 32);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  if (sha256(publicKey) !== v.ekSha256 || sha256(secretKey) !== v.dkSha256) bad++;
}
ok(bad === 0, `${vectors.keyGen.length} key generations reproduce NIST's exact key pair`);

bad = 0;
for (const v of vectors.encap) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(hex(v.ek), hex(v.m));
  if (sha256(cipherText) !== v.cSha256 || toHex(sharedSecret) !== v.k) bad++;
}
ok(bad === 0, `${vectors.encap.length} encapsulations reproduce NIST's exact ciphertext and secret`);

bad = 0;
for (const v of vectors.decap) {
  if (toHex(ml_kem768.decapsulate(hex(v.c), hex(v.dk))) !== v.k) bad++;
}
ok(bad === 0, `${vectors.decap.length} decapsulations reproduce NIST's exact shared secret`);

// A vector file that silently emptied would turn every check above into a
// no-op, and the run would still be green.
ok(vectors.keyGen.length >= 20 && vectors.encap.length >= 5 && vectors.decap.length >= 5,
   'the vector file is populated, so the checks above ran on something');

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
