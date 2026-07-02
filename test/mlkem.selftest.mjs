/**
 * Sanity check for the vendored ML-KEM-768 (web/js/vendor/noble/).
 *
 *   node test/mlkem.selftest.mjs
 *
 * Confirms the vendored ESM loads without a bundler, produces FIPS-203 sizes,
 * and that encapsulate/decapsulate agree — plus the KEM's implicit-rejection
 * property (a tampered ciphertext decapsulates to a DIFFERENT secret rather
 * than an error, so the handshake's key-confirmation must catch it).
 */

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

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
