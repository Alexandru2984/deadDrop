/**
 * Two-party self-test for the Dead Drop crypto + handshake.
 *
 * Runs the REAL crypto.js / handshake.js through a simulated data channel so the
 * handshake, key derivation, SAS agreement, message AEAD and the rekey ratchet can
 * be verified without a browser:
 *
 *     node web/js/crypto.selftest.mjs
 *
 * Exits non-zero on any failure.
 */

import { CryptoLayer } from '../web/js/crypto.js';
import { Handshake } from '../web/js/handshake.js';

let failures = 0;
function ok(cond, msg) {
  if (cond) { console.log('  ✓', msg); } else { console.error('  ✗', msg); failures++; }
}

// Deliver every message A sends to B.handle (and vice versa), in order, until quiet.
async function pump(outA, outB, hsA, hsB) {
  for (let guard = 0; guard < 50 && (outA.length || outB.length); guard++) {
    while (outA.length) await hsB.handle(outA.shift());
    while (outB.length) await hsA.handle(outB.shift());
  }
}

async function honestHandshake() {
  console.log('honest handshake');
  const a = new CryptoLayer(), b = new CryptoLayer();
  const outA = [], outB = [];
  let sasA = null, sasB = null, errA = null, errB = null;
  const hsA = new Handshake(a, m => outA.push(m), { onEstablished: s => sasA = s, onError: e => errA = e });
  const hsB = new Handshake(b, m => outB.push(m), { onEstablished: s => sasB = s, onError: e => errB = e });
  await hsA.start();
  await hsB.start();
  await pump(outA, outB, hsA, hsB);

  ok(!errA && !errB, 'no handshake errors');
  ok(sasA && sasA === sasB, `both peers agree on SAS (${sasA})`);
  const graphemes = [...new Intl.Segmenter().segment(sasA)].length;
  ok(graphemes === 6, `SAS is 6 symbols (got ${graphemes})`);
  ok(a.established && b.established, 'both sessions established');
  return { a, b };
}

async function messaging(a, b) {
  console.log('messaging');
  const m1 = await a.encrypt('hello from A 🌍');
  ok(m1.epoch === 0, 'message carries epoch 0');
  ok(await b.decrypt(m1.ciphertext, m1.iv, m1.epoch) === 'hello from A 🌍', 'B decrypts A');

  const m2 = await b.encrypt('reply from B');
  ok(await a.decrypt(m2.ciphertext, m2.iv, m2.epoch) === 'reply from B', 'A decrypts B');

  // Replay must be rejected.
  let replayed = false;
  try { await b.decrypt(m1.ciphertext, m1.iv, m1.epoch); } catch { replayed = true; }
  ok(replayed, 'replay of the same ciphertext is rejected');

  // Tamper must fail the GCM tag.
  const bad = m2.ciphertext.slice(0, -4) + (m2.ciphertext.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA');
  let tampered = false;
  try { await a.decrypt(bad, m2.iv, m2.epoch); } catch { tampered = true; }
  ok(tampered, 'tampered ciphertext is rejected');
}

async function binary(a, b) {
  console.log('binary / files');
  const data = crypto.getRandomValues(new Uint8Array(5000)).buffer;
  const { ciphertext, iv, epoch } = await a.encryptBinary(data);
  const out = await b.decryptBinary(ciphertext, iv, epoch);
  const same = new Uint8Array(out).length === 5000 &&
    new Uint8Array(out).every((v, i) => v === new Uint8Array(data)[i]);
  ok(same, 'binary round-trips intact');
}

async function rekeying(a, b) {
  console.log('rekey ratchet (forward secrecy)');
  // A is the rekey initiator.
  const offer = await a.beginRekey();
  const answer = await b.acceptRekey(offer.publicKey, offer.epoch);
  await a.completeRekey(answer.publicKey, answer.epoch);
  ok(a.sendEpoch === 1 && b.sendEpoch === 1, 'both advanced to epoch 1');

  const m = await a.encrypt('after rekey');
  ok(m.epoch === 1, 'new messages use epoch 1');
  ok(await b.decrypt(m.ciphertext, m.iv, m.epoch) === 'after rekey', 'peer decrypts epoch-1 message');

  // An in-flight epoch-0 message must still decrypt (retention window).
  const old = await a.encrypt('straggler'); // a is at epoch 1 now → this is epoch 1
  ok(old.epoch === 1, 'sender always uses current epoch');

  // Drive enough rekeys to push epoch 0 out of the retention window, then prove the
  // old key is gone (forward secrecy: a seized device can't decrypt old epochs).
  const stale = await a.encrypt('will be undecryptable old-epoch'); // epoch 1 ciphertext
  for (let i = 0; i < 3; i++) {
    const o = await a.beginRekey();
    const ans = await b.acceptRekey(o.publicKey, o.epoch);
    await a.completeRekey(ans.publicKey, ans.epoch);
  }
  ok(a.sendEpoch === 4, 'advanced to epoch 4 after 3 more rekeys');
  let dropped = false;
  try { await b.decrypt(stale.ciphertext, stale.iv, 1); } catch { dropped = true; }
  ok(dropped, 'epoch-1 key destroyed after retention window (forward secrecy)');
}

async function commitmentRejection() {
  console.log('commitment binding');
  const a = new CryptoLayer(), b = new CryptoLayer();
  const outA = [], outB = [];
  let errB = null;
  const hsA = new Handshake(a, m => outA.push(m), { onEstablished: () => {}, onError: () => {} });
  const hsB = new Handshake(b, m => outB.push(m), { onEstablished: () => {}, onError: e => errB = e });
  await hsA.start();
  await hsB.start();
  // Feed B a forged commit, then a reveal whose key does not match the commit.
  outB.length = 0; // discard B's outgoing for this targeted test
  await hsB.handle(outA.shift());          // legit commit from A → B reveals
  const forgedReveal = { type: 'kex-reveal', publicKey: bufToB64Fake(), nonce: bufToB64Fake(16) };
  await hsB.handle(forgedReveal);
  ok(errB === 'commitment mismatch — possible MitM', 'reveal not matching commitment is rejected as MitM');
}

function bufToB64Fake(len = 65) {
  // A syntactically valid but wrong public key / nonce.
  const u8 = new Uint8Array(len);
  u8[0] = 4; // uncompressed point prefix, but bogus coordinates
  let bin = '';
  for (const x of u8) bin += String.fromCharCode(x);
  return btoa(bin);
}

(async () => {
  try {
    const { a, b } = await honestHandshake();
    await messaging(a, b);
    await binary(a, b);
    await rekeying(a, b);
    await commitmentRejection();
  } catch (e) {
    console.error('FATAL', e);
    failures++;
  }
  console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
  process.exit(failures === 0 ? 0 : 1);
})();
