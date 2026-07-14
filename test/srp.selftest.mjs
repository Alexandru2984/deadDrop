/**
 * SRP-6a self-test + cross-implementation vector generator.
 *
 *   node test/srp.selftest.mjs            # run the JS client↔server flow
 *   node test/srp.selftest.mjs --vectors  # also print fixed vectors for the Go test
 *
 * The fixed vectors are asserted byte-for-byte by internal/srp/srp_test.go, which
 * proves the browser client and the Go server speak the identical protocol.
 */

import { register, ClientLogin, DEFAULT_KDF, _srp } from '../web/js/srp.js';

const { N, g, kParam, computeX, modpow, pad, bytesToBig, bigToHex, hexToBig, bytesToHex, sha256, concat } = _srp;

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

// Minimal JS "server" using the same primitives, to exercise the client.
async function serverB(b, v) {
  const k = await kParam();
  return (k * v + modpow(g, b, N)) % N;
}
async function serverVerify(Ahex, Bbig, b, v, M1hex) {
  const A = hexToBig(Ahex);
  if (A % N === 0n) throw new Error('A ≡ 0');
  const u = bytesToBig(await sha256(concat(pad(A), pad(Bbig))));
  const S = modpow((A * modpow(v, u, N)) % N, b, N);
  const Sp = pad(S);
  const expectM1 = bytesToHex(await sha256(concat(pad(A), pad(Bbig), Sp)));
  if (expectM1 !== M1hex) return null;
  const M2 = bytesToHex(await sha256(concat(pad(A), hexToBytesLocal(M1hex), Sp)));
  return { M2, K: bytesToHex(await sha256(Sp)) };
}
function hexToBytesLocal(h) {
  const u8 = new Uint8Array(h.length >> 1);
  for (let i = 0; i < u8.length; i++) u8[i] = parseInt(h.substr(i * 2, 2), 16);
  return u8;
}

async function randomFlow(kdf, label) {
  console.log(`SRP random client↔server flow (${label})`);
  const username = 'alice', password = 'correct horse battery staple';
  const { salt, verifier, kdf: usedKdf } = await register(username, password, kdf);
  ok(usedKdf === kdf, 'register reports the kdf it used');
  const v = hexToBig(verifier);

  // Login (honest) — the client stretches per the advertised kdf.
  const client = new ClientLogin(username, password);
  const { A } = client.start();
  const b = bytesToBig(crypto.getRandomValues(new Uint8Array(32)));
  const B = await serverB(b, v);
  const { M1 } = await client.finish(salt, bigToHex(B), kdf);
  const srv = await serverVerify(A, B, b, v, M1);
  ok(srv !== null, 'server accepts correct client proof M1');
  ok(srv && client.verifyServer(srv.M2), 'client accepts server proof M2 (mutual auth)');
  ok(srv && srv.K === client.K, 'both derive the same session key K');

  // Wrong password must fail.
  const bad = new ClientLogin(username, 'wrong password');
  bad.start();
  const Bb = await serverB(b, v);
  const { M1: badM1 } = await bad.finish(salt, bigToHex(Bb), kdf);
  const badSrv = await serverVerify(bigToHex(bad.A), Bb, b, v, badM1);
  ok(badSrv === null, 'server rejects wrong-password proof');

  return { salt, verifier };
}

async function kdfHardening() {
  console.log('PBKDF2 password stretch');
  const username = 'alice', password = 'correct horse battery staple';
  // Same password + same salt must yield DIFFERENT proofs with vs without the
  // stretch — evidence the KDF actually feeds the x derivation.
  const { salt } = await register(username, password, '');
  const b = bytesToBig(crypto.getRandomValues(new Uint8Array(32)));
  const B = await serverB(b, 3n); // arbitrary group element; only x differs below
  const legacy = new ClientLogin(username, password);
  legacy.start();
  const stretched = new ClientLogin(username, password);
  stretched.start();
  const m1a = (await legacy.finish(salt, bigToHex(B), '')).M1;
  const m1b = (await stretched.finish(salt, bigToHex(B), DEFAULT_KDF)).M1;
  ok(m1a !== m1b, 'stretched and legacy derivations disagree (kdf is in effect)');

  // Unknown KDF labels must be refused, never silently skipped.
  let threw = false;
  try { await register(username, password, 'argon2id:1'); } catch { threw = true; }
  ok(threw, 'unsupported kdf label is rejected');

  threw = false;
  try { await register(username, password, 'pbkdf2:5000001'); } catch { threw = true; }
  ok(threw, 'excessive kdf cost is rejected before WebCrypto work');

  const malformed = new ClientLogin(username, password);
  malformed.start();
  threw = false;
  try { await malformed.finish('00', bigToHex(B), DEFAULT_KDF); } catch { threw = true; }
  ok(threw, 'non-canonical salt is rejected');

  threw = false;
  try { await malformed.finish(salt, N.toString(16), DEFAULT_KDF); } catch { threw = true; }
  ok(threw, 'out-of-range server public value is rejected before SRP math');
}

async function printVectors() {
  console.log('\n# Fixed cross-impl vectors (copy into internal/srp/srp_test.go)');
  const username = 'alice', password = 'correct horse battery staple';
  const salt = Uint8Array.from({ length: 16 }, (_, i) => i);          // 000102…0f
  const a = bytesToBig(Uint8Array.from({ length: 32 }, (_, i) => i + 1));
  const b = bytesToBig(Uint8Array.from({ length: 32 }, (_, i) => i + 100));

  const x = await computeX(salt, username, password);
  const v = modpow(g, x, N);
  const A = modpow(g, a, N);
  const B = await serverB(b, v);
  const client = new ClientLogin(username, password, a);
  client.start();
  const { M1 } = await client.finish(bytesToHex(salt), bigToHex(B));
  const srv = await serverVerify(bigToHex(A), B, b, v, M1);

  const out = {
    saltHex: bytesToHex(salt),
    aHex: bigToHex(a), bHex: bigToHex(b),
    vHex: bigToHex(v), Ahex: bigToHex(A), Bhex: bigToHex(B),
    M1hex: M1, M2hex: srv.M2, Khex: srv.K,
  };
  for (const [key, val] of Object.entries(out)) console.log(`  ${key} = ${val}`);
  ok(client.verifyServer(srv.M2), 'fixed-vector flow self-consistent');
}

(async () => {
  await randomFlow('', 'legacy, no stretch');
  await randomFlow(DEFAULT_KDF, DEFAULT_KDF);
  await kdfHardening();
  if (process.argv.includes('--vectors')) await printVectors();
  console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
  process.exit(failures === 0 ? 0 : 1);
})();
