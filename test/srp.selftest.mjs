/**
 * SRP-6a self-test + cross-implementation vector generator.
 *
 *   node test/srp.selftest.mjs            # run the JS client↔server flow
 *   node test/srp.selftest.mjs --vectors  # also print fixed vectors for the Go test
 *
 * The fixed vectors are asserted byte-for-byte by internal/srp/srp_test.go, which
 * proves the browser client and the Go server speak the identical protocol.
 */

import { register, ClientLogin, _srp } from '../web/js/srp.js';

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

async function randomFlow() {
  console.log('SRP random client↔server flow');
  const username = 'alice', password = 'correct horse battery staple';
  const { salt, verifier } = await register(username, password);
  const v = hexToBig(verifier);

  // Login (honest).
  const client = new ClientLogin(username, password);
  const { A } = client.start();
  const b = bytesToBig(crypto.getRandomValues(new Uint8Array(32)));
  const B = await serverB(b, v);
  const { M1 } = await client.finish(salt, bigToHex(B));
  const srv = await serverVerify(A, B, b, v, M1);
  ok(srv !== null, 'server accepts correct client proof M1');
  ok(srv && client.verifyServer(srv.M2), 'client accepts server proof M2 (mutual auth)');
  ok(srv && srv.K === client.K, 'both derive the same session key K');

  // Wrong password must fail.
  const bad = new ClientLogin(username, 'wrong password');
  bad.start();
  const Bb = await serverB(b, v);
  const { M1: badM1 } = await bad.finish(salt, bigToHex(Bb));
  const badSrv = await serverVerify(bigToHex(bad.A), Bb, b, v, badM1);
  ok(badSrv === null, 'server rejects wrong-password proof');
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
  await randomFlow();
  if (process.argv.includes('--vectors')) await printVectors();
  console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
  process.exit(failures === 0 ? 0 : 1);
})();
