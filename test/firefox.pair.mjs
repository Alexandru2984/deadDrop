/**
 * The same two-peer session, on Gecko.
 *
 *   DD_URL=… DD_INVITE=… DD_INVITE2=… node test/firefox.pair.mjs
 *
 * Every other suite drives Chrome, so every claim they make about this app is a
 * claim about Blink. The client *is* the security product here, and the engines
 * differ in exactly the places it leans on: WebCrypto surfaces, SDP shapes and
 * ICE behaviour, IndexedDB, storage partitioning.
 *
 * This is deliberately the core and nothing else — handshake, safety code,
 * verification gate, one message each way. If those hold on a second engine,
 * the protocol is not quietly depending on one browser's behaviour.
 */

import { FirefoxPeer, launchFirefox } from './lib/firefox.mjs';
import { waitFor } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITES = [process.env.DD_INVITE || '', process.env.DD_INVITE2 || ''];
const PASS = 'gecko-pair-passphrase-6620';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

if (!INVITES[0] || !INVITES[1]) {
  console.error('firefox pair: set DD_INVITE and DD_INVITE2');
  process.exit(1);
}

const suffix = Math.floor(Math.random() * 1e6);
const USERS = [`zz_fa_${suffix}`, `zz_fb_${suffix}`];
console.log(`Gecko two-peer run against ${BASE} as ${USERS[0]} + ${USERS[1]}`);

const { bidi, cleanup } = await launchFirefox('pair');
const alice = await FirefoxPeer.open(bidi, 'alice');
const bob = await FirefoxPeer.open(bidi, 'bob');

await alice.goto(BASE + '/');
await bob.goto(BASE + '/');
ok(true, 'the app starts on Gecko and clears its own browser-support gate');

ok(await alice.register(USERS[0], INVITES[0], PASS), 'peer A registers');
ok(await bob.register(USERS[1], INVITES[1], PASS), 'peer B registers');

await alice.eval(`document.querySelector('#create-room').click(); true`);
const room = await waitFor(async () => {
  const code = await alice.eval(`document.querySelector('#room-code').textContent`);
  return code && code.length === 24 ? code : false;
});
ok(room, 'peer A creates a room');

await bob.eval(`
  document.querySelector('#room-code-input').value = ${JSON.stringify(room)};
  document.querySelector('#join-room').click(); true
`);
ok(await waitFor(() => bob.inChat()), 'peer B joins over the same signaling');

// The hybrid handshake runs entirely in page script — a different WebCrypto
// implementation reaching the same safety code is the point of this suite.
const sasA = await waitFor(() => alice.sas(), { timeout: 45000 });
const sasB = await waitFor(() => bob.sas(), { timeout: 45000 });
ok(sasA && sasB, 'both peers complete the hybrid handshake on Gecko');
ok(sasA === sasB, `both derive the same safety code (${sasA} / ${sasB})`);

ok(await alice.verified() === false && await bob.verified() === false,
  'traffic stays locked before anyone confirms');
ok(await alice.clickVerify() && await bob.clickVerify(), 'both confirm the code');
ok(await waitFor(() => alice.verified()) && await waitFor(() => bob.verified()),
  'mutual confirmation unlocks both sides');

const fromA = 'gecko says hello ' + suffix;
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(fromA)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await bob.transcript()).includes(fromA)),
  'a message from A is decrypted by B');

const fromB = 'and back again ' + suffix;
await bob.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(fromB)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await alice.transcript()).includes(fromB)),
  'and the reply is decrypted by A');

const errors = [...alice.errors, ...bob.errors];
ok(errors.length === 0, `no uncaught exceptions${errors.length ? ': ' + errors[0] : ''}`);

bidi.close();
cleanup();
console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
