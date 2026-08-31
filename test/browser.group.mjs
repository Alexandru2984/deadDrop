/**
 * Group-room test: three browsers in one room, three independent pairwise
 * sessions.
 *
 *   DD_URL=… DD_INVITE=… DD_INVITE2=… DD_INVITE3=… node test/browser.group.mjs
 *
 * A room is a mesh, not a group key: every pair runs its own handshake, derives
 * its own keys and needs its own safety-code comparison. That is the strongest
 * property the design has and also the easiest to get wrong — a mesh that
 * quietly reused one session across peers, or matched a safety code against the
 * wrong pair, would look completely normal from a single browser.
 *
 * So the interesting assertion here is not "messages arrive". It is that the
 * three safety codes pair up correctly and are all different from each other.
 */

import { Peer, launchBrowser, waitFor, sleep } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITES = [
  process.env.DD_INVITE || '',
  process.env.DD_INVITE2 || '',
  process.env.DD_INVITE3 || '',
];
const PASS = 'group-test-passphrase-4471';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

if (INVITES.some((i) => !i)) {
  console.error('group test: set DD_INVITE, DD_INVITE2 and DD_INVITE3');
  process.exit(1);
}

const suffix = Math.floor(Math.random() * 1e6);
const NAMES = ['a', 'b', 'c'];
const USERS = NAMES.map((n) => `zz_g${n}_${suffix}`);
console.log(`Three-peer run against ${BASE} as ${USERS.join(', ')}`);

const { cdp, cleanup } = await launchBrowser('group');

/** Every verify row: the peer label it belongs to and the code it shows. */
function verifyRows(peer) {
  return peer.eval(`
    [...document.querySelectorAll('.verify-row')].map((row) => ({
      label: row.querySelector('.verify-label')?.textContent || null,
      sas: row.querySelector('.verify-sas')?.textContent || null,
      verified: row.querySelector('.verify-btn')?.disabled || false,
    })).filter((r) => r.sas)
  `);
}

/** Confirm every row that is still awaiting this user's click. */
function confirmAllRows(peer) {
  return peer.eval(`
    (() => {
      const btns = [...document.querySelectorAll('.verify-btn')].filter((b) => !b.disabled);
      btns.forEach((b) => b.click());
      return btns.length;
    })()
  `);
}

const peers = [];
for (let i = 0; i < 3; i++) {
  const peer = await Peer.open(cdp, NAMES[i]);
  await peer.goto(BASE + '/');
  ok(await peer.register(USERS[i], INVITES[i], PASS), `peer ${NAMES[i].toUpperCase()} registers`);
  peers.push(peer);
}
const [a, b, c] = peers;

await a.eval(`document.querySelector('#create-room').click(); true`);
const room = await waitFor(async () => {
  const code = await a.eval(`document.querySelector('#room-code').textContent`);
  return code && code.length === 24 ? code : false;
});
ok(room, 'peer A creates the room');

for (const [peer, name] of [[b, 'B'], [c, 'C']]) {
  await peer.eval(`
    document.querySelector('#room-code-input').value = ${JSON.stringify(room)};
    document.querySelector('#join-room').click(); true
  `);
  ok(await waitFor(() => peer.inChat()), `peer ${name} joins the room`);
}

// Each peer must end up with one session per other member — not one shared one.
const rows = [];
for (let i = 0; i < 3; i++) {
  const got = await waitFor(async () => {
    const r = await verifyRows(peers[i]);
    return r.length === 2 ? r : false;
  }, { timeout: 45000 });
  ok(got, `peer ${NAMES[i].toUpperCase()} has a separate session with each of the other two`);
  rows.push(got || []);
}

// The mesh is only real if each pair agrees on a code and no two pairs share
// one. A single reused session would show up here as a duplicate.
const [rowsA, rowsB, rowsC] = rows;
const codesA = new Set(rowsA.map((r) => r.sas));
const codesB = new Set(rowsB.map((r) => r.sas));
const codesC = new Set(rowsC.map((r) => r.sas));

const shared = (x, y) => [...x].filter((code) => y.has(code));
const ab = shared(codesA, codesB);
const ac = shared(codesA, codesC);
const bc = shared(codesB, codesC);

ok(ab.length === 1, `A and B share exactly one safety code (${ab.join(', ') || 'none'})`);
ok(ac.length === 1, `A and C share exactly one safety code (${ac.join(', ') || 'none'})`);
ok(bc.length === 1, `B and C share exactly one safety code (${bc.join(', ') || 'none'})`);

const allPairCodes = new Set([...ab, ...ac, ...bc]);
ok(allPairCodes.size === 3,
  'the three pairwise sessions have three distinct safety codes');

const everyCode = [...codesA, ...codesB, ...codesC];
ok(new Set(everyCode).size === 3 && everyCode.length === 6,
  'every peer sees exactly the two codes for its own pairs');

// Nothing may flow before each pair has been confirmed by both of its members.
ok(await a.verified() === false, 'traffic stays locked before confirmation');

for (let round = 0; round < 2; round++) {
  for (const peer of peers) await confirmAllRows(peer);
  await sleep(500);
}
for (let i = 0; i < 3; i++) {
  ok(await waitFor(() => peers[i].verified(), { timeout: 30000 }),
    `peer ${NAMES[i].toUpperCase()} unlocks once all its pairs are confirmed`);
}

// A message is sealed separately for each pair, so reaching both others proves
// two independent encryptions succeeded.
const secret = 'mesh fanout ' + suffix;
await a.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(secret)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await b.transcript()).includes(secret)),
  'B decrypts a message sent to the room');
ok(await waitFor(async () => (await c.transcript()).includes(secret)),
  'C decrypts the same message over its own session');

// A reply from a non-creator must reach the other two the same way.
const reply = 'reply from C ' + suffix;
await c.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(reply)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await a.transcript()).includes(reply)),
  'A receives a reply from C');
ok(await waitFor(async () => (await b.transcript()).includes(reply)),
  'B receives it too, over the B–C session');

// Losing one member must not disturb the session between the other two.
await c.eval(`window.close && window.close(); true`).catch(() => {});
await cdp.send('Target.closeTarget', { targetId: c.targetId });

ok(await waitFor(async () => (await verifyRows(a)).length === 1, { timeout: 30000 }),
  'A drops only the session with the peer that left');

const after = 'still talking ' + suffix;
await a.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(after)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await b.transcript()).includes(after)),
  'A and B keep talking after C leaves');

const errors = peers.flatMap((p) => p.errors);
ok(errors.length === 0, `no uncaught exceptions in any peer${errors.length ? ': ' + errors[0] : ''}`);

cdp.close();
cleanup();
console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
