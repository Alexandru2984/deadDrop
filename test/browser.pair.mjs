/**
 * Two-peer end-to-end test: two isolated browser contexts, one real WebRTC
 * session between them.
 *
 *   DD_URL=… DD_INVITE=… DD_INVITE2=… node test/browser.pair.mjs
 *
 * Everything else in the suite exercises one side at a time. The Go tests never
 * run the client, the crypto self-test drives both handshake halves in one
 * process with no transport, and the single-page smoke test never has a peer to
 * talk to. So nothing covered the path that actually matters: two browsers, the
 * signaling server between them, a data channel, a safety code both humans
 * compare, and — since protocol v5 — a saved contact recognised on a later
 * session without comparing anything again.
 */

import { Peer, launchBrowser, waitFor, sleep } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITES = [process.env.DD_INVITE || '', process.env.DD_INVITE2 || ''];
const PASS = 'pair-test-passphrase-9182';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

if (!INVITES[0] || !INVITES[1]) {
  console.error('pair test: set DD_INVITE and DD_INVITE2 (one account each)');
  process.exit(1);
}

const suffix = Math.floor(Math.random() * 1e6);
const USERS = [`zz_pa_${suffix}`, `zz_pb_${suffix}`];
console.log(`Two-peer run against ${BASE} as ${USERS[0]} + ${USERS[1]}`);

const { cdp, cleanup } = await launchBrowser('pair');

// ── First session: strangers must compare a safety code ──
const alice = await Peer.open(cdp, 'alice');
const bob = await Peer.open(cdp, 'bob');

await alice.goto(BASE + '/');
await bob.goto(BASE + '/');
ok(await alice.register(USERS[0], INVITES[0], PASS), 'peer A registers');
ok(await bob.register(USERS[1], INVITES[1], PASS), 'peer B registers');

// Both opt into saved contacts before connecting, so the identity is present in
// the very first handshake and can be pinned when they verify.
await alice.enableSavedContacts();
await bob.enableSavedContacts();

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
ok(await waitFor(() => bob.inChat()), 'peer B joins the room');

const sasA = await waitFor(() => alice.sas(), { timeout: 30000 });
const sasB = await waitFor(() => bob.sas(), { timeout: 30000 });
ok(sasA && sasB, 'both peers complete the hybrid handshake and show a safety code');
ok(sasA === sasB, `both peers derive the same safety code (${sasA} / ${sasB})`);

ok(await alice.verified() === false && await bob.verified() === false,
  'traffic stays locked before anyone confirms');

ok(await alice.clickVerify(), 'peer A confirms the safety code');
ok(await bob.clickVerify(), 'peer B confirms the safety code');
ok(await waitFor(() => alice.verified()) && await waitFor(() => bob.verified()),
  'mutual confirmation unlocks both sides');

const secret = 'ciphertext round trip ' + suffix;
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(secret)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await bob.transcript()).includes(secret)),
  'a message sent by A is decrypted by B');

// ── Burn after reading ──
// The one message class that is meant to vanish from both sides. It works by the
// reader telling the sender it was read, so if that stops working the message
// quietly stops burning — and nothing would have noticed.
const burning = 'burn this ' + suffix;
await alice.sendBurning(burning);
ok(await waitFor(async () => (await bob.transcript()).includes(burning)),
  'a burn-after-reading message reaches B');
ok(await waitFor(async () => !(await bob.transcript()).includes(burning), { timeout: 15000 }),
  'and burns on the reader side');
ok(await waitFor(async () => !(await alice.transcript()).includes(burning), { timeout: 15000 }),
  "and the reader's receipt burns the sender's copy too");

// An ordinary message must survive all of that: only what was sent to burn burns.
const keeper = 'keep this ' + suffix;
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(keeper)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await bob.transcript()).includes(keeper)),
  'an ordinary message still arrives');
await sleep(4000);
ok((await alice.transcript()).includes(keeper),
  'and is still on the sender side after the burn window');

// ── Files ──
// filetransfer.js chunks, reassembles and re-checks the declared size against
// both the ciphertext and the plaintext. None of that had ever run against a
// real peer.
const fileBody = 'dead drop file payload ' + suffix + '\n' + 'x'.repeat(120 * 1024);
ok(await alice.sendFile('notes.txt', fileBody), 'peer A attaches a file');

const received = await waitFor(async () => {
  const files = await bob.receivedFiles();
  const match = files.find((f) => f.name === 'notes.txt');
  return match || false;
}, { timeout: 40000 });
ok(received, 'peer B receives the file and renders it');

// Both ends format the size from the same declared length, so a mismatch means
// the metadata and the payload disagreed somewhere in between.
const sentFile = (await alice.receivedFiles()).find((f) => f.name === 'notes.txt');
ok(received && sentFile && received.size === sentFile.size,
  `the received size matches what the sender showed (${received?.size} / ${sentFile?.size})`);
ok(received && received.href && received.href.startsWith('blob:'),
  'the download link points at a locally created blob, not the network');

// An image that decodes to its original dimensions could not have survived a
// corrupted chunk, a short read, or a mis-sliced reassembly.
const pngBytes = await alice.sendGeneratedImage(64, 48);
ok(pngBytes > 0, 'peer A sends a generated PNG');
ok(await waitFor(async () => (await bob.decodedImageSize()) === '64x48', { timeout: 40000 }),
  'the received image decodes at its original dimensions');

// The name is peer-controlled text and reaches the DOM. Under Trusted Types a
// markup-shaped name must arrive as literal characters, not as elements.
const nastyName = '<img src=x onerror=alert(1)>.txt';
ok(await alice.sendFile(nastyName, 'small'), 'peer A sends a file with a markup-shaped name');
const nasty = await waitFor(async () => {
  const files = await bob.receivedFiles();
  return files.find((f) => f.name === nastyName) || false;
}, { timeout: 30000 });
ok(nasty, 'the hostile filename arrives as text, not markup');
ok(await bob.eval(`!document.querySelector('#messages img[src="x"]')`),
  'no element was created from the filename');

// ── Second session: a saved contact must not need a new comparison ──
// Fresh pages in the same browser contexts, so cookies and the pinned identity
// survive exactly as they would for a returning user.
await alice.goto(BASE + '/');
await bob.goto(BASE + '/');
await waitFor(() => alice.eval(`!document.querySelector('#landing').classList.contains('hidden')`));
await waitFor(() => bob.eval(`!document.querySelector('#landing').classList.contains('hidden')`));

await alice.eval(`document.querySelector('#create-room').click(); true`);
const room2 = await waitFor(async () => {
  const code = await alice.eval(`document.querySelector('#room-code').textContent`);
  return code && code.length === 24 ? code : false;
});
await bob.eval(`
  document.querySelector('#room-code-input').value = ${JSON.stringify(room2)};
  document.querySelector('#join-room').click(); true
`);
ok(await waitFor(() => bob.inChat()), 'the saved contacts reconnect in a new room');

const autoA = await waitFor(() => alice.verified(), { timeout: 30000 });
const autoB = await waitFor(() => bob.verified(), { timeout: 30000 });
ok(autoA && autoB,
  'a recognised contact unlocks without anyone comparing a code again');

const secret2 = 'second session ' + suffix;
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(secret2)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await bob.transcript()).includes(secret2)),
  'the reconnected pair exchanges messages');

ok(alice.errors.length === 0 && bob.errors.length === 0,
  `no uncaught exceptions in either peer${
    [...alice.errors, ...bob.errors].length ? ': ' + [...alice.errors, ...bob.errors][0] : ''}`);

cdp.close();
cleanup();
console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
