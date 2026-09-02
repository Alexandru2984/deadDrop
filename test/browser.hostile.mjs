/**
 * Hostile-peer test: what a verified peer can do once it stops following the
 * protocol.
 *
 *   DD_URL=… DD_INVITE=… DD_INVITE2=… node test/browser.hostile.mjs
 *
 * Every other suite has two honest clients, so every message arrives in the
 * order the state machine expects. That is not the threat. Comparing a safety
 * code proves who is on the other end; it proves nothing about what their
 * software will do afterwards, and a peer can be honest on Monday and
 * compromised on Tuesday. The interesting question is what the receiving client
 * accepts when a *verified* peer sends the right frame at the wrong moment.
 *
 * So peer A here runs a patched bundle: same handshake, same encryption, same
 * verified session — but able to emit any frame at any time. Peer B is stock.
 * Every assertion below is about B.
 */

import { Peer, launchBrowser, waitFor, sleep } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITES = [process.env.DD_INVITE || '', process.env.DD_INVITE2 || ''];
const PASS = 'hostile-test-passphrase-7714';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

if (!INVITES[0] || !INVITES[1]) {
  console.error('hostile test: set DD_INVITE and DD_INVITE2 (one account each)');
  process.exit(1);
}

const suffix = Math.floor(Math.random() * 1e6);
const USERS = [`zz_ha_${suffix}`, `zz_hb_${suffix}`];
console.log(`Hostile-peer run against ${BASE} as ${USERS[0]} (patched) + ${USERS[1]} (stock)`);

// Serving the bundle from the interceptor makes Chrome treat the page as coming
// from an unknown address space, and its local-network guard then blocks the
// signaling socket to 127.0.0.1. That guard protects users from pages on the
// public internet reaching into their LAN — irrelevant here, and only relaxed
// for this suite.
const { cdp, cleanup } = await launchBrowser('hostile', {
  extraArgs: ['--disable-features=LocalNetworkAccessChecks'],
});

const mallory = await Peer.open(cdp, 'mallory');
const bob = await Peer.open(cdp, 'bob');
await mallory.becomeHostile();
await bob.instrumentPeerConnections();

await mallory.goto(BASE + '/');
await bob.goto(BASE + '/');
ok(await mallory.eval('!!window.__ddApp'), 'the patched client is running');
ok(await mallory.register(USERS[0], INVITES[0], PASS), 'the hostile peer registers');
ok(await bob.register(USERS[1], INVITES[1], PASS), 'peer B registers');

await mallory.eval(`document.querySelector('#create-room').click(); true`);
const room = await waitFor(async () => {
  const code = await mallory.eval(`document.querySelector('#room-code').textContent`);
  return code && code.length === 24 ? code : false;
});
await bob.eval(`
  document.querySelector('#room-code-input').value = ${JSON.stringify(room)};
  document.querySelector('#join-room').click(); true
`);
ok(await waitFor(() => bob.inChat()), 'peer B joins');
ok(await waitFor(() => bob.sas(), { timeout: 30000 }), 'the session is encrypted');

await mallory.clickVerify();
await bob.clickVerify();
ok(await waitFor(() => bob.verified()), 'peer B confirms the safety code — this peer is trusted now');
ok(await waitFor(() => bob.callable(), { timeout: 20000 }), 'B would accept a call from it');

/** Build a real media offer and push it, whatever the call state happens to be. */
const pushOffer = () => mallory.eval(`
  (async () => {
    const app = window.__ddApp;
    const conn = [...app.peers.values()][0].conn;
    if (!app.localStream) {
      app.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
    }
    if (!conn.pc.getSenders().some((s) => s.track)) {
      for (const track of app.localStream.getTracks()) conn.pc.addTrack(track, app.localStream);
    }
    await conn.pc.setLocalDescription(await conn.pc.createOffer());
    await app._sendBestEffort(conn, {
      type: 'call-offer',
      sdp: JSON.stringify(conn.pc.localDescription),
    });
    return true;
  })()
`);

const quiet = async (label) => {
  await sleep(2500);
  const s = await bob.mediaState();
  ok(s.remote === null, `${label}: nothing is playing at B`);
  ok(s.local === null, `${label}: B's own camera and microphone stay off`);
  return s;
};

// ── 1. An offer before any call at all ──
// _callPeerId is still null here, so the peer-match guard alone should stop it.
ok(await pushOffer(), 'the hostile peer sends a media offer out of the blue');
await quiet('unsolicited offer');

// ── 2. An offer while the phone is still ringing ──
// The user has been shown a prompt and has touched nothing. Consent has not
// been given, so no media may be negotiated.
await mallory.eval(`
  (async () => {
    const app = window.__ddApp;
    const conn = [...app.peers.values()][0].conn;
    app._callPeerId = [...app.peers.keys()][0];
    await app._sendBestEffort(conn, { type: 'call-req', video: true });
    return true;
  })()
`);
ok(await waitFor(() => bob.ringing(), { timeout: 20000 }), 'peer B rings');
ok(await pushOffer(), 'the hostile peer sends the offer without waiting for an answer');
const ringing = await quiet('offer during the ring');
ok(ringing.status !== 'active' && await bob.ringing(),
  'B is still only ringing, not in a call');

// ── 3. An offer straight after the user declined ──
// This is the sharpest one: the user has actively said no.
await bob.rejectCall();
await sleep(500);
ok(await pushOffer(), 'the hostile peer sends the offer again after being declined');
await quiet('offer after a decline');
ok(await bob.eval(`document.querySelector('#call-btn').textContent === '📞'`),
  'B is not shown as being in a call');

// ── 4. A stray answer with no offer outstanding ──
await mallory.eval(`
  (async () => {
    const app = window.__ddApp;
    const conn = [...app.peers.values()][0].conn;
    const pc = conn.pc;
    await app._sendBestEffort(conn, {
      type: 'call-answer',
      sdp: JSON.stringify(pc.localDescription),
    });
    return true;
  })()
`);
await quiet('unsolicited answer');

// ── The session must still be healthy: rejecting abuse is not tearing down ──
ok(await bob.verified(), 'B still holds the verified session');
const probe = 'still fine ' + suffix;
await bob.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(probe)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await mallory.transcript()).includes(probe)),
  'ordinary messages still flow after every rejected frame');

// ── 5. Fabricated read receipts ──
// A read receipt destroys the sender's copy — that is what makes a message burn
// on both sides. The stock client only ever sends one for a message that was
// sent to burn. Trusting the claim for anything else hands a peer the ability to
// erase the other side of the conversation while keeping its own copy.
const kept = [1, 2, 3].map((n) => `ordinary message ${n} of ${suffix}`);
for (const text of kept) {
  await bob.eval(`
    document.querySelector('#msg-input').value = ${JSON.stringify(text)};
    document.querySelector('#send-btn').click(); true
  `);
  await sleep(400);
}
ok(await waitFor(async () => (await mallory.transcript()).includes(kept[2])),
  'B sends three ordinary messages, none of them set to burn');

await mallory.eval(`
  (async () => {
    const app = window.__ddApp;
    const conn = [...app.peers.values()][0].conn;
    for (const key of [...app.msgMgr.messages.keys()]) {
      await app._sendBestEffort(conn, { type: 'read', id: key.split(':').slice(1).join(':') });
    }
    return true;
  })()
`);
await sleep(3000);
const survivors = await bob.transcript();
ok(kept.every((text) => survivors.includes(text)),
  'replayed read receipts destroy none of them');

// And the real thing still has to work, or the check above is satisfied by a
// client that simply stopped honouring receipts.
const burning = 'burn this ' + suffix;
await bob.sendBurning(burning);
ok(await waitFor(async () => (await mallory.transcript()).includes(burning)),
  'a message actually sent to burn still reaches the peer');
ok(await waitFor(async () => !(await bob.transcript()).includes(burning), { timeout: 15000 }),
  'and its receipt still burns the sender copy');
ok((await bob.notices()).some((n) => n.toLowerCase().includes('removed')),
  'and the sender is told a message was removed rather than watching it vanish');

// ── And B is still able to start a call of its own ──
// Only as far as the far side ringing: the hostile peer wrecked its own
// connection with three unanswered offers, so nothing past that point would be
// testing B. browser.call.mjs carries a call all the way through on clean peers.
await mallory.eval(`window.__ddApp._endCallCleanup(); true`);
await sleep(500);
await bob.eval(`document.querySelector('#call-btn').click(); true`);
ok(await waitFor(() => mallory.ringing(), { timeout: 20000 }),
  'B can still place a call of its own');
await bob.endCall();
ok(await waitFor(async () => {
  const s = await bob.mediaState();
  return s.local === null && s.status === '';
}), 'and cancel it cleanly, with no status left behind');

const errors = bob.errors;
ok(errors.length === 0, `no uncaught exceptions at B${errors.length ? ': ' + errors[0] : ''}`);

cdp.close();
cleanup();
console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
