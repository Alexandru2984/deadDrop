/**
 * Call test: two browsers, one real audio/video call.
 *
 *   DD_URL=… DD_INVITE=… DD_INVITE2=… node test/browser.call.mjs
 *
 * Calls are the one flow nothing covered, and the one with the most ways to be
 * quietly wrong. Messages ride the data channel, which the handshake already
 * authenticates. Media does not: audio and video are protected by DTLS-SRTP,
 * whose certificate is authenticated only by the fingerprint in the SDP — and
 * the SDP is relayed by the signaling server, which the threat model treats as
 * hostile. So the client attests its real DTLS fingerprint over the already
 * encrypted channel and refuses to place a call until that matches.
 *
 * A call that "works" proves nothing about that. This test therefore checks the
 * binding itself: that the attested fingerprint is the one really in the SDP,
 * that the call button stays hidden until it is bound, and only then that media
 * actually flows in both directions.
 */

import { Peer, launchBrowser, waitFor, sleep } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITES = [process.env.DD_INVITE || '', process.env.DD_INVITE2 || ''];
const PASS = 'call-test-passphrase-5530';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

if (!INVITES[0] || !INVITES[1]) {
  console.error('call test: set DD_INVITE and DD_INVITE2 (one account each)');
  process.exit(1);
}

const suffix = Math.floor(Math.random() * 1e6);
const USERS = [`zz_ca_${suffix}`, `zz_cb_${suffix}`];
console.log(`Call run against ${BASE} as ${USERS[0]} + ${USERS[1]}`);

const { cdp, cleanup } = await launchBrowser('call');

const alice = await Peer.open(cdp, 'alice');
const bob = await Peer.open(cdp, 'bob');
await alice.instrumentPeerConnections();
await bob.instrumentPeerConnections();

await alice.goto(BASE + '/');
await bob.goto(BASE + '/');
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
ok(await waitFor(() => bob.inChat()), 'peer B joins');
ok(await waitFor(() => alice.sas(), { timeout: 30000 }), 'the session is encrypted');

// ── The call button is gated on human verification, not just on a connection ──
ok(await alice.callable() === false,
  'no call is offered before the safety code is confirmed');

await alice.clickVerify();
await bob.clickVerify();
ok(await waitFor(() => alice.verified()) && await waitFor(() => bob.verified()),
  'both peers confirm the safety code');

ok(await waitFor(() => alice.callable(), { timeout: 20000 })
   && await waitFor(() => bob.callable(), { timeout: 20000 }),
  'the call button appears once the media path is bound to the verified session');

// ── The binding is real: what was attested is what the SDP actually carries ──
// If the client trusted a self-declared flag instead of comparing certificates,
// everything above would still pass and a DTLS man-in-the-middle would go
// unnoticed. So read the fingerprints straight out of both descriptions.
// Not [0]: the browser-support gate opens a throwaway RTCPeerConnection at boot
// to check WebRTC works at all, and the instrumentation records that one too.
// Take the connection that actually negotiated something.
const fingerprintsOf = (peer, which) => peer.eval(`
  (() => {
    const pc = (window.__ddPeerConnections || []).find((c) => c.${which});
    const sdp = pc && pc.${which} ? pc.${which}.sdp : '';
    return [...sdp.matchAll(/^a=fingerprint:(\\S+) (\\S+)\\s*$/gim)]
      .map((m) => (m[1] + ' ' + m[2]).toLowerCase()).sort();
  })()
`);

const aLocal = await fingerprintsOf(alice, 'localDescription');
const aRemote = await fingerprintsOf(alice, 'remoteDescription');
const bLocal = await fingerprintsOf(bob, 'localDescription');
const bRemote = await fingerprintsOf(bob, 'remoteDescription');

ok(aLocal.length > 0 && bLocal.length > 0, 'both ends present a DTLS certificate');
ok(JSON.stringify(aLocal) === JSON.stringify(bRemote),
  "A's real certificate is exactly what B was told to expect");
ok(JSON.stringify(bLocal) === JSON.stringify(aRemote),
  "B's real certificate is exactly what A was told to expect");
ok(JSON.stringify(aLocal) !== JSON.stringify(bLocal),
  'the two ends hold different certificates (nothing is being reused)');

// ── Ring, accept, connect ──
await alice.startCall();
ok(await waitFor(() => bob.ringing(), { timeout: 20000 }), 'peer B rings');
ok(await bob.mediaState().then((s) => s.remote === null),
  'nothing is playing at B while the call is still only ringing');

await bob.acceptCall();

const bobMedia = await waitFor(async () => {
  const s = await bob.mediaState();
  return s.remote && s.remote.live > 0 ? s : false;
}, { timeout: 45000 });
ok(bobMedia, 'peer B receives live remote tracks');

const aliceMedia = await waitFor(async () => {
  const s = await alice.mediaState();
  return s.remote && s.remote.live > 0 ? s : false;
}, { timeout: 45000 });
ok(aliceMedia, 'peer A receives live remote tracks');

ok(bobMedia && bobMedia.remote.audio === 1 && bobMedia.remote.video === 1,
  `B gets one audio and one video track (${bobMedia?.remote.audio}a/${bobMedia?.remote.video}v)`);
ok(bobMedia && bobMedia.local && bobMedia.local.live > 0,
  'B is also sending: the call is two-way, not a one-way push');
ok(await waitFor(() => bob.ringing().then((r) => !r)),
  'the incoming-call prompt closes once the call is up');

// ontrack fires when the track is negotiated; bytes prove SRTP actually flowed.
const flowed = await waitFor(async () => {
  const [a, b] = [await alice.inboundMedia(), await bob.inboundMedia()];
  return a > 0 && b > 0 ? [a, b] : false;
}, { timeout: 45000 });
ok(flowed, `encrypted media flows both ways (${flowed?.[0]} / ${flowed?.[1]} bytes)`);

// ── Mute is signaled over the encrypted channel, not inferred from silence ──
await alice.eval(`document.querySelector('#toggle-cam').click(); true`);
ok(await waitFor(() => bob.eval(
  `!document.querySelector('#remote-placeholder').classList.contains('hidden')`)),
  "A turning off the camera is reflected on B's screen");

// ── Hang up ──
await alice.endCall();
const ended = await waitFor(async () => {
  const s = await bob.mediaState();
  return s.remote === null && s.local === null ? s : false;
}, { timeout: 30000 });
ok(ended, 'hanging up clears both media elements on the far side');
ok(ended && ended.overlay === false, 'the call overlay closes on the far side');

ok(await waitFor(async () => {
  const s = await alice.mediaState();
  return s.local === null && s.remote === null;
}), 'the caller releases its own camera and microphone');

// The session itself must survive the call ending.
const after = 'still here ' + suffix;
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(after)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await bob.transcript()).includes(after)),
  'the encrypted session keeps working after the call');

// ── A declined call must leave no negotiated media behind ──
await alice.startCall();
ok(await waitFor(() => bob.ringing(), { timeout: 20000 }), 'peer B rings for a second call');
await bob.rejectCall();
ok(await waitFor(() => alice.mediaState().then((s) => !s.overlay), { timeout: 20000 }),
  'the caller is told the call was declined');
await sleep(1500);
const afterReject = await bob.mediaState();
ok(afterReject.remote === null && afterReject.local === null,
  'declining leaves no media attached at the callee');
ok(await waitFor(() => alice.mediaState().then((s) => s.local === null)),
  'declining releases the caller devices too');

const errors = [...alice.errors, ...bob.errors];
ok(errors.length === 0, `no uncaught exceptions${errors.length ? ': ' + errors[0] : ''}`);

cdp.close();
cleanup();
console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
