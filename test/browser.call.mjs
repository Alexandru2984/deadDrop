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

// The screen is kept on through a call: a phone that locks suspends the tab.
// A stand-in records what the page asks for, as a headless browser has no
// screen to keep on.
const WAKE_STUB = `(() => {
  window.__wake = { held: 0, asked: 0 };
  Object.defineProperty(navigator, 'wakeLock', { configurable: true, value: {
    request: async () => {
      window.__wake.asked++; window.__wake.held++;
      const lock = new EventTarget();
      let released = false;
      lock.release = async () => {
        if (released) return;
        released = true; window.__wake.held--;
        lock.dispatchEvent(new Event('release'));
      };
      return lock;
    },
  } });
  return true;
})()`;
await alice.eval(WAKE_STUB);
await bob.eval(WAKE_STUB);
// A call rings and vibrates; recorded here, as headless has no speaker.
await bob.eval(`(() => {
  window.__ring = { buzz: [], tones: 0, open: 0 };
  navigator.vibrate = (p) => { window.__ring.buzz.push(JSON.stringify(p)); return true; };
  const Real = window.AudioContext;
  window.AudioContext = class extends Real {
    constructor(...a) { super(...a); window.__ring.tones++; window.__ring.open++; }
    close() { window.__ring.open--; return super.close(); }
  };
  return true;
})()`);
ok(await alice.eval(`window.__wake.asked === 0`), 'the screen is left alone before a call');

// ── Ring, accept, connect ──
// B has left the tab: the privacy screen is up when the call comes in.
await bob.eval(`window.dispatchEvent(new Event('blur')); true`);
await alice.startCall();
ok(await waitFor(() => bob.ringing(), { timeout: 20000 }), 'peer B rings');
const ringing = await bob.eval(`({ ...window.__ring })`);
ok(ringing.tones === 1 && ringing.open === 1 && ringing.buzz.includes('[400,200,400]'),
  `the ring is heard and felt, not only shown (${JSON.stringify(ringing)})`);
// The ring used to sit under the privacy screen, out of sight.
const behindScreen = await bob.eval(`(() => {
  const screen = document.querySelector('#privacy-screen');
  const note = document.querySelector('#privacy-ringing');
  return {
    screen: !screen.classList.contains('hidden'),
    note: !note.classList.contains('hidden') && screen.contains(note) ? note.textContent : '',
    title: document.title,
  };
})()`);
ok(behindScreen.screen && /calling/i.test(behindScreen.note),
  `the privacy screen says someone is calling (${behindScreen.note || 'nothing'})`);
ok(!behindScreen.note.includes(await bob.eval(`document.querySelector('.verify-row .peer-tag').textContent`)),
  'without saying who');
ok(behindScreen.title.startsWith('● '), `and the tab title is marked (${behindScreen.title})`);
await bob.eval(`document.querySelector('#privacy-screen').click(); true`);
ok(!(await bob.eval(`document.title`)).startsWith('●'), 'the mark goes once the screen is lifted');
const ringText = await bob.eval(`document.querySelector('#incoming-call-text').textContent`);
const callerLabel = await bob.eval(`document.querySelector('.verify-row .peer-tag').textContent`);
ok(ringText.includes(callerLabel), `the ring names who is calling (${ringText})`);
ok(await bob.mediaState().then((s) => s.remote === null),
  'nothing is playing at B while the call is still only ringing');

await bob.acceptCall();
const answered = await bob.eval(`({ ...window.__ring, last: window.__ring.buzz.at(-1) })`);
ok(answered.open === 0 && answered.last === '0',
  `answering stops the tone and the vibration (${JSON.stringify(answered)})`);

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
// The call screen is modal: nothing behind it can take focus or a click
// while it is up, and everything comes back when it closes.
const modal = await alice.eval(`(() => {
  const overlay = document.querySelector('#call-overlay');
  const behind = ['#msg-input', '#panic-btn', '#send-btn'].map((s) => document.querySelector(s));
  const field = document.querySelector('#msg-input');
  field.focus();
  return {
    behindInert: behind.every((el) => el.closest('[inert]')),
    overlayLive: !overlay.closest('[inert]'),
    focusRefused: document.activeElement !== field,
  };
})()`);
ok(modal.behindInert && modal.overlayLive && modal.focusRefused,
  `the page behind a call cannot be reached (${JSON.stringify(modal)})`);

const clock = await waitFor(async () => {
  const text = await alice.eval(`document.querySelector('#call-status-bar').textContent`);
  return /🔒 .+ · \d\d:\d\d/.test(text) ? text : false;
}, { timeout: 5000 });
ok(clock, `a live call shows who it is with and for how long (${clock || 'nothing'})`);

ok(bobMedia && bobMedia.remote.audio === 1 && bobMedia.remote.video === 1,
  `B gets one audio and one video track (${bobMedia?.remote.audio}a/${bobMedia?.remote.video}v)`);
ok(bobMedia && bobMedia.local && bobMedia.local.live > 0,
  'B is also sending: the call is two-way, not a one-way push');
ok(await waitFor(() => bob.ringing().then((r) => !r)),
  'the incoming-call prompt closes once the call is up');
ok(await bob.eval(`document.querySelector('#privacy-ringing').classList.contains('hidden')`),
  'and so does the note on the privacy screen');

// ontrack fires when the track is negotiated; bytes prove SRTP actually flowed.
const flowed = await waitFor(async () => {
  const [a, b] = [await alice.inboundMedia(), await bob.inboundMedia()];
  return a > 0 && b > 0 ? [a, b] : false;
}, { timeout: 45000 });
ok(flowed, `encrypted media flows both ways (${flowed?.[0]} / ${flowed?.[1]} bytes)`);

const wakeInCall = [await alice.eval(`window.__wake.held`), await bob.eval(`window.__wake.held`)];
ok(wakeInCall[0] === 1 && wakeInCall[1] === 1,
  `both sides keep the screen on during the call (${wakeInCall.join('/')})`);

// The idle lock is for someone who walked away; nobody touches the screen
// through a call, and it used to wipe the tab half an hour into one.
await bob.eval(`(() => {
  const idle = document.querySelector('#idle-select');
  idle.value = '5'; idle.dispatchEvent(new Event('change'));
  window.__idleMark = 1;
  const real = Date.now;
  Date.now = () => real() + 6 * 60_000;
  try { window.dispatchEvent(new Event('focus')); } finally { Date.now = real; }
  return true;
})()`);
await sleep(500);
ok(await bob.eval(`window.__idleMark === 1 && !document.querySelector('#call-overlay').classList.contains('hidden')`),
  'the idle lock does not wipe the tab in the middle of a call');

// Back on the call screen returns to the conversation; the call goes on.
await alice.eval(`history.back(); true`);
ok(await waitFor(() => alice.mediaState().then((m) => !m.overlay)), 'back from the call screen shows the conversation');
ok(await alice.inChat(), 'without leaving the room');
const stillOn = await alice.mediaState();
ok(stillOn.local && stillOn.remote, 'and the call is still on');
await alice.eval(`document.querySelector('#call-btn').click(); true`);
ok(await waitFor(() => alice.mediaState().then((m) => m.overlay)), 'the call button brings the call screen back');

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
const wakeAfter = [await alice.eval(`window.__wake.held`), await bob.eval(`window.__wake.held`)];
ok(wakeAfter[0] === 0 && wakeAfter[1] === 0,
  `and both let the screen sleep again (${wakeAfter.join('/')})`);
await bob.eval(`(() => {
  const idle = document.querySelector('#idle-select');
  idle.value = '0'; idle.dispatchEvent(new Event('change'));
  return true;
})()`);

ok(await waitFor(async () => {
  const s = await alice.mediaState();
  return s.local === null && s.remote === null;
}), 'the caller releases its own camera and microphone');
ok(await alice.eval(`!document.querySelector('[inert]')`) && await bob.eval(`!document.querySelector('[inert]')`),
  'once the call is over nothing is left inert on either side');

// The session itself must survive the call ending.
const after = 'still here ' + suffix;
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(after)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await bob.transcript()).includes(after)),
  'the encrypted session keeps working after the call');

// ── A declined call must leave no negotiated media behind ──
// Ringing switched off: the call shows, and makes no sound or vibration.
await bob.eval(`(() => {
  const ring = document.querySelector('#ring-toggle');
  ring.checked = false; ring.dispatchEvent(new Event('change'));
  window.__ring = { buzz: [], tones: 0, open: 0 };
  return true;
})()`);
await alice.startCall();
ok(await waitFor(() => bob.ringing(), { timeout: 20000 }), 'peer B rings for a second call');
const silent = await bob.eval(`({ ...window.__ring })`);
ok(silent.tones === 0 && !silent.buzz.some((p) => p !== '0'),
  `with ringing off, the call only shows on screen (${JSON.stringify(silent)})`);
await bob.rejectCall();
ok(await waitFor(() => alice.mediaState().then((s) => !s.overlay), { timeout: 20000 }),
  'the caller is told the call was declined');
await sleep(1500);
const afterReject = await bob.mediaState();
ok(afterReject.remote === null && afterReject.local === null,
  'declining leaves no media attached at the callee');
ok(await waitFor(() => alice.mediaState().then((s) => s.local === null)),
  'declining releases the caller devices too');

// ── The caller hangs up while the callee's permission prompt is still open ──
// The camera and microphone granted after that belong to no call. They used
// to be adopted anyway, live, with the call already gone on both sides.
await alice.startCall();
ok(await waitFor(() => bob.ringing(), { timeout: 20000 }), 'peer B rings for a third call');
await bob.eval(`(() => {
  const real = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  window.__lateCall = null;
  navigator.mediaDevices.getUserMedia = (c) => new Promise((resolve) => setTimeout(async () => {
    window.__lateCall = await real(c);
    resolve(window.__lateCall);
  }, 2000));
  window.__restoreGum = () => { navigator.mediaDevices.getUserMedia = real; };
  return true;
})()`);
await bob.acceptCall();
await sleep(300);
await alice.endCall();
const lateCall = await waitFor(() => bob.eval(`window.__lateCall && {
  live: window.__lateCall.getTracks().some((tr) => tr.readyState === 'live'),
  overlay: !document.querySelector('#call-overlay').classList.contains('hidden'),
}`), { timeout: 15000 });
await bob.eval(`window.__restoreGum(); true`);
await sleep(500);
const lateState = await bob.mediaState();
ok(lateCall && !lateCall.live && lateState.local === null && !lateState.overlay,
  `media granted after the call ended is stopped, not adopted (${JSON.stringify({ ...lateCall, local: lateState.local })})`);

// ── Nobody answers ──
// A call used to ring for as long as both tabs stayed open.
await sleep(1000);
await alice.startCall();
ok(await waitFor(() => bob.ringing(), { timeout: 20000 }), 'peer B rings for a call nobody answers');
const gaveUp = await waitFor(async () => {
  const [a, b] = [(await alice.notices()).join('\n'), (await bob.notices()).join('\n')];
  return /No answer/.test(a) && /Missed call from/.test(b) ? true : false;
}, { timeout: 70000 });
ok(gaveUp, 'an unanswered call stops: the caller hears no answer, the other side a missed call');
ok(!(await bob.ringing()) && !(await alice.mediaState()).overlay,
  'and neither side is left ringing or on the call screen');

const errors = [...alice.errors, ...bob.errors];
ok(errors.length === 0, `no uncaught exceptions${errors.length ? ': ' + errors[0] : ''}`);

cdp.close();
cleanup();
console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
