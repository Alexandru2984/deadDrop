/**
 * A path that drops for a moment must not end a verified session.
 *
 * A phone changing networks takes an established WebRTC connection through
 * ICE "disconnected", and it usually recovers within seconds. Ending the
 * session there threw away a verified conversation that needed a new safety
 * code to replace. "failed" and "closed" are final and still end it at once.
 *
 *   node test/ice-grace.selftest.mjs
 */

import { PeerConnection } from '../web/js/peer.js';

let failures = 0;
const ok = (cond, msg) => {
  if (cond) console.log('  ✓', msg);
  else { console.error('  ✗', msg); failures++; }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

globalThis.RTCPeerConnection = class {
  constructor() { this.connectionState = 'new'; }
  getSenders() { return []; }
  close() { this.connectionState = 'closed'; }
};

function harness() {
  const states = [];
  const peer = new PeerConnection({ send() {} }, {}, () => {}, (s) => states.push(s));
  peer.iceGraceMs = 60;
  const pc = peer._newRTCPeerConnection();
  peer.pc = pc;
  const set = (s) => { pc.connectionState = s; pc.onconnectionstatechange(); };
  return { peer, pc, set, states };
}

console.log('ICE interruptions on an established path');
{
  const { set, states } = harness();
  set('connected');
  set('disconnected');
  ok(states.at(-1) === 'interrupted', 'a drop is reported as an interruption, not an end');
  await sleep(20);
  set('connected');
  await sleep(80);
  ok(!states.includes('disconnected'), 'recovering within the grace period keeps the session');
  ok(states.at(-1) === 'connected', 'and reports the path as connected again');
}
{
  const { set, states } = harness();
  set('connected');
  set('disconnected');
  await sleep(100);
  ok(states.at(-1) === 'disconnected', 'a path that never comes back ends the session after the grace period');
}
{
  const { set, states } = harness();
  set('connected');
  set('failed');
  ok(states.at(-1) === 'disconnected', '"failed" ends it at once');
}
{
  const { peer, set, states } = harness();
  set('connected');
  set('disconnected');
  peer.close(false);
  await sleep(100);
  ok(!states.includes('disconnected'), 'closing the session cancels the pending end — no second teardown');
}
{
  const { set, states } = harness();
  set('disconnected');
  ok(states.at(-1) === 'disconnected', 'a path that was never up is not given a grace period');
}

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
