/**
 * Call-signaling state machine self-test.
 *
 * The browser suites can show that a hostile peer fails to negotiate media at
 * three specific moments. They cannot show that no such moment is left, because
 * that means enumerating every frame against every state — which is exactly
 * what a table is for.
 *
 * The property worth stating plainly: media negotiation is reachable from one
 * state per side and no other. Everything else about a call — who rang, who
 * declined, who hung up — can be replayed freely without a camera coming on.
 */

import { callSignalAllowed, CALL_SIGNAL_TYPES } from '../web/js/callsignal.js';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

const STATES = ['idle', 'requesting', 'incoming', 'connecting', 'active'];
const ROLES = [null, 'caller', 'callee'];

const allowed = (type, state, role, fromCallPeer = true) =>
  callSignalAllowed(type, { state, role, fromCallPeer });

console.log('media negotiation is reachable from exactly one state per side');

// The whole point. Anything else that lets an offer through is a camera turning
// on without the user having agreed to it.
const offerStates = [];
for (const state of STATES) {
  for (const role of ROLES) {
    if (allowed('call-offer', state, role)) offerStates.push(`${state}/${role}`);
  }
}
ok(offerStates.length === 1 && offerStates[0] === 'connecting/callee',
  `an offer is accepted only while accepting a call (${offerStates.join(', ') || 'never'})`);

const answerStates = [];
for (const state of STATES) {
  for (const role of ROLES) {
    if (allowed('call-answer', state, role)) answerStates.push(`${state}/${role}`);
  }
}
ok(answerStates.length === 1 && answerStates[0] === 'connecting/caller',
  `an answer is accepted only while placing a call (${answerStates.join(', ') || 'never'})`);

console.log('\nthe moments a real attack would use');
ok(!allowed('call-offer', 'incoming', 'callee'),
  'an offer while the phone is still ringing is refused');
ok(!allowed('call-offer', 'idle', null),
  'an offer after the user declined — state back to idle — is refused');
ok(!allowed('call-offer', 'idle', 'callee'),
  'an offer after a decline is refused even if the role was left behind');
ok(!allowed('call-offer', 'active', 'callee'),
  'an offer mid-call cannot renegotiate the media');
ok(!allowed('call-answer', 'connecting', 'callee'),
  'the callee cannot be made to complete an answer it never offered');
ok(!allowed('call-accept', 'incoming', 'callee'),
  'the callee cannot be told its own call was accepted');

console.log('\npeer scoping');
for (const type of CALL_SIGNAL_TYPES) {
  if (type === 'call-req') continue;
  const reachable = STATES.some((s) => ROLES.some((r) => allowed(type, s, r, false)));
  ok(!reachable, `${type} is ignored from a peer this call is not with`);
}
ok(allowed('call-req', 'idle', null, false),
  'a request from a new peer is still heard');
ok(allowed('call-req', 'active', 'caller', false),
  'a request while busy is heard too, so the caller gets a decline rather than silence');

console.log('\nthe ordinary flow still works');
ok(allowed('call-req', 'idle', null, false), 'A rings B');
ok(allowed('call-accept', 'requesting', 'caller'), 'B picks up, A hears it');
ok(allowed('call-offer', 'connecting', 'callee'), "B takes A's offer");
ok(allowed('call-answer', 'connecting', 'caller'), "A takes B's answer");
ok(allowed('call-mute', 'active', 'caller') && allowed('call-mute', 'active', 'callee'),
  'either side can signal mute during the call');
ok(!allowed('call-mute', 'incoming', 'callee'),
  'mute outside a live call is refused — it only drives an indicator, but a peer should not drive it at will');
for (const state of ['requesting', 'incoming', 'connecting', 'active']) {
  ok(allowed('call-end', state, 'caller') && allowed('call-end', state, 'callee'),
    `hanging up is honoured in ${state}`);
}
ok(!allowed('call-end', 'idle', null), 'hanging up an idle client is a no-op');
ok(allowed('call-reject', 'requesting', 'caller'), 'a decline reaches the caller');

console.log('\nunknown frames');
for (const type of ['call-steal', '__proto__', 'constructor', '', 'call-offer ']) {
  ok(!allowed(type, 'connecting', 'callee'), `${JSON.stringify(type)} is not a call frame`);
}

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
