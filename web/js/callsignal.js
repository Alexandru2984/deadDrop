/**
 * Dead Drop — which call-signaling frames a client may act on.
 *
 * Call setup is the one part of the protocol where the two sides take different
 * roles, and where acting on the wrong frame has a physical consequence: a
 * camera and a microphone switch on, or a stranger's audio starts playing.
 *
 * Everything here rides the encrypted data channel, so only the peer whose
 * safety code the user confirmed can send any of it. That is a weaker guarantee
 * than it looks. Verification says who is on the other end; it says nothing
 * about what their software will do next, and a peer who was honest yesterday
 * may be running a patched build today. So each frame is checked against where
 * this side's own state machine actually is, rather than trusted because of who
 * sent it.
 *
 * The rule that matters: an offer is only ever legitimate for a callee who has
 * accepted and is waiting for it, and an answer only for a caller who sent one.
 * Without that, a peer can negotiate media while the phone is merely ringing —
 * or seconds after the user pressed decline.
 *
 * Kept apart from the UI so the whole table can be enumerated in a test.
 */

/**
 * state → the call-signaling frames that make sense in it.
 *
 * Null-prototype, because the key is peer-controlled: a plain object would
 * answer a lookup for `__proto__` or `constructor` with something truthy.
 */
const RULES = {
  __proto__: null,
  // A request may arrive from any peer at any time — including while this side
  // is already busy, which the handler answers with a decline. Screening it
  // here instead would leave the caller waiting on a reply that never comes.
  'call-req':    { states: '*', role: null, fromAnyPeer: true },
  // The callee picked up; only the caller waiting on that can act on it.
  'call-accept': { states: ['requesting'], role: 'caller' },
  // Declines tear down, so they are safe to honour a little more broadly.
  'call-reject': { states: ['requesting', 'connecting'], role: 'caller' },
  // The two that negotiate media, and the reason this table exists.
  'call-offer':  { states: ['connecting'], role: 'callee' },
  'call-answer': { states: ['connecting'], role: 'caller' },
  // Hanging up is always fail-safe.
  'call-end':    { states: ['requesting', 'incoming', 'connecting', 'active'], role: null },
  // Camera and microphone indicators only mean anything during a live call.
  'call-mute':   { states: ['active'], role: null },
};

export const CALL_SIGNAL_TYPES = Object.keys(RULES);

const isType = (type) => typeof type === 'string' && Object.hasOwn(RULES, type);

/**
 * @param {string} type            – the frame's `type` field
 * @param {object} ctx
 * @param {string} ctx.state       – idle | requesting | incoming | connecting | active
 * @param {?string} ctx.role       – 'caller' | 'callee' | null
 * @param {boolean} ctx.fromCallPeer – the sender is the peer this call is with
 */
export function callSignalAllowed(type, { state, role, fromCallPeer }) {
  if (!isType(type)) return false;
  const rule = RULES[type];
  if (!rule.fromAnyPeer && !fromCallPeer) return false;
  if (rule.states !== '*' && !rule.states.includes(state)) return false;
  if (rule.role && rule.role !== role) return false;
  return true;
}
