import { sanitizeIceConfig, passwordProblem } from '../web/js/util.js';

const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
};
const { getPref, setPref } = await import('../web/js/prefs.js');

let failures = 0;
const ok = (condition, message) => {
  if (condition) console.log('  ✓', message);
  else { console.error('  ✗', message); failures++; }
};

const now = 2_000_000_000;
const valid = {
  ttl: 3600,
  iceServers: [
    { urls: ['stun:192.0.2.1:3478'] },
    {
      urls: ['turn:192.0.2.1:3478?transport=udp', 'turns:turn.example.com:5349?transport=tcp'],
      username: `${now + 3600}:0123456789abcdef`,
      credential: 'AAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    },
  ],
};

console.log('ICE configuration validation');
const clean = sanitizeIceConfig(valid, now);
ok(clean.iceServers.length === 2 && clean.ttl === 3600, 'valid self-hosted STUN/TURN configuration accepted');
ok(Object.keys(clean.iceServers[1]).sort().join(',') === 'credential,urls,username', 'unknown entry fields are not propagated');

const invalid = [
  { ...valid, ttl: 86400 },
  { ...valid, iceServers: [{ urls: ['https://example.com'] }] },
  { ...valid, iceServers: [{ urls: ['stun:example.com?transport=udp'] }] },
  { ...valid, iceServers: [{ urls: ['stun:a..example.com'] }] },
  { ...valid, iceServers: [{ urls: ['stun:999.999.999.999'] }] },
  { ...valid, iceServers: [{ urls: ['turn:example.com'], username: `${now + 3600}:short`, credential: 'x' }] },
  { ...valid, iceServers: [{ ...valid.iceServers[1], username: `${now + 9999}:0123456789abcdef` }] },
];
for (const [index, value] of invalid.entries()) {
  let rejected = false;
  try { sanitizeIceConfig(value, now); } catch { rejected = true; }
  ok(rejected, `invalid ICE configuration ${index + 1} rejected`);
}

console.log('new-password policy');
ok(passwordProblem('Tr0ub4dor&3', 'alice') === 'err.shortPassword', 'eleven characters are refused');
ok(passwordProblem('correct horse battery', 'alice') === null, 'a few random words pass');
ok(passwordProblem('alice-is-my-secret', 'alice') === 'err.passwordHasName', 'a password containing the handle is refused');
ok(passwordProblem('ALICE-is-my-secret', 'alice') === 'err.passwordHasName', 'the handle check ignores case');
ok(passwordProblem('aaaaaaaaaaaaaaaa', 'bob') === 'err.passwordSimple', 'a repeated character is refused');
ok(passwordProblem('Password123!', 'bob') === 'err.passwordSimple', 'a decorated "password" is refused');
ok(passwordProblem('password is not my password at all', 'bob') === null, 'long passphrases may contain common words');
ok(passwordProblem('🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥', 'bob') === 'err.passwordSimple', 'length counts characters, and variety still applies');
ok(passwordProblem(undefined) === 'err.shortPassword', 'a missing password is refused, not thrown on');

console.log('remembered settings');
ok(getPref('relayOnly') === true && getPref('scrubMetadata') === true && getPref('idleLockMinutes') === 0,
   'with nothing stored, the protective defaults apply');
setPref('relayOnly', false);
ok(getPref('relayOnly') === false, 'a deliberate choice is remembered');
setPref('idleLockMinutes', 7);
ok(getPref('idleLockMinutes') === 0, 'an idle period outside the offered ones is refused');
store.set('dd_prefs', JSON.stringify({ scrubMetadata: 'no', relayOnly: 0, idleLockMinutes: 15 }));
ok(getPref('scrubMetadata') === true && getPref('relayOnly') === true,
   'a malformed stored value reads as the protective default, never as off');
ok(getPref('idleLockMinutes') === 15, 'a valid stored value survives beside malformed ones');
store.set('dd_prefs', '{not json');
ok(getPref('scrubMetadata') === true, 'a corrupt store reads as defaults');
let threw = false;
try { getPref('nonsense'); } catch { threw = true; }
ok(threw, 'an unknown preference name is a programming error, not a silent default');

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
