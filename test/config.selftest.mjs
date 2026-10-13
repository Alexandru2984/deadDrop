import { sanitizeIceConfig, passwordProblem, passphrase, randomBelow } from '../web/js/util.js';
import { WORDS } from '../web/js/wordlist.js';

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

console.log('passphrase generator');
ok(WORDS.length === 1295 && new Set(WORDS).size === WORDS.length && WORDS.every((w) => /^[a-z]{3,5}$/.test(w)),
   'the word list is 1295 distinct plain words');
const phrases = Array.from({ length: 200 }, () => passphrase(WORDS));
ok(phrases.every((p) => p.split('-').length === 6 && p.split('-').every((w) => WORDS.includes(w))),
   'a passphrase is six words from the list');
ok(phrases.every((p) => passwordProblem(p, 'alice') === null), 'every generated passphrase passes the password policy');
ok(new Set(phrases).size === phrases.length, 'two hundred draws never repeat');
// Uniformity: with n = 3, a modulo-biased draw from 65536 values would be
// visible as a skew; rejection sampling keeps each bucket near a third.
const counts = [0, 0, 0];
for (let i = 0; i < 30000; i++) counts[randomBelow(3)]++;
ok(counts.every((c) => Math.abs(c - 10000) < 600), `draws are uniform across the range (${counts.join('/')})`);
let refused = 0;
for (const bad of [0, -1, 1.5, 0x10001]) { try { randomBelow(bad); } catch { refused++; } }
ok(refused === 4, 'an impossible range is refused rather than looping or skewing');

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
