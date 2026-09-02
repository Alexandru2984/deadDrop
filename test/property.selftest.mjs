/**
 * Randomised property test for the browser-side parsers that read bytes we did
 * not write.
 *
 * The Go parsers are fuzzed natively; Node has no equivalent, and these two are
 * on the same footing. `sanitizeIceConfig` reads whatever /api/turn returns, and
 * the threat model treats that server as hostile. `extractFingerprints` reads an
 * SDP the signaling server relayed, and its output decides whether a call is
 * allowed to carry media.
 *
 * Example-based tests already cover the shapes we thought of. This one covers
 * the ones we did not: it generates structurally plausible garbage and asserts
 * the properties that have to hold for *every* input, not just the listed ones.
 */

import { sanitizeIceConfig } from '../web/js/util.js';
import { extractFingerprints, fingerprintsMatch } from '../web/js/peer.js';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

// Deterministic, so a failure can be reproduced from the printed seed.
let seed = Number(process.env.DD_SEED || 0x2f6f2b61);
const rand = () => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return (seed >>> 0) / 2 ** 32; };
const pick = (list) => list[Math.floor(rand() * list.length)];
const int = (lo, hi) => lo + Math.floor(rand() * (hi - lo + 1));

const JUNK = ['', ' ', '\n', '\0', '"', '\\', '../', '%', ':', '//', '@', '#', '?',
  'javascript:', 'data:', 'http://evil', '­', '�', 'ſ', 'K', 'A'.repeat(300)];

function randomString(maxLen = 24) {
  const n = int(0, maxLen);
  let out = '';
  for (let i = 0; i < n; i++) {
    out += rand() < 0.3 ? pick(JUNK) : String.fromCharCode(int(32, 126));
  }
  return out;
}

function randomValue(depth = 0) {
  const roll = rand();
  if (depth > 2 || roll < 0.3) return pick([null, true, false, 0, -1, 1e9, NaN, randomString()]);
  if (roll < 0.6) return Array.from({ length: int(0, 4) }, () => randomValue(depth + 1));
  const obj = {};
  for (let i = 0; i < int(0, 4); i++) obj[randomString(8)] = randomValue(depth + 1);
  return obj;
}

/** Config-shaped input: mostly plausible, occasionally not. */
function randomIceConfig() {
  if (rand() < 0.15) return randomValue();
  const scheme = pick(['stun', 'stuns', 'turn', 'turns', 'http', 'javascript', '', randomString(6)]);
  const host = pick(['127.0.0.1', 'turn.example.com', '[::1]', 'evil@example.com',
    'example.com:99999', randomString(12), '']);
  const url = `${scheme}:${host}${rand() < 0.5 ? '?transport=' + pick(['udp', 'tcp', randomString(4)]) : ''}`;
  return {
    iceServers: Array.from({ length: int(0, 3) }, () => ({
      urls: Array.from({ length: int(0, 9) }, () => (rand() < 0.8 ? url : randomValue())),
      username: rand() < 0.5 ? randomString() : undefined,
      credential: rand() < 0.5 ? randomString() : undefined,
      extra: rand() < 0.2 ? randomString() : undefined,
    })),
    ttl: rand() < 0.8 ? int(200, 8000) : randomValue(),
  };
}

console.log('sanitizeIceConfig: accepted output is always a safe shape');
let accepted = 0;
for (let i = 0; i < 20000; i++) {
  const input = randomIceConfig();
  let clean;
  try {
    clean = sanitizeIceConfig(input, 1_700_000_000);
  } catch {
    continue; // rejecting is always allowed
  }
  accepted++;
  // Whatever it lets through goes straight into RTCPeerConnection.
  const shapeOK = clean && Array.isArray(clean.iceServers) && clean.iceServers.length <= 2
    && Number.isInteger(clean.ttl) && clean.ttl >= 300 && clean.ttl <= 7200;
  if (!shapeOK) {
    ok(false, `accepted a malformed config: ${JSON.stringify(clean)?.slice(0, 200)}`);
    break;
  }
  let bad = null;
  for (const entry of clean.iceServers) {
    const keys = Object.keys(entry).sort().join(',');
    if (keys !== 'urls' && keys !== 'credential,urls,username') bad = `unexpected fields ${keys}`;
    if (!Array.isArray(entry.urls) || entry.urls.length < 1 || entry.urls.length > 8) bad = 'bad urls array';
    for (const url of entry.urls || []) {
      if (typeof url !== 'string' || !/^(stun|stuns|turn|turns):/.test(url)) bad = `scheme in ${url}`;
    }
  }
  if (bad) { ok(false, `accepted an entry with ${bad}`); break; }
}
ok(accepted > 200, `${accepted} of 20000 generated configs were accepted, and all were well shaped`);
ok(failures === 0, 'no malformed configuration reached RTCPeerConnection');

console.log('\nextractFingerprints: every entry is a complete, canonical fingerprint');
const ALGS = ['sha-256', 'sha-384', 'sha-512', 'sha-1', 'md5', randomString(6)];
const LEN = { 'sha-256': 32, 'sha-384': 48, 'sha-512': 64 };
let extracted = 0;
for (let i = 0; i < 20000; i++) {
  const alg = pick(ALGS);
  // Mostly the right length for the algorithm, so the accept path is exercised;
  // the rest is off-by-one and junk, which is where the rejections should be.
  const correct = LEN[alg];
  const octets = correct && rand() < 0.7
    ? (rand() < 0.85 ? correct : correct + pick([-1, 1]))
    : int(0, 70);
  const hex = Array.from({ length: octets },
    () => (rand() < 0.97 ? int(0, 255).toString(16).padStart(2, '0') : pick(['g0', 'ZZ', '0', '']))).join(':');
  const sdp = [
    'v=0',
    rand() < 0.5 ? `a=fingerprint:${alg} ${hex}` : `a=fingerprint:${alg} ${hex}\r`,
    rand() < 0.3 ? `a=fingerprint:${alg} ${hex}` : 'a=setup:actpass',
    rand() < 0.3 ? randomString(40) : 'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
  ].join('\n');

  const found = extractFingerprints(sdp);
  extracted += found.length;
  for (const entry of found) {
    const [gotAlg, gotHex] = entry.split(' ');
    if (!LEN[gotAlg]) { ok(false, `emitted an unsupported algorithm: ${entry}`); break; }
    const parts = (gotHex || '').split(':');
    if (parts.length !== LEN[gotAlg] || !parts.every((p) => /^[0-9a-f]{2}$/.test(p))) {
      ok(false, `emitted a malformed fingerprint: ${entry}`);
      break;
    }
  }
  // Duplicates would let an attacker pad a set until an overlap check passes.
  if (new Set(found).size !== found.length) { ok(false, 'emitted duplicate entries'); break; }
}
ok(extracted > 100, `${extracted} fingerprints extracted, all canonical and deduplicated`);

console.log('\nfingerprintsMatch: only exact set equality');
let matchFailures = 0;
for (let i = 0; i < 5000; i++) {
  const a = Array.from({ length: int(1, 3) }, () => `sha-256 ${randomString(8)}`);
  const extra = `sha-256 ${randomString(8)}`;
  const b = rand() < 0.5 ? [...a] : [...a, extra];
  // The function compares sets, so the expectation has to be about sets too —
  // a repeated entry adds nothing, and treating it as a difference would be
  // testing the test.
  const set = (list) => new Set(list.map((x) => x.toLowerCase()));
  const sameSet = set(a).size === set(b).size
    && [...set(a)].every((x) => set(b).has(x));
  if (fingerprintsMatch(a, b) !== sameSet) {
    ok(false, `mismatch verdict for ${JSON.stringify(a)} vs ${JSON.stringify(b)}`);
    matchFailures++;
    break;
  }
  // A genuine superset must never pass: that is how a real certificate gets
  // smuggled in beside an attacker's one.
  const smuggled = 'sha-256 ' + 'ff:'.repeat(31) + 'ff';
  if (!set(a).has(smuggled) && fingerprintsMatch(a, [...a, smuggled])) {
    ok(false, 'a superset passed the match');
    matchFailures++;
    break;
  }
}
ok(matchFailures === 0, 'a fingerprint set never matches a genuine superset of itself');

console.log(failures === 0 ? `\nALL PASS ✅ (seed 0x${(process.env.DD_SEED ? Number(process.env.DD_SEED) : 0x2f6f2b61).toString(16)})`
  : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
