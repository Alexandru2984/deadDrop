import { sanitizeIceConfig } from '../web/js/util.js';

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

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
