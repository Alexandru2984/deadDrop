/**
 * Unit test for the DTLS-fingerprint media-path check (web/js/peer.js).
 *
 *   node test/fingerprint.selftest.mjs
 *
 * The full MitM detection needs two live browsers; this covers the pure parsing
 * and the match/mismatch decision that gates it.
 */

import { extractFingerprints, fingerprintsMatch } from '../web/js/peer.js';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

console.log('DTLS fingerprint parsing + comparison');

const sdpA =
  'v=0\r\n' +
  'a=group:BUNDLE 0\r\n' +
  'm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n' +
  'a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:' +
  '10:20:30:40:50:60:70:80:90:A0:B0:C0:D0:E0:F0:01\r\n' +
  'a=setup:actpass\r\n';

const fpsA = extractFingerprints(sdpA);
ok(fpsA.length === 1, 'parses one fingerprint from an SDP');
ok(fpsA[0].startsWith('sha-256 aa:bb:cc'), 'normalizes to lowercase "alg hex"');

// Case-insensitivity and multiple m-lines with the same cert de-duplicate.
const sdpMulti = sdpA + 'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n' +
  'a=fingerprint:SHA-256 aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:' +
  '10:20:30:40:50:60:70:80:90:a0:b0:c0:d0:e0:f0:01\r\n';
ok(extractFingerprints(sdpMulti).length === 1, 'duplicate fingerprint across m-lines collapses to one');

// No fingerprint at all → empty (caller then refuses to trust the media path).
ok(extractFingerprints('v=0\r\nm=application 9 ...\r\n').length === 0, 'no fingerprint → empty list');

ok(extractFingerprints('a=fingerprint:sha-256 AA:BB:ZZ\r\n').length === 0,
   'malformed or truncated fingerprints are rejected');

// The decision requires exact set equality, not merely one overlapping value.
const peerReal = extractFingerprints(sdpA);                 // what the peer really holds
const sdpMitm = sdpA.replace(/aa:bb/gi, '99:88');           // a MitM's different cert
const relayed = extractFingerprints(sdpMitm);               // what signaling delivered to us
ok(!fingerprintsMatch(peerReal, relayed),
   'a swapped (MitM) fingerprint shares nothing with the real one → detected');

const honestRelayed = extractFingerprints(sdpA);
ok(fingerprintsMatch(peerReal, honestRelayed),
   'an untampered fingerprint matches → media path trusted');

const smuggled = [...peerReal, relayed[0]];
ok(!fingerprintsMatch(peerReal, smuggled),
   'one genuine fingerprint plus an attacker fingerprint is rejected');

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
