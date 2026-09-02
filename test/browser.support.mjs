/**
 * Browser-support gate: what happens on a browser that cannot do the job.
 *
 *   DD_URL=… node test/browser.support.mjs
 *
 * Everything protecting a conversation runs in the browser, so a missing
 * primitive is not a cosmetic problem — it is the difference between an
 * encrypted session and a broken one. The app used to assume every capability
 * it uses, which on an engine without one meant a page that looked alive, took
 * a password, and protected nothing.
 *
 * The healthy path is easy to check and easy to fool yourself with: every
 * browser this suite can drive passes it. So the test breaks a required
 * primitive on purpose and asserts the refusal — and, above all, that the
 * password field is not reachable behind it.
 *
 * No invite and no account: nothing here gets as far as registering.
 */

import { Peer, launchBrowser, sleep } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

console.log(`Browser-support gate against ${BASE}`);
const { cdp, cleanup } = await launchBrowser('support');

// ── A capable browser must not notice the gate at all ──
const good = await Peer.open(cdp, 'capable');
await good.goto(BASE + '/');
ok(await good.eval(`document.querySelector('#boot').classList.contains('hidden')`),
  'a capable browser leaves the boot notice behind');
ok(await good.eval(`!document.querySelector('#auth').classList.contains('hidden')`),
  'and lands on the sign-in page');
ok(await good.eval(`!document.querySelector('#boot-detail') || document.querySelector('#boot-detail').classList.contains('hidden')`),
  'with nothing reported as missing');

/** Start a context whose crypto is broken in one specific way, before any page script runs. */
async function withBroken(name, source) {
  const peer = await Peer.open(cdp, name);
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source }, peer.sessionId);
  await peer.goto(BASE + '/', { expectApp: false });
  await sleep(1500);
  return peer;
}

const reasons = (peer) => peer.eval(
  `[...document.querySelectorAll('#boot-detail li')].map((n) => n.textContent)`);

const refused = async (peer, label, expect) => {
  ok(await peer.eval(`document.querySelector('#auth').classList.contains('hidden')`),
    `${label}: the sign-in page is never shown`);
  // The one that matters. A refusal that still renders a password box is not a
  // refusal — the user types a real secret into a client that cannot hold it.
  ok(await peer.eval(`
    (() => {
      const auth = document.querySelector('#auth');
      return !auth || auth.classList.contains('hidden');
    })()
  `), `${label}: the password field is unreachable`);
  const found = await reasons(peer);
  ok(found.some((r) => r.includes(expect)),
    `${label}: says which capability is missing (${found.join('; ') || 'nothing'})`);
};

// ── One required primitive at a time ──
await refused(await withBroken('no-hkdf', `
  const real = crypto.subtle.deriveBits.bind(crypto.subtle);
  crypto.subtle.deriveBits = (algo, ...rest) => {
    if (algo && algo.name === 'HKDF') throw new Error('HKDF not implemented');
    return real(algo, ...rest);
  };
`), 'without HKDF', 'HKDF');

await refused(await withBroken('no-ecdh', `
  const real = crypto.subtle.generateKey.bind(crypto.subtle);
  crypto.subtle.generateKey = (algo, ...rest) => {
    if (algo && algo.name === 'ECDH') throw new Error('unsupported curve');
    return real(algo, ...rest);
  };
`), 'without ECDH', 'ECDH');

await refused(await withBroken('no-webrtc', `
  delete window.RTCPeerConnection;
`), 'without WebRTC', 'WebRTC');

// ── Optional capabilities degrade, they do not block ──
// Refusing here would cost the user a working encrypted session and buy nothing.
const noIdb = await Peer.open(cdp, 'no-indexeddb');
await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
  source: `Object.defineProperty(window, 'indexedDB', { value: null, configurable: true });`,
}, noIdb.sessionId);
await noIdb.goto(BASE + '/');
ok(await noIdb.eval(`!document.querySelector('#auth').classList.contains('hidden')`),
  'a browser without IndexedDB still gets a working sign-in');
const note = await noIdb.eval(`document.querySelector('.boot-note')?.textContent || ''`);
ok(note.includes('saved contacts'),
  `and is told which feature is unavailable (${note || 'no note'})`);
ok(note.includes('protected either way'),
  'without implying the encryption is weaker');

cdp.close();
cleanup();
console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
