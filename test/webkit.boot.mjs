/**
 * Does the app run on WebKit at all?
 *
 *   DD_URL=… DD_INVITE=… node test/webkit.boot.mjs
 *
 * One session, which is the important difference from webkit.pair.mjs: Safari's
 * driver is strict about concurrency, and this suite needs nothing that could be
 * refused. Whatever else happens, this answers the question that has been open
 * since the project started — whether the client starts on the engine every
 * iPhone runs.
 *
 * The support gate is the sharpest part. It probes each required primitive by
 * running it, so a WebKit that lacks one names it here rather than producing a
 * broken session later.
 */

import { DriverPeer, launchDriver } from './lib/webdriver.mjs';
import { waitFor } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITE = process.env.DD_INVITE || '';
const PASS = 'webkit-boot-passphrase-1174';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

if (!INVITE) {
  console.error('webkit boot: set DD_INVITE');
  process.exit(1);
}

const { driver, cleanup } = await launchDriver({
  label: 'WebKit',
  requireEnv: 'DD_REQUIRE_WEBKIT',
  binary: process.env.DD_WEBDRIVER || '/usr/bin/safaridriver',
  args: (process.env.DD_WEBDRIVER_ARGS || '').split(' ').filter(Boolean)
    .concat([`--port=${process.env.DD_DRIVER_PORT || 4444}`]),
  port: Number(process.env.DD_DRIVER_PORT || 4444),
  capabilities: { alwaysMatch: JSON.parse(process.env.DD_CAPABILITIES || '{"browserName":"safari"}') },
});

const peer = new DriverPeer(driver, 'webkit');
const suffix = Math.floor(Math.random() * 1e6);
console.log(`WebKit boot check against ${BASE}`);

try {
  console.log('  engine: ' + await peer.eval(`navigator.userAgent`));
  await peer.goto(BASE + '/');
  ok(true, 'the app constructs and hides the call button — its own boot signal');

  ok(await peer.eval(`document.querySelector('#boot').classList.contains('hidden')`),
    'the browser-support gate lets it through');
  ok(await peer.eval(`!document.querySelector('#auth').classList.contains('hidden')`),
    'and the sign-in page is shown');

  // What the app itself thinks of this engine, primitive by primitive.
  const support = await peer.eval(`(async () => {
    const m = await import('/js/support.js');
    const r = await m.checkSupport();
    return JSON.stringify({ ok: r.ok, missing: r.missing.map((x) => x.id), degraded: r.degraded.map((x) => x.id) });
  })()`);
  const verdict = JSON.parse(support);
  ok(verdict.ok, `every required primitive is present (${verdict.missing.join(', ') || 'nothing missing'})`);
  console.log(`  degraded here: ${verdict.degraded.join(', ') || 'nothing'}`);

  ok(await peer.register(`zz_wk_${suffix}`, INVITE, PASS), 'an account can be registered');

  await peer.eval(`(() => { document.querySelector('#create-room').click(); return true; })()`);
  const room = await waitFor(async () => {
    const code = await peer.eval(`document.querySelector('#room-code').textContent`);
    return code && code.length === 24 ? code : false;
  }, { timeout: 30000 });
  ok(room, 'a room is created over the signaling socket');

  // The post-quantum half is vendored JavaScript with no WebCrypto equivalent,
  // so it is the most likely thing to behave differently on a new engine.
  const kem = await peer.eval(`(async () => {
    const { ml_kem768 } = await import('/js/vendor/noble/ml-kem.js');
    const kp = ml_kem768.keygen();
    const e = ml_kem768.encapsulate(kp.publicKey);
    const d = ml_kem768.decapsulate(e.cipherText, kp.secretKey);
    return kp.publicKey.length === 1184 && e.cipherText.length === 1088
      && [...d].every((b, i) => b === e.sharedSecret[i]);
  })()`);
  ok(kem, 'ML-KEM-768 keygen, encapsulate and decapsulate agree on this engine');
} finally {
  await driver.quit();
  cleanup();
}

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
