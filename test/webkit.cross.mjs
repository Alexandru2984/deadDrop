/**
 * A session between two different engines: Safari on one side, Chrome on the
 * other.
 *
 *   DD_URL=… DD_INVITE=… DD_INVITE2=… node test/webkit.cross.mjs
 *
 * This started as two Safaris and could not be. macOS runs one Safari, and its
 * driver says so plainly: "The Safari instance is already paired with another
 * WebDriver session." The limit turned out to be a better test. Two people on
 * the same browser is the case that already has coverage; someone on an iPhone
 * talking to someone on a laptop is the one that actually happens, and it is the
 * one where a disagreement between engines has somewhere to hide.
 *
 * Both halves derive the same keys from the same transcript, or the safety codes
 * differ and neither side can send anything. That is the property worth pinning
 * across engines — and the reason it is worth pinning is Firefox, where the
 * first cross-engine run found a handshake race that broke every session.
 */

import { DriverPeer, launchDriver } from './lib/webdriver.mjs';
import { existsSync } from 'node:fs';
import { waitFor } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITES = [process.env.DD_INVITE || '', process.env.DD_INVITE2 || ''];
const PASS = 'webkit-pair-passphrase-3390';
const PORT = Number(process.env.DD_DRIVER_PORT || 4444);

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

if (!INVITES[0] || !INVITES[1]) {
  console.error('cross-engine: set DD_INVITE and DD_INVITE2');
  process.exit(1);
}

// One driver process per peer, each with its own binary and capabilities, so
// the two sides can be different browsers.
const CHROME_ARGS = ['--headless=new', '--no-sandbox', '--disable-gpu',
  '--disable-dev-shm-usage', '--use-fake-device-for-media-stream',
  '--use-fake-ui-for-media-stream'];

const spec = (side, port) => {
  const binary = process.env[`DD_WEBDRIVER_${side}`]
    || (side === 'A' ? '/usr/bin/safaridriver' : findChromedriver());
  const caps = process.env[`DD_CAPABILITIES_${side}`]
    || (side === 'A'
      ? '{"browserName":"safari"}'
      : JSON.stringify({ browserName: 'chrome', 'goog:chromeOptions': { args: CHROME_ARGS } }));
  return {
    label: side === 'A' ? 'Safari' : 'Chrome',
    requireEnv: 'DD_REQUIRE_WEBKIT',
    binary,
    args: [`--port=${port}`],
    port,
    capabilities: { alwaysMatch: JSON.parse(caps) },
  };
};

/** Where the runner images keep it, in the order worth trying. */
function findChromedriver() {
  for (const candidate of [
    process.env.CHROMEWEBDRIVER && `${process.env.CHROMEWEBDRIVER}/chromedriver`,
    '/usr/local/bin/chromedriver',
    '/opt/homebrew/bin/chromedriver',
    '/usr/bin/chromedriver',
  ].filter(Boolean)) {
    if (existsSync(candidate)) return candidate;
  }
  return '';
}

const suffix = Math.floor(Math.random() * 1e6);
const USERS = [`zz_wa_${suffix}`, `zz_wb_${suffix}`];
console.log(`Cross-engine run against ${BASE}: Safari (${USERS[0]}) ↔ Chrome (${USERS[1]})`);

const a = await launchDriver(spec('A', PORT));
const b = await launchDriver(spec('B', PORT + 1));
const alice = new DriverPeer(a.driver, 'safari');
const bob = new DriverPeer(b.driver, 'chrome');

try {
  await alice.goto(BASE + '/');
  await bob.goto(BASE + '/');
  ok(true, 'both engines start the app and clear its browser-support gate');

  ok(await alice.register(USERS[0], INVITES[0], PASS), 'peer A registers');
  ok(await bob.register(USERS[1], INVITES[1], PASS), 'peer B registers');

  await alice.eval(`(() => { document.querySelector('#create-room').click(); return true; })()`);
  const room = await waitFor(async () => {
    const code = await alice.eval(`document.querySelector('#room-code').textContent`);
    return code && code.length === 24 ? code : false;
  });
  ok(room, 'peer A creates a room');

  await bob.eval(`(() => {
    document.querySelector('#room-code-input').value = ${JSON.stringify(room)};
    document.querySelector('#join-room').click();
    return true;
  })()`);
  ok(await waitFor(() => bob.inChat()), 'peer B joins over the same signaling');

  // The hybrid handshake runs entirely in page script. A different WebCrypto and
  // a different WebRTC stack arriving at the same safety code is the point.
  const sasA = await waitFor(() => alice.sas(), { timeout: 60000 });
  const sasB = await waitFor(() => bob.sas(), { timeout: 60000 });
  ok(sasA && sasB, 'Safari and Chrome complete the hybrid handshake with each other');
  ok(sasA === sasB, `both derive the same safety code (${sasA} / ${sasB})`);

  ok(await alice.verified() === false && await bob.verified() === false,
    'traffic stays locked before anyone confirms');
  ok(await alice.clickVerify() && await bob.clickVerify(), 'both confirm the code');
  ok(await waitFor(() => alice.verified()) && await waitFor(() => bob.verified()),
    'mutual confirmation unlocks both sides');

  const fromA = 'safari says hello ' + suffix;
  await alice.send(fromA);
  ok(await waitFor(async () => (await bob.transcript()).includes(fromA)),
    'a message from Safari is decrypted by Chrome');

  const fromB = 'and back again ' + suffix;
  await bob.send(fromB);
  ok(await waitFor(async () => (await alice.transcript()).includes(fromB)),
    'and the reply is decrypted by Safari');
} finally {
  await a.driver.quit();
  await b.driver.quit();
  a.cleanup();
  b.cleanup();
}

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
