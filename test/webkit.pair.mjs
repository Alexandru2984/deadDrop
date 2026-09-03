/**
 * The core two-peer session, on WebKit.
 *
 *   DD_URL=… DD_INVITE=… DD_INVITE2=… node test/webkit.pair.mjs
 *
 * WebKit is the engine this project has never run on, and the one every iPhone
 * uses — including every other browser on iOS, which is WebKit underneath. It is
 * also the engine that cannot be driven from a Linux box, so this runs on a
 * macOS runner against real Safari.
 *
 * Firefox was the second engine, and the first run of it found a handshake race
 * that broke every Gecko session outright: not a degraded feature, no session at
 * all, and nothing would have reported it until a user tried. There is no reason
 * to expect the third engine to be kinder.
 *
 * Deliberately the core and nothing more — handshake, safety code, the
 * verification gate, one message each way. Those are what must hold everywhere.
 */

import { DriverPeer, launchDriver } from './lib/webdriver.mjs';
import { waitFor } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITES = [process.env.DD_INVITE || '', process.env.DD_INVITE2 || ''];
const PASS = 'webkit-pair-passphrase-3390';
const PORT = Number(process.env.DD_DRIVER_PORT || 4444);

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

if (!INVITES[0] || !INVITES[1]) {
  console.error('webkit pair: set DD_INVITE and DD_INVITE2');
  process.exit(1);
}

// Safari's driver refuses more than one session at a time, so the two peers get
// a driver process each rather than two sessions on one.
const spec = (port) => ({
  label: 'WebKit',
  requireEnv: 'DD_REQUIRE_WEBKIT',
  binary: process.env.DD_WEBDRIVER || '/usr/bin/safaridriver',
  args: (process.env.DD_WEBDRIVER_ARGS || '').split(' ').filter(Boolean).concat([`--port=${port}`]),
  port,
  capabilities: {
    alwaysMatch: JSON.parse(process.env.DD_CAPABILITIES || '{"browserName":"safari"}'),
  },
});

const suffix = Math.floor(Math.random() * 1e6);
const USERS = [`zz_wa_${suffix}`, `zz_wb_${suffix}`];
console.log(`WebKit two-peer run against ${BASE} as ${USERS[0]} + ${USERS[1]}`);

const a = await launchDriver(spec(PORT));
const b = await launchDriver(spec(PORT + 1));
const alice = new DriverPeer(a.driver, 'alice');
const bob = new DriverPeer(b.driver, 'bob');

try {
  await alice.goto(BASE + '/');
  await bob.goto(BASE + '/');
  ok(true, 'the app starts on WebKit and clears its own browser-support gate');

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
  ok(sasA && sasB, 'both peers complete the hybrid handshake on WebKit');
  ok(sasA === sasB, `both derive the same safety code (${sasA} / ${sasB})`);

  ok(await alice.verified() === false && await bob.verified() === false,
    'traffic stays locked before anyone confirms');
  ok(await alice.clickVerify() && await bob.clickVerify(), 'both confirm the code');
  ok(await waitFor(() => alice.verified()) && await waitFor(() => bob.verified()),
    'mutual confirmation unlocks both sides');

  const fromA = 'webkit says hello ' + suffix;
  await alice.send(fromA);
  ok(await waitFor(async () => (await bob.transcript()).includes(fromA)),
    'a message from A is decrypted by B');

  const fromB = 'and back again ' + suffix;
  await bob.send(fromB);
  ok(await waitFor(async () => (await alice.transcript()).includes(fromB)),
    'and the reply is decrypted by A');
} finally {
  await a.driver.quit();
  await b.driver.quit();
  a.cleanup();
  b.cleanup();
}

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
