/** Privacy regressions using the unchanged served client and controlled network timing. */
import { Peer, launchBrowser, waitFor, sleep, chooseDirectTransport } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const invites = [process.env.DD_INVITE, process.env.DD_INVITE2];
if (invites.some((v) => !v)) throw new Error('privacy: set DD_INVITE and DD_INVITE2');
let failures = 0;
const ok = (condition, message) => {
  if (condition) console.log('  ✓', message);
  else { failures++; console.error('  ✗', message); }
};
const { cdp, cleanup } = await launchBrowser('privacy');
try {
  const alice = await Peer.open(cdp, 'privacy A');
  const bob = await Peer.open(cdp, 'privacy B');
  await alice.instrumentPeerConnections();
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: `
    window.__privacySockets = [];
    const NativeSocket = WebSocket;
    window.WebSocket = class extends NativeSocket {
      constructor(...args) { super(...args); window.__privacySockets.push(this); }
    };
  ` }, alice.sessionId);

  const noRelay = { status: 200, body: JSON.stringify({ iceServers: [], ttl: 3600 }) };
  const validRelay = () => ({ status: 200, body: JSON.stringify({ ttl: 3600, iceServers: [{
    urls: ['turn:192.0.2.1:3478'], username: `${Math.floor(Date.now() / 1000) + 3600}:0123456789abcdef`,
    credential: 'AAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  }] }) });
  let response = noRelay;
  let holdScrub = false;
  let scrubRequest = null;
  let logoutRequest = null;
  let holdAuth = false;
  let authRequest = null;
  let authenticateRequests = 0;
  let holdRoom = false;
  let roomRequest = null;
  let holdWipe = false;
  const errors = [];
  await cdp.send('Fetch.enable', { patterns: [
    { urlPattern: '*/api/turn', requestStage: 'Request' },
    { urlPattern: '*/js/scrub.js', requestStage: 'Request' },
    { urlPattern: '*/api/logout*', requestStage: 'Request' },
    { urlPattern: '*/api/srp/challenge', requestStage: 'Request' },
    { urlPattern: '*/api/srp/authenticate', requestStage: 'Request' },
    { urlPattern: '*/api/room', requestStage: 'Request' },
  ] }, alice.sessionId);
  cdp.on(async (msg) => {
    if (msg.sessionId !== alice.sessionId || msg.method !== 'Fetch.requestPaused') return;
    const { requestId, request } = msg.params;
    try {
      if (holdAuth && request.url.endsWith('/api/srp/challenge')) {
        authRequest = requestId;
      } else if (request.url.endsWith('/api/srp/authenticate')) {
        authenticateRequests++;
        await cdp.send('Fetch.continueRequest', { requestId }, alice.sessionId);
      } else if (holdRoom && request.url.endsWith('/api/room')) {
        roomRequest = requestId;
      } else if (request.url.endsWith('/api/turn')) {
        await cdp.send('Fetch.fulfillRequest', {
          requestId, responseCode: response.status,
          responseHeaders: [{ name: 'Content-Type', value: 'application/json' }],
          body: Buffer.from(response.body).toString('base64'),
        }, alice.sessionId);
      } else if (holdScrub && request.url.endsWith('/js/scrub.js')) {
        scrubRequest = requestId;
      } else if ((holdScrub || holdWipe) && request.url.includes('/api/logout')) {
        logoutRequest = requestId;
      } else {
        await cdp.send('Fetch.continueRequest', { requestId }, alice.sessionId);
      }
    } catch (err) { errors.push(err.message); }
  });

  const suffix = Math.floor(Math.random() * 1e6);
  for (const [i, peer] of [alice, bob].entries()) {
    await peer.goto(BASE + '/');
    ok(await peer.register(`zz_pr${i}_${suffix}`, invites[i], 'privacy-test-passphrase-2208'), `${peer.name} registers`);
  }
  const landing = async (peer) => {
    await peer.goto(BASE + '/');
    if (!await waitFor(() => peer.eval(`!document.querySelector('#landing').classList.contains('hidden')`))) {
      throw new Error('privacy: did not return to the landing page');
    }
  };
  const loginAlice = async () => {
    await alice.eval(`fetch('/api/logout', { method: 'POST' }).then(() => true)`);
    await alice.goto(BASE + '/');
    if (!await waitFor(() => alice.eval(`!document.querySelector('#auth').classList.contains('hidden')`))) {
      throw new Error('privacy: sign-in page not shown');
    }
    await alice.eval(`document.querySelector('#auth-user').value = ${JSON.stringify(`zz_pr0_${suffix}`)};
      document.querySelector('#auth-pass').value = 'privacy-test-passphrase-2208';
      document.querySelector('#login-btn').click(); true`);
    if (!await waitFor(() => alice.eval(`!document.querySelector('#landing').classList.contains('hidden')`))) {
      throw new Error('privacy: sign-in did not return to landing');
    }
  };
  const panic = () => alice.eval(`window.__privacyPanicDocument = true; for (let i = 0; i < 3; i++)
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })); true`);
  const resume = async (requestId) => {
    try { await cdp.send('Fetch.continueRequest', { requestId }, alice.sessionId); }
    catch (err) { if (!/Invalid InterceptionId|Invalid requestId/.test(err.message)) throw err; }
  };
  const wipedReload = async () => {
    if (!await waitFor(() => alice.eval(`document.readyState === 'complete'
      && !window.__privacyPanicDocument
      && !document.querySelector('#login-btn').disabled
      && document.querySelector('#relay-toggle').checked`).catch(() => false), { timeout: 8000 })) {
      throw new Error('privacy: panic did not reload');
    }
    holdWipe = false;
  };

  console.log('panic cancels pending authentication and room entry');
  await alice.eval(`fetch('/api/logout', { method: 'POST' }).then(() => true)`);
  await alice.goto(BASE + '/');
  await waitFor(() => alice.eval(`!document.querySelector('#auth').classList.contains('hidden')`));
  holdAuth = holdWipe = true;
  authenticateRequests = 0;
  await alice.eval(`document.querySelector('#auth-user').value = ${JSON.stringify(`zz_pr0_${suffix}`)};
    document.querySelector('#auth-pass').value = 'privacy-test-passphrase-2208';
    document.querySelector('#login-btn').click(); true`);
  if (!await waitFor(() => authRequest)) throw new Error('privacy: auth challenge not intercepted');
  await panic();
  if (!await waitFor(() => logoutRequest)) throw new Error('privacy: auth wipe not intercepted');
  holdAuth = false;
  await resume(authRequest);
  await sleep(1800);
  ok(authenticateRequests === 0, 'a delayed sign-in never sends a new proof after panic');
  ok(await alice.eval(`!document.querySelector('#auth').classList.contains('hidden')`),
    'a delayed sign-in cannot restore the account screen after panic');
  await wipedReload();

  // Derivation cannot be aborted like fetch. Its result may still arrive after
  // cleanup, and must be discarded before an authentication request is made.
  await alice.eval(`fetch('/api/logout', { method: 'POST' }).then(() => true)`);
  await alice.goto(BASE + '/');
  await waitFor(() => alice.eval(`!document.querySelector('#auth').classList.contains('hidden')`));
  holdWipe = true;
  logoutRequest = null;
  authenticateRequests = 0;
  await alice.eval(`(() => {
    const derive = crypto.subtle.deriveBits.bind(crypto.subtle);
    let hold = true;
    crypto.subtle.deriveBits = async (...args) => {
      const bits = await derive(...args);
      if (hold) { hold = false; await new Promise((resolve) => { window.__privacyResumeDerive = resolve; }); }
      return bits;
    };
    document.querySelector('#auth-user').value = ${JSON.stringify(`zz_pr0_${suffix}`)};
    document.querySelector('#auth-pass').value = 'privacy-test-passphrase-2208';
    document.querySelector('#login-btn').click();
    return true;
  })()`);
  if (!await waitFor(() => alice.eval('!!window.__privacyResumeDerive'))) throw new Error('privacy: derivation not held');
  await panic();
  if (!await waitFor(() => logoutRequest)) throw new Error('privacy: derivation wipe not intercepted');
  await alice.eval('window.__privacyResumeDerive(); true');
  await sleep(1800);
  ok(authenticateRequests === 0, 'a password derivation completed after panic cannot send a proof');
  ok(await alice.eval(`!document.querySelector('#auth').classList.contains('hidden')`),
    'a late password derivation leaves the wiped screen clear');
  await wipedReload();
  await loginAlice();

  response = validRelay();
  holdRoom = holdWipe = true;
  logoutRequest = null;
  await alice.eval(`document.querySelector('#create-room').click(); true`);
  if (!await waitFor(() => roomRequest)) throw new Error('privacy: room request not intercepted');
  await panic();
  if (!await waitFor(() => logoutRequest)) throw new Error('privacy: room wipe not intercepted');
  const socketsAfterWipe = await alice.eval('window.__privacySockets.length');
  holdRoom = false;
  await resume(roomRequest);
  await sleep(500);
  ok(await alice.eval('window.__privacySockets.length') === socketsAfterWipe,
    'a delayed room response opens no signaling socket after panic');
  ok(await alice.eval(`!document.querySelector('#auth').classList.contains('hidden')
    && document.querySelector('#messages').children.length === 0`),
    'a delayed room response cannot restore the conversation or invitation');
  await wipedReload();
  await loginAlice();

  // Ordinary logout also cancels work, without relying on the panic flag or a
  // reload. Deliver the successful room response after the session has ended.
  holdRoom = true;
  roomRequest = null;
  await alice.eval(`document.querySelector('#create-room').click(); true`);
  if (!await waitFor(() => roomRequest)) throw new Error('privacy: logout room request not intercepted');
  await alice.eval(`document.querySelector('#logout-btn').click(); true`);
  if (!await waitFor(() => alice.eval(`!document.querySelector('#auth').classList.contains('hidden')`))) {
    throw new Error('privacy: ordinary logout did not finish');
  }
  const socketsAfterLogout = await alice.eval('window.__privacySockets.length');
  holdRoom = false;
  try {
    await cdp.send('Fetch.fulfillRequest', { requestId: roomRequest, responseCode: 200,
      responseHeaders: [{ name: 'Content-Type', value: 'application/json' }],
      body: Buffer.from(JSON.stringify({ code: '0123456789abcdef01234567' })).toString('base64'),
    }, alice.sessionId);
  } catch (err) { if (!/Invalid InterceptionId|Invalid requestId/.test(err.message)) throw err; }
  await sleep(500);
  ok(await alice.eval('window.__privacySockets.length') === socketsAfterLogout,
    'a late room response opens no signaling socket after ordinary logout');
  await loginAlice();

  console.log('relay-only fails closed');
  for (const [name, value, join] of [
    ['no relay configured', noRelay],
    ['expired session', { status: 401, body: '{}' }],
    ['rate-limited credentials', { status: 429, body: '{}' }],
    ['server error', { status: 500, body: '{}' }],
    ['malformed JSON', { status: 200, body: '{' }],
    ['expired credential', { status: 200, body: validRelay().body.replace(/\d{10,12}:/, '1000000000:') }],
    ['joining without a relay', noRelay, true],
  ]) {
    response = value;
    await landing(alice);
    await alice.eval(`
      document.querySelector('#room-code-input').value = '0123456789abcdef01234567';
      document.querySelector(${JSON.stringify(join ? '#join-room' : '#create-room')}).click(); true
    `);
    const blocked = await waitFor(() => alice.eval(`(() => {
      const el = document.querySelector('#landing-error');
      return !document.querySelector('#landing').classList.contains('hidden')
        && !el.classList.contains('hidden') && el.textContent.includes('Connection blocked');
    })()`), { timeout: 5000 });
    ok(blocked, `${name}: explains the refusal on the landing page`);
    ok(await alice.eval(`document.querySelector('#relay-toggle').checked
      && window.__privacySockets.length === 0
      && window.__ddPeerConnections.every((pc) => pc.connectionState === 'closed')`),
    `${name}: preserves the setting and opens no signaling or peer connection`);
  }

  // Credentials can expire while an empty room is waiting for someone. A later
  // refresh failure must not turn the already selected privacy policy into all.
  response = validRelay();
  await landing(alice);
  await alice.eval(`document.querySelector('#create-room').click(); true`);
  const room = await waitFor(async () => {
    const value = await alice.eval(`document.querySelector('#room-code').textContent`);
    return /^[0-9a-f]{24}$/.test(value) ? value : false;
  });
  if (!room) throw new Error('privacy: valid relay configuration did not allow a room');
  response = { status: 500, body: '{}' };
  await alice.eval(`const realNow = Date.now; Date.now = () => realNow() + 7200000; true`);
  await chooseDirectTransport(bob);
  await bob.eval(`document.querySelector('#room-code-input').value = ${JSON.stringify(room)};
    document.querySelector('#join-room').click(); true`);
  ok(await waitFor(() => alice.eval(`[...document.querySelectorAll('.msg.system')]
    .some((n) => n.textContent.includes('Connection blocked'))`)), 'a failed refresh after expiry blocks the arriving peer');
  ok(await alice.eval(`window.__ddPeerConnections.every((pc) => pc.connectionState === 'closed')`),
    'expired relay credentials never create a direct peer connection');

  response = noRelay;
  await landing(alice);
  await landing(bob);
  await chooseDirectTransport(alice);
  await chooseDirectTransport(bob);
  await alice.enableSavedContacts();
  holdScrub = true;
  await alice.eval(`document.querySelector('#create-room').click(); true`);
  const directRoom = await waitFor(async () => {
    const code = await alice.eval(`document.querySelector('#room-code').textContent`);
    return /^[0-9a-f]{24}$/.test(code) ? code : false;
  });
  if (!directRoom) throw new Error('privacy: explicit direct choice did not allow a room');
  await bob.eval(`document.querySelector('#room-code-input').value = ${JSON.stringify(directRoom)};
    document.querySelector('#join-room').click(); true`);
  const encrypted = await waitFor(async () => (await alice.sas()) && (await bob.sas()), { timeout: 45000 });
  if (!encrypted) throw new Error('privacy: explicit direct peers did not establish encryption');
  ok(await alice.sas() === await bob.sas(), 'an explicit direct choice still establishes the same safety code');
  await alice.clickVerify();
  await bob.clickVerify();
  if (!await waitFor(async () => await alice.verified() && await bob.verified())) throw new Error('privacy: verification failed');

  console.log('panic cancels pending file preparation without a logout response');
  if (!await waitFor(() => scrubRequest)) throw new Error('privacy: scrub import was not intercepted');
  await alice.sendFile('must-not-return.txt', 'sensitive pending file');
  await alice.eval(`localStorage.setItem('dd_lang', 'ro'); document.querySelector('#panic-btn').click(); true`);
  if (!await waitFor(() => logoutRequest)) throw new Error('privacy: logout was not intercepted');
  ok((await alice.receivedFiles()).length === 0, 'panic removes the file cards immediately');
  ok(await alice.eval(`localStorage.getItem('dd_prefs') === null && localStorage.getItem('dd_lang') === null`),
    'preferences and language are removed locally without waiting for Clear-Site-Data');
  ok(await alice.eval(`(async () => {
    const db = await new Promise((resolve, reject) => {
      const r = indexedDB.open('deaddrop-identity'); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error);
    });
    try { return await new Promise((resolve) => {
      const r = db.transaction('identity').objectStore('identity').get('self'); r.onsuccess = () => resolve(!r.result);
    }); } finally { db.close(); }
  })()`), 'the saved identity is deleted before the logout response arrives');
  await cdp.send('Fetch.continueRequest', { requestId: scrubRequest }, alice.sessionId);
  await sleep(350);
  ok((await alice.receivedFiles()).length === 0, 'a delayed original scrub module cannot resurrect a file or Blob link');
  ok((await bob.receivedFiles()).length === 0, 'the abandoned file is never sent to the other peer');
  ok(await waitFor(() => alice.eval(`document.readyState === 'complete'
    && document.querySelector('#relay-toggle').checked && document.querySelector('#scrub-toggle').checked`)
    .catch(() => false), { timeout: 8000 }), 'a hung logout has a bound and the next page restores protective defaults');
  ok(errors.length === 0 || errors.every((e) => /Invalid InterceptionId|Invalid requestId|Target closed/.test(e)),
    `network interception completed without unexpected errors (${errors.join('; ') || 'none'})`);
} finally {
  cdp.close();
  cleanup();
}
console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exitCode = failures ? 1 : 0;
