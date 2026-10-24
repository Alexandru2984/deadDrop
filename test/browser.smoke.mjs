/**
 * Real-browser smoke test: drives headless Chrome over the DevTools Protocol.
 *
 *   DD_URL=http://127.0.0.1:8100 DD_INVITE=DD-… node test/browser.smoke.mjs
 *
 * The Go and Node suites cover protocol behaviour but never execute the page, so
 * nothing catches a policy the browser refuses to run under — a CSP directive
 * that blocks the app's own code, or a Trusted Types violation from an innerHTML
 * assignment that crept back in. Those fail silently in a unit test and loudly in
 * a user's face.
 *
 * Uses Node's built-in WebSocket and the Chromium that ships in the Playwright
 * cache; no npm dependencies.
 */

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
// When set, each emulated viewport is also captured to a PNG. CI uploads the
// directory so the mobile layout can be reviewed as rendered, not imagined.
const SHOT_DIR = process.env.DD_SCREENSHOT_DIR || '';
const INVITE = process.env.DD_INVITE || '';
const USER = 'zz_ui_' + Math.floor(Math.random() * 1e6);
const PASS = 'browser-smoke-passphrase-77';

const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
  `${process.env.HOME}/.cache/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell`,
  `${process.env.HOME}/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome`,
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
].filter(Boolean);

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

function findChrome() {
  for (const path of CHROME_CANDIDATES) if (existsSync(path)) return path;
  return null;
}

/* ── Minimal CDP client ── */

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.listeners = [];
    ws.addEventListener('message', (e) => {
      const msg = JSON.parse(e.data);
      if (msg.id !== undefined) {
        const entry = this.pending.get(msg.id);
        if (entry) {
          this.pending.delete(msg.id);
          msg.error ? entry.reject(new Error(msg.error.message)) : entry.resolve(msg.result);
        }
        return;
      }
      for (const fn of this.listeners) fn(msg);
    });
  }

  static async connect(url) {
    const ws = new WebSocket(url);
    await new Promise((resolve, reject) => {
      ws.addEventListener('open', resolve, { once: true });
      ws.addEventListener('error', () => reject(new Error('CDP socket failed')), { once: true });
    });
    return new CDP(ws);
  }

  send(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }

  on(fn) { this.listeners.push(fn); }

  /** Evaluate in the page and return the JSON value. Throws on a page exception. */
  async eval(expression) {
    const res = await this.send('Runtime.evaluate', {
      expression, awaitPromise: true, returnByValue: true,
    });
    if (res.exceptionDetails) {
      throw new Error(res.exceptionDetails.exception?.description || 'page exception');
    }
    return res.result.value;
  }

  close() { this.ws.close(); }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Returns what the condition produced, not merely that it held, so an assertion
// can report the value it waited for instead of the word "true".
async function waitFor(fn, { timeout = 8000, interval = 100 } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const value = await fn();
    if (value) return value;
    if (Date.now() > deadline) return false;
    await sleep(interval);
  }
}

/* ── Test run ── */

const chromePath = findChrome();
if (!chromePath) {
  // Skipping is fine on a developer box, but CI sets DD_REQUIRE_BROWSER=1 so a
  // missing browser fails loudly instead of quietly never running this suite.
  if (process.env.DD_REQUIRE_BROWSER === '1') {
    console.error('browser smoke: no Chromium found and DD_REQUIRE_BROWSER=1');
    process.exit(1);
  }
  console.log('browser smoke: no Chromium available — skipping');
  process.exit(0);
}
if (!INVITE) {
  console.error('browser smoke: set DD_INVITE');
  process.exit(1);
}

console.log(`Browser smoke against ${BASE} as ${USER}`);

const profile = mkdtempSync(join(tmpdir(), 'dd-smoke-'));
const chrome = spawn(chromePath, [
  '--headless=new',
  '--remote-debugging-port=0',
  `--user-data-dir=${profile}`,
  '--no-first-run',
  '--no-default-browser-check',
  '--disable-gpu',
  '--no-sandbox',
  // A CI container has no session bus and a small /dev/shm. Without these,
  // startup stalls on dbus long enough to miss the endpoint deadline, or the
  // renderer dies outright once shared memory runs out.
  '--disable-dev-shm-usage',
  '--disable-extensions',
  '--disable-component-update',
  '--disable-default-apps',
  '--disable-background-networking',
  '--disable-sync',
  '--mute-audio',
  'about:blank',
], {
  stdio: ['ignore', 'ignore', 'pipe'],
  env: { ...process.env, DBUS_SESSION_BUS_ADDRESS: '/dev/null' },
});

// Chrome writes its chosen port and websocket path to DevToolsActivePort in the
// profile directory. Reading that file is deterministic; scraping the same
// information out of stderr races against chunk boundaries and startup timing,
// which is exactly how this step failed intermittently on CI. stderr is kept
// only as a fallback and to surface a launch error.
let wsURL = null;
let stderrTail = '';
chrome.stderr.on('data', (chunk) => {
  const text = chunk.toString();
  stderrTail = (stderrTail + text).slice(-2000);
  const m = /ws:\/\/[^\s]+/.exec(text);
  if (m && !wsURL) wsURL = m[0];
});

function readDevToolsEndpoint() {
  const portFile = join(profile, 'DevToolsActivePort');
  if (!existsSync(portFile)) return null;
  const [port, path] = readFileSync(portFile, 'utf8').split('\n');
  if (!port || !path) return null;
  return `ws://127.0.0.1:${port.trim()}${path.trim()}`;
}

const cleanup = () => {
  try { chrome.kill('SIGKILL'); } catch { /* already gone */ }
  try { rmSync(profile, { recursive: true, force: true }); } catch { /* best effort */ }
};
process.on('exit', cleanup);

const gotEndpoint = await waitFor(() => {
  const fromFile = readDevToolsEndpoint();
  if (fromFile) { wsURL = fromFile; return true; }
  return wsURL !== null;
}, { timeout: 60000, interval: 100 });

if (!gotEndpoint) {
  console.error('browser smoke: Chromium did not report a debugging endpoint');
  if (chrome.exitCode !== null) console.error(`  chrome exited with ${chrome.exitCode}`);
  if (stderrTail) console.error('  chrome stderr:\n' + stderrTail);
  process.exit(1);
}

const browser = await CDP.connect(wsURL);
const { targetId } = await browser.send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await browser.send('Target.attachToTarget', { targetId, flatten: true });

// Every call below carries our page session id.
const raw = browser;
const sessionSend = (method, params = {}) => {
  const id = ++raw.id;
  raw.ws.send(JSON.stringify({ id, method, params, sessionId }));
  return new Promise((resolve, reject) => raw.pending.set(id, { resolve, reject }));
};
const sessionEval = async (expression) => {
  const res = await sessionSend('Runtime.evaluate', {
    expression, awaitPromise: true, returnByValue: true,
  });
  if (res.exceptionDetails) {
    throw new Error(res.exceptionDetails.exception?.description || 'page exception');
  }
  return res.result.value;
};

const consoleErrors = [];
const pageErrors = [];
const cspViolations = [];

raw.on((msg) => {
  if (msg.sessionId !== sessionId) return;
  if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
    consoleErrors.push(msg.params.args.map((a) => a.value ?? a.description ?? '').join(' '));
  }
  if (msg.method === 'Runtime.exceptionThrown') {
    pageErrors.push(msg.params.exceptionDetails.exception?.description
      || msg.params.exceptionDetails.text || 'exception');
  }
  if (msg.method === 'Log.entryAdded') {
    const e = msg.params.entry;
    if (e.source === 'security' || /Content Security Policy|Trusted Type/i.test(e.text || '')) {
      cspViolations.push(e.text);
    }
  }
});

await sessionSend('Runtime.enable');
await sessionSend('Log.enable');
await sessionSend('Page.enable');

// Keep a handle on the page's sockets so a dropped connection can be
// simulated. Injected through the protocol, outside the page's CSP.
await sessionSend('Page.addScriptToEvaluateOnNewDocument', { source: `
  window.__sockets = [];
  const Native = WebSocket;
  window.WebSocket = class extends Native {
    constructor(...args) { super(...args); window.__sockets.push(this); }
  };
` });
await sessionSend('Page.navigate', { url: BASE + '/' });
const booted = await waitFor(async () => sessionEval(
  `!!document.querySelector('#auth') && !document.querySelector('#auth').classList.contains('hidden')`,
).catch(() => false));
ok(booted, 'the app boots and shows the auth page');

// The security explanation is offered in the language the interface is in.
const aboutHref = async () => sessionEval(`document.querySelector('#auth .about-link').getAttribute('href')`);
const hrefEn = await aboutHref();
await sessionEval(`document.querySelector('.lang-btn').click(); true`);
const hrefRo = await aboutHref();
await sessionEval(`document.querySelector('.lang-btn').click(); true`);
ok(hrefEn === '/about.html' && hrefRo === '/about.ro.html',
  `the security page link follows the interface language (${hrefEn} / ${hrefRo})`);

// A failed login says so in the interface's words, not the server's
// lower-case English.
await sessionEval(`
  document.querySelector('#auth-user').value = 'zz_nobody_${Math.floor(Math.random() * 1e6)}';
  document.querySelector('#auth-pass').value = 'not-the-password-123';
  document.querySelector('#login-btn').click();
  true
`);
const loginError = await waitFor(async () => sessionEval(
  `document.querySelector('.auth-error:not(.hidden)')?.textContent || ''`).catch(() => ''), { timeout: 15000 });
ok(loginError && loginError !== 'invalid credentials',
  `a failed login is reported in the interface language (${loginError || 'nothing shown'})`);

// Register through the real UI, so the SRP client, the fetch layer and the
// post-auth render all execute under the live CSP.
await sessionEval(`
  document.querySelector('#auth-user').value = ${JSON.stringify(USER)};
  document.querySelector('#auth-pass').value = ${JSON.stringify(PASS)};
  document.querySelector('#auth-invite').value = ${JSON.stringify(INVITE)};
  document.querySelector('#register-btn').click();
  true
`);
const landed = await waitFor(async () => sessionEval(
  `!document.querySelector('#landing').classList.contains('hidden')`,
).catch(() => false), { timeout: 20000 });
ok(landed, 'registration completes and the landing page renders');

// The account panel is where the new current-password field lives.
await sessionEval(`document.querySelector('#settings-btn').click(); true`);
const panel = await sessionEval(`
  !!document.querySelector('#current-pass') &&
  !document.querySelector('#account-panel').classList.contains('hidden')
`);
ok(panel, 'the account panel exposes a current-password field');

// Changing the password: a weak one is refused before anything is sent, a good
// one is accepted only with the current password proved again.
// The outcome is written under the button and stays there: it used to flash
// through the button label for two seconds, unannounced to a screen reader.
const msgOf = (id) => sessionEval(`(() => {
  const el = document.querySelector('#${id}');
  return el.classList.contains('hidden') || el.getAttribute('role') !== 'status' ? '' : el.textContent;
})()`);
const flashOf = () => msgOf('pass-msg');
await sessionEval(`
  document.querySelector('#new-pass').value = 'short';
  document.querySelector('#current-pass').value = ${JSON.stringify(PASS)};
  document.querySelector('#change-pass-btn').click(); true
`);
ok(/12/.test(await flashOf()), 'a short new password is refused in the browser');
await sleep(2800);
ok(/12/.test(await flashOf()), 'and the reason is still there to read after the old flash would have gone');
ok(await sessionEval(`document.querySelector('#change-pass-btn').textContent`) === 'Change password',
  'while the button keeps its own label');
const NEW_PASS = PASS + '-rotated';
await sessionEval(`
  document.querySelector('#new-pass').value = ${JSON.stringify(NEW_PASS)};
  document.querySelector('#current-pass').value = ${JSON.stringify(PASS)};
  document.querySelector('#change-pass-btn').click(); true
`);
const changed = await waitFor(async () => /✓/.test(await flashOf()), { timeout: 20000 });
ok(changed, 'the password is changed after re-proving the current one');
const stillSignedIn = await sessionEval(`fetch('/api/me').then((r) => r.status)`);
ok(stillSignedIn === 200, 'the browser that changed it keeps its session');

// The decoy password: held to the same strength rule, never equal to the real
// one (only the browser can compare them), and a result that can be read.
const setDuress = (pw, current) => sessionEval(`
  document.querySelector('#duress-pass').value = ${JSON.stringify(pw)};
  document.querySelector('#current-pass').value = ${JSON.stringify(current)};
  document.querySelector('#set-duress-btn').click(); true
`);
await setDuress('short', NEW_PASS);
ok(/12/.test(await msgOf('duress-msg')), `a short decoy password is refused with a reason (${await msgOf('duress-msg') || 'nothing shown'})`);
await setDuress(NEW_PASS, NEW_PASS);
ok(/differ/.test(await msgOf('duress-msg')), 'a decoy equal to the real password is refused');
await setDuress('decoy-' + NEW_PASS.split('').reverse().join(''), NEW_PASS);
ok(await waitFor(async () => /✓/.test(await msgOf('duress-msg')), { timeout: 20000 }),
  'a good decoy password is saved and says so');

// Settings survive a reload, and only the ones the user changed differ from
// the protective defaults.
await sessionEval(`
  (() => {
    const idle = document.querySelector('#idle-select');
    idle.value = '15'; idle.dispatchEvent(new Event('change'));
    const typing = document.querySelector('#typing-toggle');
    typing.checked = false; typing.dispatchEvent(new Event('change'));
    return true;
  })()
`);
await sessionEval(`location.reload(); true`);
await sleep(1500);
const relanded = await waitFor(async () => sessionEval(
  `!document.querySelector('#landing').classList.contains('hidden')`,
).catch(() => false), { timeout: 20000 });
const remembered = relanded && await sessionEval(`({
  idle: document.querySelector('#idle-select').value,
  typing: document.querySelector('#typing-toggle').checked,
  relay: document.querySelector('#relay-toggle').checked,
  scrub: document.querySelector('#scrub-toggle').checked,
})`);
ok(remembered && remembered.idle === '15' && remembered.typing === false,
  'changed settings are remembered across a reload');
ok(remembered && remembered.relay === true && remembered.scrub === true,
  'untouched protections stay at their defaults');
await sessionEval(`
  (() => {
    const idle = document.querySelector('#idle-select');
    idle.value = '0'; idle.dispatchEvent(new Event('change'));
    document.querySelector('#settings-btn').click();
    return true;
  })()
`);

// A join the server refuses — here, by sending it a malformed code — returns to
// the landing page with the reason, instead of leaving an empty chat view
// whose header holds the only clue.
await sessionEval(`(() => {
  const send = WebSocket.prototype.send;
  WebSocket.prototype.send = function (data) {
    const msg = JSON.parse(data);
    if (msg.type === 'join') { WebSocket.prototype.send = send; msg.room = 'zz'; data = JSON.stringify(msg); }
    return send.call(this, data);
  };
  document.querySelector('#room-code-input').value = 'a1b2c3d4e5f6a1b2c3d4e5f6';
  document.querySelector('#join-room').click();
  return true;
})()`);
const turnedAway = await waitFor(() => sessionEval(`(() => {
  const err = document.querySelector('#landing-error');
  return !document.querySelector('#landing').classList.contains('hidden')
    && document.querySelector('#chat-wrap').classList.contains('hidden')
    && !err.classList.contains('hidden') ? err.textContent : false;
})()`), { timeout: 15000 });
ok(turnedAway, `a refused join goes back to the landing page and says why (${turnedAway || 'stuck'})`);

// Typing a code nobody is using yet puts you in that room, alone. The client
// once sat on "Joining room…" forever because nothing came back to say so.
const emptyCode = [...crypto.getRandomValues(new Uint8Array(12))]
  .map((b) => b.toString(16).padStart(2, '0')).join('');
// Something that is not a code is refused where it was typed — the error used
// to go to the hidden conversation log, so the button seemed to do nothing.
await sessionEval(`
  document.querySelector('#room-code-input').value = 'not a room';
  document.querySelector('#join-room').click();
  true
`);
const refusedHere = await waitFor(() => sessionEval(`(() => {
  const err = document.querySelector('#landing-error');
  return !err.classList.contains('hidden') && err.getBoundingClientRect().height > 0
    && document.querySelector('#room-code-input').getAttribute('aria-invalid') !== null
    && !document.querySelector('#landing').classList.contains('hidden') ? err.textContent : false;
})()`), { timeout: 5000 });
ok(refusedHere, `a bad room code is refused visibly, on the landing page (${refusedHere || 'nothing shown'})`);

// The whole invitation link is what people are sent, and what they paste.
await sessionEval(`
  document.querySelector('#room-code-input').value = location.origin + '/#join=${emptyCode}';
  document.querySelector('#join-room').click();
  true
`);
const aloneInRoom = await waitFor(async () => sessionEval(
  `document.querySelector('#status').classList.contains('waiting')
   && !!document.querySelector('.share-link')`).catch(() => false), { timeout: 15000 });
ok(aloneInRoom, 'joining an empty room by code ends in "waiting", with the invitation to share');
ok(await sessionEval(`document.querySelector('#room-code').textContent`) === emptyCode,
  'a pasted invitation link joins the room it names');

// A phone changing networks drops the signaling socket. Someone waiting alone
// must get back into the same room by themselves, or whoever they invited
// arrives to nobody.
await sessionEval(`window.__sockets.at(-1).close(); true`);
const reconnecting = await waitFor(() => sessionEval(
  `document.querySelector('#status').classList.contains('disconnected')`), { timeout: 5000 });
ok(reconnecting, 'a dropped connection is shown as reconnecting, not as waiting');
const rejoined = await waitFor(() => sessionEval(
  `document.querySelector('#status').classList.contains('waiting')
   && window.__sockets.length >= 2 && window.__sockets.at(-1).readyState === 1
   && document.querySelectorAll('.share-link').length === 1`), { timeout: 15000 });
ok(rejoined, 'it rejoins the same room on its own, with one invitation on screen');

// A network that is simply gone is not a logged-out user. Each failed
// reconnect used to rerun the boot-time login check; with no answer from the
// server that read as "signed out", and the room was swapped for the sign-in
// page while the session was still good.
await sessionSend('Network.enable');
await sessionSend('Network.emulateNetworkConditions', { offline: true, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
await sessionEval(`window.__sockets.at(-1).close(); true`);
await sleep(7000); // long enough for at least two failed reconnects
const heldRoom = await sessionEval(`({
  chat: !document.querySelector('#chat-wrap').classList.contains('hidden'),
  auth: !document.querySelector('#auth').classList.contains('hidden'),
  status: document.querySelector('#status').textContent,
})`);
ok(heldRoom.chat && !heldRoom.auth, `offline, the room is kept rather than swapped for sign-in (${heldRoom.status})`);
await sessionSend('Network.emulateNetworkConditions', { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
ok(await waitFor(() => sessionEval(`document.querySelector('#status').classList.contains('waiting')
  && window.__sockets.at(-1).readyState === 1`), { timeout: 40000 }),
  'and back online it rejoins the room by itself');

// A login that really has ended — as after a server restart — goes to sign-in
// with the reason, since nobody is waiting in this room to talk to.
await sessionEval(`fetch('/api/logout', { method: 'POST' }).then(() => { window.__sockets.at(-1).close(); return true; })`);
const endedNote = await waitFor(() => sessionEval(`(() => {
  const auth = document.querySelector('#auth');
  const err = document.querySelector('#auth-error');
  return !auth.classList.contains('hidden') && !err.classList.contains('hidden') ? err.textContent : false;
})()`), { timeout: 20000 });
ok(/ended/i.test(endedNote || ''), `an ended login lands on sign-in and says why (${endedNote || 'nothing shown'})`);
await sessionEval(`
  document.querySelector('#auth-user').value = ${JSON.stringify(USER)};
  document.querySelector('#auth-pass').value = ${JSON.stringify(NEW_PASS)};
  document.querySelector('#login-btn').click(); true
`);
ok(await waitFor(() => sessionEval(`!document.querySelector('#landing').classList.contains('hidden')`), { timeout: 30000 }),
  'and logging in again works');

// The idle lock. Timers stop while a phone sleeps, so it has to judge by the
// wall clock when the page comes back; and signing out disarms it, or it would
// later wipe the identity and contacts of someone who had already left.
const signIn = async () => {
  await sessionEval(`
    document.querySelector('#auth-user').value = ${JSON.stringify(USER)};
    document.querySelector('#auth-pass').value = ${JSON.stringify(NEW_PASS)};
    document.querySelector('#login-btn').click(); true
  `);
  return waitFor(() => sessionEval(`!document.querySelector('#landing').classList.contains('hidden')`)
    .catch(() => false), { timeout: 30000 });
};
const skipClock = `(() => {
  const real = Date.now;
  Date.now = () => real() + 6 * 60_000;
  return () => { Date.now = real; };
})()`;
await sessionEval(`(() => {
  const idle = document.querySelector('#idle-select');
  idle.value = '5'; idle.dispatchEvent(new Event('change'));
  window.__idleMark = 1;
  document.querySelector('#logout-btn').click();
  return true;
})()`);
await waitFor(() => sessionEval(`!document.querySelector('#auth').classList.contains('hidden')`), { timeout: 10000 });
await sessionEval(`(() => {
  const restore = ${skipClock};
  window.dispatchEvent(new Event('focus'));
  document.dispatchEvent(new Event('visibilitychange'));
  restore();
  return true;
})()`);
await sleep(1500);
ok(await sessionEval(`window.__idleMark === 1`).catch(() => false),
  'after signing out, the idle lock no longer fires');
ok(await signIn(), 'signing back in after that works');
// Reloaded first, because a reload used to leave the lock unarmed until the
// first key or touch.
await sessionEval(`location.reload(); true`);
await sleep(1500);
await waitFor(() => sessionEval(`!document.querySelector('#landing').classList.contains('hidden')`)
  .catch(() => false), { timeout: 20000 });
await sessionEval(`(() => {
  window.__idleMark = 1;
  const restore = ${skipClock};
  document.dispatchEvent(new Event('visibilitychange'));
  restore();
  return true;
})()`);
ok(await waitFor(() => sessionEval(`window.__idleMark === undefined
  && document.readyState === 'complete'
  && !document.querySelector('#auth').classList.contains('hidden')`).catch(() => false), { timeout: 20000 }),
  'coming back after the idle period has passed on the wall clock wipes the tab, even untouched since a reload');
ok(await signIn(), 'and signing in after the wipe works');
await sessionEval(`(() => {
  const idle = document.querySelector('#idle-select');
  idle.value = '0'; idle.dispatchEvent(new Event('change'));
  return true;
})()`);
await sessionEval(`location.reload(); true`);
await waitFor(async () => sessionEval(
  `!document.querySelector('#landing').classList.contains('hidden')`).catch(() => false), { timeout: 20000 });

// Enter a room so the chat view, header and verify bar all render. Tapped
// twice, as an impatient thumb on a slow connection does: that used to make
// two rooms, two signalling connections and two invitations.
const socketsBefore = await sessionEval(`window.__sockets.filter((w) => w.readyState <= 1).length`);
await sessionEval(`(() => {
  window.__joins = [];
  const send = WebSocket.prototype.send;
  WebSocket.prototype.send = function (data) {
    try { const m = JSON.parse(data); if (m.type === 'join') window.__joins.push(m.room); } catch { /* binary */ }
    return send.call(this, data);
  };
  document.querySelector('#create-room').click();
  document.querySelector('#create-room').click();
  return true;
})()`);
const inRoom = await waitFor(async () => sessionEval(
  `!document.querySelector('#chat-wrap').classList.contains('hidden')
   && document.querySelector('#room-code').textContent.length === 24`,
).catch(() => false), { timeout: 15000 });
ok(inRoom, 'a room is created and the chat view renders');
await sleep(1500);
const once = await sessionEval(`({
  links: document.querySelectorAll('.share-link').length,
  joins: window.__joins,
  shown: document.querySelector('#room-code').textContent,
  sockets: window.__sockets.filter((w) => w.readyState <= 1).length,
  matches: [...document.querySelectorAll('.share-url')].every((n) =>
    n.textContent.endsWith(document.querySelector('#room-code').textContent)),
})`);
ok(once.links === 1 && once.matches && once.sockets <= Math.max(1, socketsBefore)
  && once.joins.length === 1 && once.joins[0] === once.shown,
  `a double tap creates one room (${JSON.stringify(once)})`);

// Alone in a room after a minute out of sight, the server has dropped this
// tab for missing pongs while the browser may still think the socket open.
// Coming back rejoins the same room on a fresh connection.
const resumed = await sessionEval(`(async () => {
  const room = document.querySelector('#room-code').textContent;
  const before = window.__sockets.length;
  window.__joins = [];
  const hidden = Object.getOwnPropertyDescriptor(Document.prototype, 'hidden');
  Object.defineProperty(document, 'hidden', { configurable: true, get: () => true });
  document.dispatchEvent(new Event('visibilitychange'));
  const now = Date.now;
  Date.now = () => now() + 60_000;
  Object.defineProperty(document, 'hidden', { configurable: true, get: () => false });
  try { document.dispatchEvent(new Event('visibilitychange')); } finally {
    Date.now = now;
    delete document.hidden;
  }
  document.querySelector('#privacy-screen').click();
  for (let i = 0; i < 60 && !window.__joins.length; i++) await new Promise((r) => setTimeout(r, 100));
  return { fresh: window.__sockets.length > before, joins: window.__joins, room };
})()`);
ok(resumed.fresh && resumed.joins.length === 1 && resumed.joins[0] === resumed.room,
  `back after a minute away, alone in a room, it rejoins on a fresh connection (${JSON.stringify(resumed)})`);
ok(await waitFor(() => sessionEval(`document.querySelector('#status').classList.contains('waiting')`), { timeout: 10000 }),
  'and is waiting in the room again');

// The share-link row is built by the DOM path that replaced innerHTML.
const shareRendered = await sessionEval(`
  (() => {
    const el = document.querySelector('.share-link');
    if (!el) return 'missing';
    const url = el.querySelector('.share-url');
    const btn = el.querySelector('.copy-link-btn');
    return url && btn && url.textContent.includes('#join=') ? 'ok' : 'incomplete';
  })()
`);
ok(shareRendered === 'ok', 'the share-link row renders through the DOM builder');

// Switching language turns the invitation too. It was drawn once, in the
// language of the moment, and stayed in it — a Romanian button in an English
// screen after switching back.
const shareLangs = await sessionEval(`(() => {
  const read = () => document.querySelector('.copy-link-btn').textContent
    + ' | ' + document.querySelector('.share-intro').textContent
    + ' | ' + document.querySelector('#status').textContent;
  const flip = () => document.querySelector('#lang-btn').click();
  const first = read(); flip(); const second = read(); flip();
  return { first, second, back: read() };
})()`);
const [firstParts, secondParts] = [shareLangs.first, shareLangs.second].map((x) => x.split(' | '));
ok(firstParts.every((part, i) => part !== secondParts[i]) && shareLangs.back === shareLangs.first,
  `the invitation and the room status follow a language switch (${shareLangs.second})`);

// Alone in a fresh room the invitation sits in the middle of the empty space,
// not pinned to the top over a blank screen.
const shareGap = await sessionEval(`
  (() => {
    const box = document.querySelector('#messages').getBoundingClientRect();
    const card = document.querySelector('.share-link').getBoundingClientRect();
    return Math.round(Math.abs((card.top - box.top) - (box.bottom - card.bottom)));
  })()
`);
ok(shareGap <= 40, `the invitation is centred in the empty room (off by ${shareGap}px)`);

// A browser that refuses the clipboard used to leave the button unchanged,
// which reads as "copied". It must select the link and say so instead.
const copyRefused = await sessionEval(`(async () => {
  const real = navigator.clipboard.writeText;
  navigator.clipboard.writeText = () => Promise.reject(new DOMException('denied', 'NotAllowedError'));
  document.querySelector('.copy-link-btn').click();
  await new Promise((r) => setTimeout(r, 300));
  navigator.clipboard.writeText = real;
  const notes = [...document.querySelectorAll('.msg.system')].map((n) => n.textContent);
  const selected = String(window.getSelection());
  const note = notes.find((n) => /would not copy/.test(n)) || '';
  document.querySelectorAll('.msg.system').forEach((n) => { if (n.textContent === note) n.remove(); });
  window.getSelection().removeAllRanges();
  return { note, selected };
})()`);
ok(copyRefused.note && copyRefused.selected.includes('#join='),
  `a refused copy selects the link and says so (${copyRefused.note || 'nothing shown'})`);

// A copied link is taken back out of the clipboard after a minute — by the
// wall clock, so a phone that slept through that minute clears it on waking.
const clipWrites = await sessionEval(`(async () => {
  const real = navigator.clipboard.writeText;
  const writes = [];
  navigator.clipboard.writeText = (v) => { writes.push(v); return Promise.resolve(); };
  const hasFocus = document.hasFocus;
  document.hasFocus = () => true;
  try {
    document.querySelector('.copy-link-btn').click();
    await new Promise((r) => setTimeout(r, 300));
    const now = Date.now;
    Date.now = () => now() + 61_000;
    try { window.dispatchEvent(new Event('focus')); } finally { Date.now = now; }
    return writes;
  } finally {
    navigator.clipboard.writeText = real;
    document.hasFocus = hasFocus;
  }
})()`);
ok(clipWrites.length === 2 && clipWrites[0].includes('#join=') && clipWrites[1] === '',
  `a copied link is cleared on coming back after its minute is up (${JSON.stringify(clipWrites.map((w) => w.slice(0, 12)))})`);

// The QR generator is fetched on demand rather than on every page load, so the
// image arrives after the row. Nothing tested it before the change, which means
// a green suite said nothing about whether it still worked — and a QR that
// silently stopped rendering is a verification path quietly gone.
const qrDecoded = await waitFor(async () => sessionEval(`
  (async () => {
    const img = document.querySelector('.share-link .share-qr');
    if (!img || !img.src.startsWith('data:image/')) return false;
    // Decode it: a data URL that is present but not an image would still pass a
    // src check, and the QR is only useful if a camera can read it.
    // Decoded through an Image, not fetch: connect-src is 'self', so the page
    // may not fetch a data: URL — img-src is what allows one, and it is the
    // path the browser actually uses to show this.
    const probe = new Image();
    probe.src = img.src;
    await probe.decode();
    return probe.naturalWidth > 0 && probe.naturalWidth === probe.naturalHeight
      ? probe.naturalWidth : false;
  })()
`), { timeout: 15000 });
ok(qrDecoded, `the share QR is generated on demand and decodes (${qrDecoded}px square)`);

/* ── Saved contacts (opt-in identity) ──
 * The privacy claim is that nothing long-lived exists unless the user asks for
 * it. That is only true if the default really does store nothing, so check the
 * database rather than the checkbox.
 */
const identityStored = async () => sessionEval(`
  (async () => {
    const dbs = await indexedDB.databases();
    if (!dbs.some((d) => d.name === 'deaddrop-identity')) return false;
    return await new Promise((resolve) => {
      const req = indexedDB.open('deaddrop-identity');
      req.onsuccess = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains('identity')) { db.close(); resolve(false); return; }
        const get = db.transaction('identity', 'readonly').objectStore('identity').get('self');
        get.onsuccess = () => { const v = get.result; db.close(); resolve(!!(v && v.privateKey)); };
        get.onerror = () => { db.close(); resolve(false); };
      };
      req.onerror = () => resolve(false);
    });
  })()
`);

await sessionEval(`document.querySelector('#settings-btn').click(); true`);
await sleep(200);

ok(await identityStored() === false,
  'no identity key exists until the user opts in');
ok(await sessionEval(`document.querySelector('#contacts-toggle').checked`) === false,
  'saved contacts default to off');

await sessionEval(`
  const box = document.querySelector('#contacts-toggle');
  box.checked = true;
  box.dispatchEvent(new Event('change'));
  true
`);
await waitFor(async () => identityStored(), { timeout: 8000 });
ok(await identityStored() === true, 'opting in mints and stores an identity key');

// The private half must not be readable, or storing it buys nothing.
const extractable = await sessionEval(`
  (async () => {
    const req = indexedDB.open('deaddrop-identity');
    const db = await new Promise((r) => { req.onsuccess = () => r(req.result); });
    const get = db.transaction('identity', 'readonly').objectStore('identity').get('self');
    const rec = await new Promise((r) => { get.onsuccess = () => r(get.result); });
    db.close();
    return rec.privateKey.extractable;
  })()
`);
ok(extractable === false, 'the stored private key is non-extractable');

/* ── Mobile layout ──
 * "Looks fine on a phone" is not checkable by reading CSS, but the failures that
 * actually ruin a mobile UI are measurable: a page that scrolls sideways, a
 * control too small to hit, or text pushed outside the viewport. Assert those at
 * real device sizes instead of trusting the media queries.
 */
const VIEWPORTS = [
  { name: 'iPhone SE', width: 375, height: 667 },
  { name: 'small Android', width: 360, height: 740 },
  { name: 'iPhone Pro Max', width: 430, height: 932 },
];

/** Measure the current document at one emulated phone viewport. */
async function measureLayout(pageLabel) {
  return sessionEval(`
    (() => {
      const doc = document.documentElement;
      const overflowsPage = doc.scrollWidth > doc.clientWidth + 1;

      const spillers = [];
      for (const el of document.querySelectorAll('body *')) {
        if (!el.getClientRects().length) continue;
        const r = el.getBoundingClientRect();
        if (r.width === 0) continue;
        if (r.right > doc.clientWidth + 1 || r.left < -1) {
          spillers.push((el.id ? '#' + el.id : el.className || el.tagName).toString().slice(0, 60));
        }
      }

      // A checkbox or radio is measured through the label that wraps it, since
      // that label is what a finger actually lands on.
      //
      // A link written inside a sentence is exempt: prose links take their size
      // from the text around them, and forcing 44px there would wreck the
      // paragraph. A link that stands alone in its own block is a control and
      // has to be tappable like any other.
      const standsAlone = (a) => {
        const parent = a.parentElement;
        if (!parent) return true;
        const own = (a.textContent || '').trim();
        const around = (parent.textContent || '').trim();
        return around.length - own.length < 3;
      };

      const small = [];
      for (const el of document.querySelectorAll('button, a, input, select, [role="button"]')) {
        if (!el.getClientRects().length) continue;
        if (el.tagName === 'A' && !standsAlone(el)) continue;
        const isToggle = el.tagName === 'INPUT'
          && (el.type === 'checkbox' || el.type === 'radio');
        const target = isToggle ? (el.closest('label') || el) : el;
        const r = target.getBoundingClientRect();
        // Half a pixel of tolerance: a box with min-height:44px can measure
        // 43.99 after layout rounding, which is a reporting artefact rather
        // than a target anyone would miss.
        if (r.height > 0 && r.height < 43.5) {
          const name = target.id ? '#' + target.id : (target.className || target.tagName);
          small.push((name + '@' + Math.round(r.height) + 'px').toString().slice(0, 60));
        }
      }

      // A text-entry control under 16px makes iOS zoom the whole page on focus.
      const zoomy = [];
      for (const el of document.querySelectorAll(
          'textarea, select, input:not([type=checkbox]):not([type=radio]):not([type=range])')) {
        if (!el.getClientRects().length) continue;
        const size = parseFloat(getComputedStyle(el).fontSize);
        if (size < 16) zoomy.push(((el.id || el.tagName) + '@' + size + 'px').toString());
      }

      // Controls painted over one another. Nothing spills off the screen when
      // a header's icons slide left over the room code, so the overflow check
      // above never saw it; at 430px the call button sat on the code.
      const overlaps = [];
      const controls = [...document.querySelectorAll('button, input, select, a[href], code, .status')]
        .filter((el) => el.getClientRects().length && el.getBoundingClientRect().width > 0);
      for (let i = 0; i < controls.length; i++) {
        for (let j = i + 1; j < controls.length; j++) {
          const a = controls[i], b = controls[j];
          if (a.contains(b) || b.contains(a)) continue;
          const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
          if (ra.left < rb.right - 1 && rb.left < ra.right - 1
              && ra.top < rb.bottom - 1 && rb.top < ra.bottom - 1) {
            const name = (el) => (el.id ? '#' + el.id : el.className || el.tagName).toString().slice(0, 40);
            overlaps.push(name(a) + ' × ' + name(b));
          }
        }
      }

      return {
        overlaps: [...new Set(overlaps)].slice(0, 6),
        coarse: window.matchMedia('(pointer: coarse)').matches,
        overflowsPage,
        spillers: [...new Set(spillers)].slice(0, 6),
        small: [...new Set(small)].slice(0, 6),
        zoomy: [...new Set(zoomy)].slice(0, 6),
      };
    })()
  `);
}

/** Put the browser into a phone-shaped, touch-driven emulation. */
async function emulatePhone(vp) {
  await sessionSend('Emulation.setDeviceMetricsOverride', {
    width: vp.width, height: vp.height, deviceScaleFactor: 2, mobile: true,
  });
  // Device metrics alone do not change the pointer media feature, so a
  // (pointer: coarse) rule would never apply and the run would be measuring a
  // desktop layout at phone width. Emulate the input type as well.
  await sessionSend('Emulation.setEmulatedMedia', {
    features: [
      { name: 'pointer', value: 'coarse' },
      { name: 'any-pointer', value: 'coarse' },
      { name: 'hover', value: 'none' },
      { name: 'any-hover', value: 'none' },
    ],
  });
  await sessionSend('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 });
  await sleep(400); // let the media queries settle
}

function assertLayout(report, label) {
  ok(report.coarse, `${label}: the run really is emulating a touch pointer`);
  ok(!report.overflowsPage && report.spillers.length === 0,
    `${label}: nothing overflows the viewport${
      report.spillers.length ? ' — ' + report.spillers.join(', ') : ''}`);
  ok(report.small.length === 0,
    `${label}: every control is at least 44px tall${
      report.small.length ? ' — ' + report.small.join(', ') : ''}`);
  ok(report.overlaps.length === 0,
    `${label}: no two controls are painted over each other${
      report.overlaps.length ? ' — ' + report.overlaps.join(', ') : ''}`);
  ok(report.zoomy.length === 0,
    `${label}: no input smaller than 16px (iOS zoom)${
      report.zoomy.length ? ' — ' + report.zoomy.join(', ') : ''}`);
}

for (const vp of VIEWPORTS) {
  await emulatePhone(vp);

  if (SHOT_DIR) {
    mkdirSync(SHOT_DIR, { recursive: true });
    for (const [view, prep] of [
      ['chat', `true`],
      ['landing', `document.querySelector('#chat-wrap').classList.add('hidden');
                  document.querySelector('#landing').classList.remove('hidden'); true`],
      ['auth', `document.querySelector('#landing').classList.add('hidden');
                document.querySelector('#auth').classList.remove('hidden'); true`],
    ]) {
      await sessionEval(prep);
      await sleep(150);
      const shot = await sessionSend('Page.captureScreenshot', { format: 'png' });
      const slug = vp.name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
      writeFileSync(join(SHOT_DIR, `${slug}-${vp.width}-${view}.png`),
        Buffer.from(shot.data, 'base64'));
    }
    await sessionEval(`
      document.querySelector('#auth').classList.add('hidden');
      document.querySelector('#landing').classList.add('hidden');
      document.querySelector('#chat-wrap').classList.remove('hidden'); true
    `);
    await sleep(150);
  }

  assertLayout(await measureLayout(vp.name), `${vp.name} (${vp.width}px)`);

  // Romanian runs longer than English almost everywhere, and every check
  // above was only ever made in English. Measure each screen in both.
  for (const lang of ['en', 'ro']) {
    await sessionEval(`document.documentElement.lang === ${JSON.stringify(lang)}
      || (document.querySelector('#lang-btn').click(), true)`);
    for (const [view, show] of [['chat', '#chat-wrap'], ['landing', '#landing'], ['sign-in', '#auth']]) {
      await sessionEval(`
        for (const id of ['#chat-wrap', '#landing', '#auth']) {
          document.querySelector(id).classList.toggle('hidden', id !== ${JSON.stringify(show)});
        }
        true`);
      await sleep(150);
      assertLayout(await measureLayout(view), `${view} in ${lang} on ${vp.name} (${vp.width}px)`);
    }
    // The longest text in the app is behind the account panel and the privacy
    // options, both closed above. Open them, with a result line showing.
    await sessionEval(`(() => {
      document.querySelector('#auth').classList.add('hidden');
      document.querySelector('#landing').classList.remove('hidden');
      document.querySelector('#account-panel').classList.remove('hidden');
      document.querySelector('.prefs').open = true;
      const msg = document.querySelector('#duress-msg');
      msg.textContent = 'Parola-capcană trebuie să fie diferită de parola reală';
      msg.classList.remove('hidden');
      return true;
    })()`);
    await sleep(150);
    assertLayout(await measureLayout('landing, panels open'),
      `landing with every panel open in ${lang} on ${vp.name} (${vp.width}px)`);
    await sessionEval(`
      document.querySelector('#account-panel').classList.add('hidden');
      document.querySelector('#duress-msg').classList.add('hidden');
      document.querySelector('.prefs').open = false; true`);
  }
  await sessionEval(`
    document.documentElement.lang === 'en' || document.querySelector('#lang-btn').click();
    document.querySelector('#auth').classList.add('hidden');
    document.querySelector('#landing').classList.add('hidden');
    document.querySelector('#chat-wrap').classList.remove('hidden'); true`);

  // The status pill is how anyone knows whether the room is safe to type in.
  // The room code may ellipsize; "Waiting for peer…" must not.
  const status = await sessionEval(`(() => {
    const el = document.querySelector('#status');
    return { text: el.textContent, cut: el.scrollWidth > el.clientWidth + 1 };
  })()`);
  ok(!status.cut, `${vp.name}: the status reads in full ("${status.text}")`);

  // The same phone with its keyboard up: as short as a phone on its side but
  // still narrow. The landscape single-row composer once applied here and
  // left the message field zero pixels wide.
  await sessionSend('Emulation.setDeviceMetricsOverride', {
    width: vp.width, height: 360, deviceScaleFactor: 2, mobile: true,
  });
  await sleep(300);
  const field = await sessionEval(`Math.round(document.querySelector('#msg-input').getBoundingClientRect().width)`);
  ok(field >= 120, `${vp.name} with the keyboard up: the message field is usable (${field}px wide)`);
  await emulatePhone(vp);

  // With the account panel open the landing column is taller than any phone.
  // Centred without `safe`, its top overflowed upward where no scroll reaches,
  // and the logout and account buttons were simply gone.
  const reachable = await sessionEval(`(async () => {
    const landing = document.querySelector('#landing');
    const chat = document.querySelector('#chat-wrap');
    const panel = document.querySelector('#account-panel');
    const prefs = document.querySelector('.prefs');
    chat.classList.add('hidden');
    landing.classList.remove('hidden');
    panel.classList.remove('hidden');
    prefs.open = true;
    landing.scrollTop = 0;
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    const top = document.querySelector('#logout-btn').getBoundingClientRect().top;
    panel.classList.add('hidden');
    prefs.open = false;
    landing.classList.add('hidden');
    chat.classList.remove('hidden');
    return top;
  })()`);
  ok(reachable >= 0, `${vp.name}: the account buttons stay on screen with every panel open (top ${Math.round(reachable)}px)`);
}

// The standalone pages carry the security explanations and the integrity
// checker. They are reached from the app but never exercised by any other
// suite, so nothing would notice them breaking on a phone.
for (const page of ['about.html', 'about.ro.html', 'verify.html', 'verify.ro.html']) {
  for (const vp of VIEWPORTS) {
    await emulatePhone(vp);
    await sessionSend('Page.navigate', { url: `${BASE}/${page}` });
    await waitFor(async () => sessionEval('document.readyState === "complete"').catch(() => false),
      { timeout: 10000 });
    await sleep(250);

    assertLayout(await measureLayout(page), `${page} on ${vp.name} (${vp.width}px)`);

    if (SHOT_DIR && vp.width === 375) {
      const shot = await sessionSend('Page.captureScreenshot', { format: 'png' });
      writeFileSync(join(SHOT_DIR, `${page.replace('.html', '')}-375.png`),
        Buffer.from(shot.data, 'base64'));
    }
  }
}

// The Romanian verifier runs the same check and reports it in Romanian.
await sessionSend('Page.navigate', { url: `${BASE}/verify.ro.html` });
const roVerdict = await waitFor(async () => {
  const text = await sessionEval(`document.querySelector('#summary').textContent`).catch(() => '');
  return /^✓ Toate cele \d+ răspunsuri/.test(text) ? text : false;
}, { timeout: 30000 });
ok(roVerdict, `the Romanian verifier checks every file and says so in Romanian (${roVerdict || 'no verdict'})`);

await sessionSend('Emulation.clearDeviceMetricsOverride');
await sessionSend('Emulation.setEmulatedMedia', { features: [] });
await sessionSend('Emulation.setTouchEmulationEnabled', { enabled: false });

// Assert the clean-run properties BEFORE deliberately tripping Trusted Types
// below, so the probe's own violation cannot be mistaken for one from the app.
ok(pageErrors.length === 0, `no uncaught page exceptions${pageErrors.length ? ': ' + pageErrors[0] : ''}`);

const distinctViolations = [...new Set(cspViolations)];
ok(distinctViolations.length === 0,
  `no CSP, Permissions-Policy or Trusted Types violations${
    distinctViolations.length ? ':\n      - ' + distinctViolations.join('\n      - ') : ''}`);

const realConsoleErrors = consoleErrors.filter((e) => !/favicon|ERR_/.test(e));
ok(realConsoleErrors.length === 0,
  `no console errors${realConsoleErrors.length ? ': ' + realConsoleErrors[0] : ''}`);

// Last, because it is expected to violate: the whole point is that the browser
// refuses this. If the policy ever stops being enforced, the sink silently comes
// back and every render path becomes an injection candidate again.
const ttEnforced = await sessionEval(`
  (() => {
    if (!window.trustedTypes) return 'unsupported';
    try {
      document.createElement('div').innerHTML = '<b>x</b>';
      return 'allowed';
    } catch (e) {
      return e && /Trusted|TrustedHTML/i.test(String(e)) ? 'blocked' : 'other:' + e;
    }
  })()
`);
ok(ttEnforced === 'blocked', `innerHTML is refused by Trusted Types (${ttEnforced})`);

browser.close();
cleanup();

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
