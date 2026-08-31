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
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITE = process.env.DD_INVITE || '';
const USER = 'zz_ui_' + Math.floor(Math.random() * 1e6);
const PASS = 'browser-smoke-passphrase-77';

const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
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

async function waitFor(fn, { timeout = 8000, interval = 100 } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    if (await fn()) return true;
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
  'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });

let wsURL = null;
chrome.stderr.on('data', (chunk) => {
  const m = /ws:\/\/[^\s]+/.exec(chunk.toString());
  if (m && !wsURL) wsURL = m[0];
});

const cleanup = () => {
  try { chrome.kill('SIGKILL'); } catch { /* already gone */ }
  try { rmSync(profile, { recursive: true, force: true }); } catch { /* best effort */ }
};
process.on('exit', cleanup);

if (!await waitFor(() => wsURL !== null, { timeout: 15000 })) {
  console.error('browser smoke: Chromium did not report a debugging endpoint');
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

await sessionSend('Page.navigate', { url: BASE + '/' });
const booted = await waitFor(async () => sessionEval(
  `!!document.querySelector('#auth') && !document.querySelector('#auth').classList.contains('hidden')`,
).catch(() => false));
ok(booted, 'the app boots and shows the auth page');

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

// Enter a room so the chat view, header and verify bar all render.
await sessionEval(`document.querySelector('#create-room').click(); true`);
const inRoom = await waitFor(async () => sessionEval(
  `!document.querySelector('#chat-wrap').classList.contains('hidden')
   && document.querySelector('#room-code').textContent.length === 24`,
).catch(() => false), { timeout: 15000 });
ok(inRoom, 'a room is created and the chat view renders');

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

// Trusted Types must actually be enforced: innerHTML has to throw.
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

ok(pageErrors.length === 0, `no uncaught page exceptions${pageErrors.length ? ': ' + pageErrors[0] : ''}`);
const distinctViolations = [...new Set(cspViolations)];
ok(distinctViolations.length === 0,
  `no CSP, Permissions-Policy or Trusted Types violations${
    distinctViolations.length ? ':\n      - ' + distinctViolations.join('\n      - ') : ''}`);

const realConsoleErrors = consoleErrors.filter((e) => !/favicon|ERR_/.test(e));
ok(realConsoleErrors.length === 0,
  `no console errors${realConsoleErrors.length ? ': ' + realConsoleErrors[0] : ''}`);

browser.close();
cleanup();

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
