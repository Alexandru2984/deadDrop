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
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
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

for (const vp of VIEWPORTS) {
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

  const report = await sessionEval(`
    (() => {
      const doc = document.documentElement;
      const overflowsPage = doc.scrollWidth > doc.clientWidth + 1;

      // Elements poking past the right edge are the usual cause.
      const spillers = [];
      for (const el of document.querySelectorAll('body *')) {
        if (!el.getClientRects().length) continue;
        const r = el.getBoundingClientRect();
        if (r.width === 0) continue;
        if (r.right > doc.clientWidth + 1 || r.left < -1) {
          spillers.push((el.id ? '#' + el.id : el.className || el.tagName).toString().slice(0, 60));
        }
      }

      // Anything tappable needs a real target. 44px is the long-standing floor.
      // A checkbox or radio is measured through the label that wraps it, since
      // that label is what a finger actually lands on.
      const small = [];
      const tappable = document.querySelectorAll(
        'button, a, input, select, [role="button"]');
      for (const el of tappable) {
        if (!el.getClientRects().length) continue;
        const isToggle = el.tagName === 'INPUT'
          && (el.type === 'checkbox' || el.type === 'radio');
        const target = isToggle ? (el.closest('label') || el) : el;
        const r = target.getBoundingClientRect();
        if (r.height > 0 && r.height < 44) {
          const name = target.id ? '#' + target.id : (target.className || target.tagName);
          small.push((name + '@' + Math.round(r.height) + 'px').toString().slice(0, 60));
        }
      }

      // A text-entry control under 16px makes iOS zoom the whole page on focus.
      // Checkboxes and radios do not, so they are not part of this rule.
      const zoomy = [];
      const typeable = document.querySelectorAll(
        'textarea, select, input:not([type=checkbox]):not([type=radio]):not([type=range])');
      for (const el of typeable) {
        if (!el.getClientRects().length) continue;
        const size = parseFloat(getComputedStyle(el).fontSize);
        if (size < 16) zoomy.push(((el.id || el.tagName) + '@' + size + 'px').toString());
      }

      return {
        coarse: window.matchMedia('(pointer: coarse)').matches,
        overflowsPage,
        spillers: [...new Set(spillers)].slice(0, 6),
        small: [...new Set(small)].slice(0, 6),
        zoomy: [...new Set(zoomy)].slice(0, 6),
      };
    })()
  `);

  const label = `${vp.name} (${vp.width}px)`;
  ok(report.coarse, `${label}: the run really is emulating a touch pointer`);
  ok(!report.overflowsPage && report.spillers.length === 0,
    `${label}: nothing overflows the viewport${
      report.spillers.length ? ' — ' + report.spillers.join(', ') : ''}`);
  ok(report.small.length === 0,
    `${label}: every control is at least 44px tall${
      report.small.length ? ' — ' + report.small.join(', ') : ''}`);
  ok(report.zoomy.length === 0,
    `${label}: no input smaller than 16px (iOS zoom)${
      report.zoomy.length ? ' — ' + report.zoomy.join(', ') : ''}`);
}

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
