/**
 * Two-peer end-to-end test: two isolated browser contexts, one real WebRTC
 * session between them.
 *
 *   DD_URL=… DD_INVITE=… DD_INVITE2=… node test/browser.pair.mjs
 *
 * Everything else in the suite exercises one side at a time. The Go tests never
 * run the client, the crypto self-test drives both handshake halves in one
 * process with no transport, and the single-page smoke test never has a peer to
 * talk to. So nothing covered the path that actually matters: two browsers, the
 * signaling server between them, a data channel, a safety code both humans
 * compare, and — since protocol v5 — a saved contact recognised on a later
 * session without comparing anything again.
 *
 * Each peer gets its own browser context so they have separate cookie jars and
 * separate IndexedDB; sharing a profile would put both accounts on one session.
 */

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITES = [process.env.DD_INVITE || '', process.env.DD_INVITE2 || ''];
const PASS = 'pair-test-passphrase-9182';

const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
  `${process.env.HOME}/.cache/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell`,
  `${process.env.HOME}/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome`,
  '/usr/bin/chromium',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
].filter(Boolean);

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(fn, { timeout = 20000, interval = 150 } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    let value;
    try { value = await fn(); } catch { value = false; }
    if (value) return value;
    if (Date.now() > deadline) return false;
    await sleep(interval);
  }
}

/* ── CDP ── */

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

  send(method, params = {}, sessionId) {
    const id = ++this.id;
    this.ws.send(JSON.stringify(sessionId ? { id, method, params, sessionId } : { id, method, params }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }

  on(fn) { this.listeners.push(fn); }
  close() { this.ws.close(); }
}

/** One peer: its own browser context, page and evaluation helper. */
class Peer {
  constructor(cdp, name) {
    this.cdp = cdp;
    this.name = name;
    this.errors = [];
  }

  static async open(cdp, name) {
    const peer = new Peer(cdp, name);
    const { browserContextId } = await cdp.send('Target.createBrowserContext',
      { disposeOnDetach: false });
    peer.contextId = browserContextId;
    const { targetId } = await cdp.send('Target.createTarget',
      { url: 'about:blank', browserContextId });
    peer.targetId = targetId;
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    peer.sessionId = sessionId;

    cdp.on((msg) => {
      if (msg.sessionId !== sessionId) return;
      if (msg.method === 'Runtime.exceptionThrown') {
        peer.errors.push(msg.params.exceptionDetails.exception?.description
          || msg.params.exceptionDetails.text || 'exception');
      }
    });
    await cdp.send('Runtime.enable', {}, sessionId);
    await cdp.send('Page.enable', {}, sessionId);
    return peer;
  }

  async eval(expression) {
    const res = await this.cdp.send('Runtime.evaluate', {
      expression, awaitPromise: true, returnByValue: true,
    }, this.sessionId);
    if (res.exceptionDetails) {
      throw new Error(`${this.name}: ${res.exceptionDetails.exception?.description
        || res.exceptionDetails.text}`);
    }
    return res.result.value;
  }

  async goto(url) {
    await this.cdp.send('Page.navigate', { url }, this.sessionId);
    await waitFor(() => this.eval('document.readyState === "complete"'));
    // The app asks for confirmation before trusting a safety code and prompts
    // for a contact name. Answer both so the flow can run unattended.
    await this.eval(`window.confirm = () => true; window.prompt = () => 'peer'; true`);
  }

  async register(username, invite) {
    await this.eval(`
      document.querySelector('#auth-user').value = ${JSON.stringify(username)};
      document.querySelector('#auth-pass').value = ${JSON.stringify(PASS)};
      document.querySelector('#auth-invite').value = ${JSON.stringify(invite)};
      document.querySelector('#register-btn').click(); true
    `);
    return waitFor(() => this.eval(
      `!document.querySelector('#landing').classList.contains('hidden')`), { timeout: 25000 });
  }

  async enableSavedContacts() {
    await this.eval(`
      document.querySelector('#settings-btn').click();
      const box = document.querySelector('#contacts-toggle');
      box.checked = true;
      box.dispatchEvent(new Event('change'));
      true
    `);
    await waitFor(() => this.eval(`
      (async () => {
        const dbs = await indexedDB.databases();
        return dbs.some((d) => d.name === 'deaddrop-identity');
      })()
    `));
    await this.eval(`document.querySelector('#settings-btn').click(); true`);
  }

  inChat() {
    return this.eval(`!document.querySelector('#chat-wrap').classList.contains('hidden')`);
  }

  sas() {
    return this.eval(`
      (() => {
        const el = document.querySelector('.verify-sas');
        return el && el.textContent ? el.textContent : null;
      })()
    `);
  }

  verified() {
    return this.eval(`document.querySelector('#verify-bar').classList.contains('verified')`);
  }

  clickVerify() {
    return this.eval(`
      (() => {
        const btns = [...document.querySelectorAll('.verify-btn')].filter((b) => !b.disabled);
        if (!btns.length) return false;
        btns[0].click();
        return true;
      })()
    `);
  }

  transcript() {
    return this.eval(`
      [...document.querySelectorAll('.msg-text')].map((n) => n.textContent).join('\\n')
    `);
  }
}

/* ── Run ── */

const chromePath = CHROME_CANDIDATES.find((p) => existsSync(p));
if (!chromePath) {
  if (process.env.DD_REQUIRE_BROWSER === '1') {
    console.error('pair test: no Chromium found and DD_REQUIRE_BROWSER=1');
    process.exit(1);
  }
  console.log('pair test: no Chromium available — skipping');
  process.exit(0);
}
if (!INVITES[0] || !INVITES[1]) {
  console.error('pair test: set DD_INVITE and DD_INVITE2 (one account each)');
  process.exit(1);
}

const suffix = Math.floor(Math.random() * 1e6);
const USERS = [`zz_pa_${suffix}`, `zz_pb_${suffix}`];
console.log(`Two-peer run against ${BASE} as ${USERS[0]} + ${USERS[1]}`);

const profile = mkdtempSync(join(tmpdir(), 'dd-pair-'));
const chrome = spawn(chromePath, [
  '--headless=new',
  '--remote-debugging-port=0',
  `--user-data-dir=${profile}`,
  '--no-first-run', '--no-default-browser-check',
  '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
  '--disable-extensions', '--disable-component-update', '--disable-default-apps',
  '--disable-background-networking', '--disable-sync', '--mute-audio',
  'about:blank',
], {
  stdio: ['ignore', 'ignore', 'pipe'],
  env: { ...process.env, DBUS_SESSION_BUS_ADDRESS: '/dev/null' },
});

let stderrTail = '';
chrome.stderr.on('data', (c) => { stderrTail = (stderrTail + c.toString()).slice(-2000); });

const cleanup = () => {
  try { chrome.kill('SIGKILL'); } catch { /* gone */ }
  try { rmSync(profile, { recursive: true, force: true }); } catch { /* best effort */ }
};
process.on('exit', cleanup);

const endpoint = await waitFor(() => {
  const file = join(profile, 'DevToolsActivePort');
  if (!existsSync(file)) return false;
  const [port, path] = readFileSync(file, 'utf8').split('\n');
  return port && path ? `ws://127.0.0.1:${port.trim()}${path.trim()}` : false;
}, { timeout: 60000, interval: 100 });

if (!endpoint) {
  console.error('pair test: Chromium did not report a debugging endpoint');
  if (stderrTail) console.error(stderrTail);
  process.exit(1);
}

const cdp = await CDP.connect(endpoint);

// ── First session: strangers must compare a safety code ──
const alice = await Peer.open(cdp, 'alice');
const bob = await Peer.open(cdp, 'bob');

await alice.goto(BASE + '/');
await bob.goto(BASE + '/');
ok(await alice.register(USERS[0], INVITES[0]), 'peer A registers');
ok(await bob.register(USERS[1], INVITES[1]), 'peer B registers');

// Both opt into saved contacts before connecting, so the identity is present in
// the very first handshake and can be pinned when they verify.
await alice.enableSavedContacts();
await bob.enableSavedContacts();

await alice.eval(`document.querySelector('#create-room').click(); true`);
const room = await waitFor(async () => {
  const code = await alice.eval(`document.querySelector('#room-code').textContent`);
  return code && code.length === 24 ? code : false;
});
ok(room, 'peer A creates a room');

await bob.eval(`
  document.querySelector('#room-code-input').value = ${JSON.stringify(room)};
  document.querySelector('#join-room').click(); true
`);
ok(await waitFor(() => bob.inChat()), 'peer B joins the room');

const sasA = await waitFor(() => alice.sas(), { timeout: 30000 });
const sasB = await waitFor(() => bob.sas(), { timeout: 30000 });
ok(sasA && sasB, 'both peers complete the hybrid handshake and show a safety code');
ok(sasA === sasB, `both peers derive the same safety code (${sasA} / ${sasB})`);

ok(await alice.verified() === false && await bob.verified() === false,
  'traffic stays locked before anyone confirms');

ok(await alice.clickVerify(), 'peer A confirms the safety code');
ok(await bob.clickVerify(), 'peer B confirms the safety code');
ok(await waitFor(() => alice.verified()) && await waitFor(() => bob.verified()),
  'mutual confirmation unlocks both sides');

const secret = 'ciphertext round trip ' + suffix;
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(secret)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await bob.transcript()).includes(secret)),
  'a message sent by A is decrypted by B');

// ── Second session: a saved contact must not need a new comparison ──
// Fresh pages in the same browser contexts, so cookies and the pinned identity
// survive exactly as they would for a returning user.
await alice.goto(BASE + '/');
await bob.goto(BASE + '/');
await waitFor(() => alice.eval(`!document.querySelector('#landing').classList.contains('hidden')`));
await waitFor(() => bob.eval(`!document.querySelector('#landing').classList.contains('hidden')`));

await alice.eval(`document.querySelector('#create-room').click(); true`);
const room2 = await waitFor(async () => {
  const code = await alice.eval(`document.querySelector('#room-code').textContent`);
  return code && code.length === 24 ? code : false;
});
await bob.eval(`
  document.querySelector('#room-code-input').value = ${JSON.stringify(room2)};
  document.querySelector('#join-room').click(); true
`);
ok(await waitFor(() => bob.inChat()), 'the saved contacts reconnect in a new room');

const autoA = await waitFor(() => alice.verified(), { timeout: 30000 });
const autoB = await waitFor(() => bob.verified(), { timeout: 30000 });
ok(autoA && autoB,
  'a recognised contact unlocks without anyone comparing a code again');

const secret2 = 'second session ' + suffix;
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(secret2)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await bob.transcript()).includes(secret2)),
  'the reconnected pair exchanges messages');

ok(alice.errors.length === 0 && bob.errors.length === 0,
  `no uncaught exceptions in either peer${
    [...alice.errors, ...bob.errors].length ? ': ' + [...alice.errors, ...bob.errors][0] : ''}`);

cdp.close();
cleanup();
console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
