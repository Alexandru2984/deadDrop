/**
 * A minimal WebDriver BiDi driver, so the suites can run on Gecko.
 *
 * Everything else in this directory drives Chrome over the DevTools Protocol,
 * which means every claim the tests make about this app is a claim about Blink.
 * The client is the whole security product here, and the engines disagree about
 * exactly the things it depends on — WebCrypto surfaces, WebRTC negotiation,
 * IndexedDB, and Trusted Types, which Gecko does not implement at all.
 *
 * Firefox dropped CDP, so this speaks BiDi instead. Only the handful of commands
 * the suites need are implemented; this is a test driver, not a client library.
 */

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sleep, waitFor } from './browser.mjs';

export const FIREFOX_CANDIDATES = [
  process.env.FIREFOX_PATH,
  '/usr/bin/firefox',
  '/usr/bin/firefox-esr',
  '/opt/firefox/firefox',
].filter(Boolean);

export function findFirefox() {
  return FIREFOX_CANDIDATES.find((p) => existsSync(p)) || null;
}

class BiDi {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.listeners = [];
    ws.addEventListener('message', (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id !== undefined && this.pending.has(msg.id)) {
        const entry = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.type === 'error') {
          entry.reject(new Error(`${msg.error}: ${msg.message}`));
        } else {
          entry.resolve(msg.result);
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
      ws.addEventListener('error', () => reject(new Error('BiDi socket failed')), { once: true });
    });
    return new BiDi(ws);
  }

  send(method, params = {}, timeout = 60000) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`BiDi ${method} timed out after ${timeout}ms`));
      }, timeout);
      const done = (fn) => (value) => { clearTimeout(timer); fn(value); };
      this.pending.set(id, { resolve: done(resolve), reject: done(reject) });
    });
  }

  on(fn) { this.listeners.push(fn); }
  close() { this.ws.close(); }
}

/** One tab, in its own user context so cookies and storage are its own. */
export class FirefoxPeer {
  constructor(bidi, name, context) {
    this.bidi = bidi;
    this.name = name;
    this.context = context;
    this.errors = [];
    this.logs = [];
  }

  static async open(bidi, name) {
    // A user context is Gecko's container: the isolation Chrome gets from a
    // browser context, which is what makes two peers in one browser realistic.
    const { userContext } = await bidi.send('browser.createUserContext', {});
    const { context } = await bidi.send('browsingContext.create',
      { type: 'tab', userContext });
    const peer = new FirefoxPeer(bidi, name, context);

    bidi.on((msg) => {
      if (msg.method === 'log.entryAdded' && msg.params?.source?.context === context) {
        const entry = msg.params;
        if (entry.level === 'error') peer.logs.push(entry.text || '');
        if (entry.type === 'javascript') peer.errors.push(entry.text || '');
      }
    });
    return peer;
  }

  /**
   * Evaluate in the page and return the value.
   *
   * BiDi returns structured values rather than JSON, so anything beyond a
   * primitive comes back as a typed tree. The suites only ever ask for
   * primitives and small arrays of them, which is all deserialize handles.
   */
  async eval(expression) {
    const result = await this.bidi.send('script.evaluate', {
      expression,
      target: { context: this.context },
      awaitPromise: true,
      resultOwnership: 'none',
    });
    if (result.type === 'exception') {
      throw new Error(`${this.name}: ${result.exceptionDetails?.text || 'exception'}`);
    }
    return deserialize(result.result);
  }

  async goto(url, { expectApp = true } = {}) {
    await this.bidi.send('browsingContext.navigate',
      { context: this.context, url, wait: 'complete' });
    if (expectApp) {
      const booted = await waitFor(() => this.eval(
        `document.querySelector('#call-btn')?.style.display === 'none'`), { timeout: 45000 });
      if (!booted) throw new Error(`${this.name}: the app never started on ${url}`);
    }
    await this.eval(`window.confirm = () => true; window.prompt = () => 'peer'; true`);
  }

  async register(username, invite, password, { attempts = 3 } = {}) {
    for (let attempt = 1; attempt <= attempts; attempt++) {
      await this.eval(`
        document.querySelector('#auth-user').value = ${JSON.stringify(username)};
        document.querySelector('#auth-pass').value = ${JSON.stringify(password)};
        document.querySelector('#auth-invite').value = ${JSON.stringify(invite)};
        document.querySelector('#register-btn').click(); true
      `);
      const outcome = await waitFor(async () => {
        if (await this.eval(`!document.querySelector('#landing').classList.contains('hidden')`)) {
          return 'landed';
        }
        return await this.eval(`
          (() => {
            const el = document.querySelector('#auth-error');
            return el && !el.classList.contains('hidden') && el.textContent
              ? 'error: ' + el.textContent : false;
          })()
        `);
      }, { timeout: 25000 });
      if (outcome === 'landed') return true;
      if (String(outcome).includes('too many requests') && attempt < attempts) {
        console.log(`  … ${this.name} is rate limited; waiting for the bucket to refill`);
        await sleep(65000);
        continue;
      }
      console.error(`  ! ${this.name} did not reach the landing page: ${outcome}`);
      return false;
    }
    return false;
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

/** BiDi's structured values back to plain JS, for the shapes the suites use. */
function deserialize(value) {
  if (!value || typeof value !== 'object') return value;
  switch (value.type) {
    case 'undefined': return undefined;
    case 'null': return null;
    case 'string': case 'boolean': return value.value;
    case 'number':
      return typeof value.value === 'string' ? Number(value.value) : value.value;
    case 'array': return (value.value || []).map(deserialize);
    case 'object':
      return Object.fromEntries((value.value || []).map(([k, v]) => [deserialize(k), deserialize(v)]));
    default: return value.value ?? null;
  }
}

export async function launchFirefox(prefix) {
  const binary = findFirefox();
  if (!binary) {
    if (process.env.DD_REQUIRE_FIREFOX === '1') {
      console.error(`${prefix}: no Firefox found and DD_REQUIRE_FIREFOX=1`);
      process.exit(1);
    }
    console.log(`${prefix}: no Firefox available — skipping`);
    process.exit(0);
  }

  const profile = mkdtempSync(join(tmpdir(), `dd-ff-${prefix}-`));
  const port = 9400 + Math.floor(Math.random() * 500);
  const firefox = spawn(binary, [
    '--headless', '--no-remote',
    '--profile', profile,
    `--remote-debugging-port=${port}`,
    'about:blank',
  ], {
    stdio: ['ignore', 'ignore', 'pipe'],
    // Same reasoning as the Chrome launcher: kill the tree, not the launcher.
    detached: true,
    env: {
      ...process.env,
      MOZ_DISABLE_CONTENT_SANDBOX: '1',
      // Fake devices, so a call can be placed without hardware.
      MOZ_FAKE_MEDIA_STREAMS: '1',
    },
  });

  let stderrTail = '';
  firefox.stderr.on('data', (c) => { stderrTail = (stderrTail + c.toString()).slice(-2000); });

  const cleanup = () => {
    try { process.kill(-firefox.pid, 'SIGKILL'); } catch { /* gone */ }
    try { firefox.kill('SIGKILL'); } catch { /* gone */ }
    try { rmSync(profile, { recursive: true, force: true }); } catch { /* best effort */ }
  };
  process.on('exit', cleanup);

  const ready = await waitFor(async () => {
    try {
      const probe = await BiDi.connect(`ws://127.0.0.1:${port}/session`);
      return probe;
    } catch { return false; }
  }, { timeout: 60000, interval: 250 });
  if (!ready) {
    cleanup();
    console.error(`${prefix}: Firefox did not expose BiDi.\n${stderrTail}`);
    process.exit(1);
  }

  await ready.send('session.new', { capabilities: {} });
  await ready.send('session.subscribe', { events: ['log.entryAdded'] });
  return { bidi: ready, cleanup };
}
