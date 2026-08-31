/**
 * Shared browser-driving helpers for the multi-peer suites.
 *
 * Launches headless Chrome, speaks the DevTools Protocol over Node's built-in
 * WebSocket (no npm packages), and gives each peer its own browser context so
 * cookies and IndexedDB are not shared between simulated people.
 */

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const CHROME_CANDIDATES = [
  process.env.CHROME_PATH,
  `${process.env.HOME}/.cache/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell`,
  `${process.env.HOME}/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome`,
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
].filter(Boolean);

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function waitFor(fn, { timeout = 20000, interval = 150 } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    let value;
    try { value = await fn(); } catch { value = false; }
    if (value) return value;
    if (Date.now() > deadline) return false;
    await sleep(interval);
  }
}

export function findChrome() {
  return CHROME_CANDIDATES.find((p) => existsSync(p)) || null;
}

/**
 * Launch Chrome and connect. Returns { cdp, cleanup } or exits with a clear
 * message — a browser suite that cannot start a browser has nothing to say.
 */
export async function launchBrowser(prefix) {
  const chromePath = findChrome();
  if (!chromePath) {
    if (process.env.DD_REQUIRE_BROWSER === '1') {
      console.error(`${prefix}: no Chromium found and DD_REQUIRE_BROWSER=1`);
      process.exit(1);
    }
    console.log(`${prefix}: no Chromium available — skipping`);
    process.exit(0);
  }

  const profile = mkdtempSync(join(tmpdir(), `dd-${prefix}-`));
  const chrome = spawn(chromePath, [
    '--headless=new',
    '--remote-debugging-port=0',
    `--user-data-dir=${profile}`,
    '--no-first-run', '--no-default-browser-check',
    '--disable-gpu', '--no-sandbox',
    // A CI container has no session bus and a small /dev/shm; without these,
    // startup stalls on dbus or the renderer dies once shared memory runs out.
    '--disable-dev-shm-usage',
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

  // Chrome writes its port and websocket path here. Scraping the same thing out
  // of stderr races against chunk boundaries and startup timing.
  const endpoint = await waitFor(() => {
    const file = join(profile, 'DevToolsActivePort');
    if (!existsSync(file)) return false;
    const [port, path] = readFileSync(file, 'utf8').split('\n');
    return port && path ? `ws://127.0.0.1:${port.trim()}${path.trim()}` : false;
  }, { timeout: 60000, interval: 100 });

  if (!endpoint) {
    console.error(`${prefix}: Chromium did not report a debugging endpoint`);
    if (stderrTail) console.error(stderrTail);
    process.exit(1);
  }
  return { cdp: await CDP.connect(endpoint), cleanup };
}

/* ── CDP ── */

export class CDP {
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
export class Peer {
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

  async register(username, invite, password) {
    await this.eval(`
      document.querySelector('#auth-user').value = ${JSON.stringify(username)};
      document.querySelector('#auth-pass').value = ${JSON.stringify(password)};
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

  /**
   * Send a file the way the UI does: put a real File on the hidden input and
   * fire change. Reaching past it into the transfer manager would skip the
   * size-binding checks that run on the way in.
   */
  async sendFile(name, contents, type = 'text/plain') {
    return this.eval(`
      (() => {
        const input = document.querySelector('#file-input');
        const dt = new DataTransfer();
        dt.items.add(new File([${JSON.stringify(contents)}], ${JSON.stringify(name)},
          { type: ${JSON.stringify(type)} }));
        input.files = dt.files;
        input.dispatchEvent(new Event('change', { bubbles: true }));
        return true;
      })()
    `);
  }

  /** Filenames, sizes and download hrefs of received file messages. */
  receivedFiles() {
    return this.eval(`
      [...document.querySelectorAll('.file-msg')].map((el) => ({
        name: el.querySelector('.file-name')?.textContent || null,
        size: el.querySelector('.file-size')?.textContent || null,
        href: el.querySelector('.file-download')?.getAttribute('href') || null,
        hasImage: !!el.querySelector('.file-preview-img'),
      }))
    `);
  }

  /**
   * Decode a received image preview.
   *
   * The blob cannot be read back with fetch(): connect-src is 'self' and does
   * not admit blob:, which is correct — the app only ever uses these URLs as a
   * src or href. Letting the browser decode the image proves the bytes survived
   * chunking, encryption and reassembly just as well, without loosening the
   * policy for a test.
   */
  decodedImageSize() {
    return this.eval(`
      (async () => {
        const img = document.querySelector('#messages .file-preview-img');
        if (!img) return null;
        if (!img.complete) {
          await new Promise((r) => { img.onload = r; img.onerror = r; });
        }
        return img.naturalWidth + 'x' + img.naturalHeight;
      })()
    `);
  }

  /** Draw a PNG of known dimensions and hand it to the attach input. */
  async sendGeneratedImage(width, height, name = 'proof.png') {
    return this.eval(`
      (async () => {
        const canvas = document.createElement('canvas');
        canvas.width = ${width}; canvas.height = ${height};
        const ctx = canvas.getContext('2d');
        // Noise, so the encoded bytes are not a trivially compressible constant.
        const img = ctx.createImageData(${width}, ${height});
        for (let i = 0; i < img.data.length; i += 4) {
          img.data[i] = (i * 7) % 251; img.data[i + 1] = (i * 13) % 241;
          img.data[i + 2] = (i * 29) % 239; img.data[i + 3] = 255;
        }
        ctx.putImageData(img, 0, 0);
        const blob = await new Promise((r) => canvas.toBlob(r, 'image/png'));
        const input = document.querySelector('#file-input');
        const dt = new DataTransfer();
        dt.items.add(new File([blob], ${JSON.stringify(name)}, { type: 'image/png' }));
        input.files = dt.files;
        input.dispatchEvent(new Event('change', { bubbles: true }));
        return blob.size;
      })()
    `);
  }

  transcript() {
    return this.eval(`
      [...document.querySelectorAll('.msg-text')].map((n) => n.textContent).join('\\n')
    `);
  }
}

