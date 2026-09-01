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
export async function launchBrowser(prefix, { extraArgs = [] } = {}) {
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
    // Calls need a camera and a microphone. The fake device produces a
    // deterministic tone and a moving pattern, and the fake UI auto-grants the
    // permission prompt, so a headless run can place a real WebRTC call.
    '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream',
    '--autoplay-policy=no-user-gesture-required',
    ...extraArgs,
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

  /**
   * A renderer wedged in a WebRTC operation never answers, and a test that
   * waits forever tells CI nothing. Fail the call instead, with the method name
   * that stalled.
   */
  send(method, params = {}, sessionId, timeout = 60000) {
    const id = ++this.id;
    this.ws.send(JSON.stringify(sessionId ? { id, method, params, sessionId } : { id, method, params }));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP ${method} timed out after ${timeout}ms`));
      }, timeout);
      const done = (fn) => (value) => { clearTimeout(timer); fn(value); };
      this.pending.set(id, { resolve: done(resolve), reject: done(reject) });
    });
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
    this.logs = [];
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
      // A script the browser refuses to run — a failed integrity check, a CSP
      // block — throws nothing. It is reported here and nowhere else, and
      // without it a page whose app never started looks exactly like a page
      // whose app started and did nothing.
      if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
        peer.logs.push(msg.params.entry.text);
      }
    });
    await cdp.send('Runtime.enable', {}, sessionId);
    await cdp.send('Page.enable', {}, sessionId);
    await cdp.send('Log.enable', {}, sessionId);
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

  /**
   * Navigate, and do not come back until the app is actually running.
   *
   * Waiting on readyState alone is not enough, and failing quietly is worse. The
   * markup is static, so every element a test reaches for exists as soon as the
   * HTML is parsed — a form can be filled in and a button clicked on a page
   * whose module has not executed, and nothing happens. The run then fails much
   * later, on an assertion far from the cause, with the server showing no
   * request at all.
   *
   * `#call-btn` is hidden from the constructor through the CSSOM rather than an
   * inline attribute (the CSP allows no inline styles), so an inline display of
   * 'none' cannot come from the markup: it means the constructor ran. And since
   * that constructor is synchronous, nothing outside can observe a half-built
   * app — seeing the flag means the event handlers are bound too.
   */
  async goto(url, { expectApp = true } = {}) {
    await this.cdp.send('Page.navigate', { url }, this.sessionId);
    const ready = await waitFor(() => this.eval('document.readyState === "complete"'),
      { timeout: 45000 });
    if (!ready) throw new Error(`${this.name}: ${url} never finished loading — ${await this.why()}`);
    if (expectApp) {
      const booted = await waitFor(() => this.eval(
        `document.querySelector('#call-btn')?.style.display === 'none'`), { timeout: 45000 });
      if (!booted) throw new Error(`${this.name}: the app never started on ${url} — ${await this.why()}`);
    }
    // The app asks for confirmation before trusting a safety code and prompts
    // for a contact name. Answer both so the flow can run unattended.
    await this.eval(`window.confirm = () => true; window.prompt = () => 'peer'; true`);
  }

  /**
   * Register, waiting out the auth rate limit if it is in the way.
   *
   * The suites are ordinary clients of a public API that allows ten auth
   * requests a minute per address, and registering an account costs several —
   * a room, a TURN config and a session check on top of the registration
   * itself. Run a few suites from one address and the later ones are refused,
   * exactly as an attacker would be. That is the limiter working, not a bug to
   * engineer around: the tests pace themselves instead.
   *
   * Tokens come back in whole-interval steps, so a partial wait buys nothing.
   */
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
      // A registration that silently fails takes every later assertion down with
      // it, and the run then reports twenty red lines that all mean one thing.
      // Say what the page actually showed instead.
      console.error(`  ! ${this.name} never reached the landing page: ${await this.why()}`);
      return false;
    }
    return false;
  }

  /** Whatever the page can tell us about why it is not where it should be. */
  async why() {
    const page = await this.eval(`
      (() => ({
        url: location.href,
        ready: document.readyState,
        authError: document.querySelector('#auth-error')?.textContent || '',
        visible: [...document.querySelectorAll('section, main, div')]
          .filter((el) => el.id && !el.classList.contains('hidden'))
          .map((el) => el.id).slice(0, 6),
      }))()
    `).catch((err) => ({ evalFailed: String(err) }));
    return JSON.stringify({
      ...page,
      errors: this.errors.slice(0, 3),
      browserLogs: this.logs.slice(0, 5),
    });
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

  /* ── Calls ── */

  /** True once the call button is offered, i.e. the media path is bound. */
  callable() {
    return this.eval(`
      (() => {
        const btn = document.querySelector('#call-btn');
        return !!btn && btn.style.display !== 'none';
      })()
    `);
  }

  startCall() {
    return this.eval(`document.querySelector('#call-btn').click(); true`);
  }

  ringing() {
    return this.eval(
      `!document.querySelector('#incoming-call').classList.contains('hidden')`);
  }

  acceptCall() {
    return this.eval(`document.querySelector('#accept-call').click(); true`);
  }

  rejectCall() {
    return this.eval(`document.querySelector('#reject-call').click(); true`);
  }

  endCall() {
    return this.eval(`document.querySelector('#end-call').click(); true`);
  }

  /**
   * What the media elements actually hold. `remote` is the only honest proof a
   * call connected: it is set from `ontrack`, which cannot fire unless DTLS-SRTP
   * completed with the peer.
   */
  mediaState() {
    return this.eval(`
      (() => {
        const state = (v) => {
          const s = v && v.srcObject;
          if (!s) return null;
          return {
            audio: s.getAudioTracks().length,
            video: s.getVideoTracks().length,
            live: s.getTracks().filter((t) => t.readyState === 'live').length,
          };
        };
        return {
          local: state(document.querySelector('#local-video')),
          remote: state(document.querySelector('#remote-video')),
          overlay: !document.querySelector('#call-overlay').classList.contains('hidden'),
          status: document.querySelector('#call-status-bar').textContent || '',
        };
      })()
    `);
  }

  /**
   * Turn this peer into a hostile client.
   *
   * A peer you compared a safety code with is still just software on someone
   * else's machine, and nothing stops them from running a modified build. The
   * only honest way to test what the *other* side does when a peer stops
   * following the protocol is to actually have one that does not.
   *
   * So rewrite the bundle on its way into this browser: drop the integrity
   * attributes the page pins its own modules with (an attacker patching their
   * own client would), and hand the app instance to the test so it can send any
   * frame it likes over the real, properly encrypted channel. The victim peer
   * is untouched and sees a perfectly ordinary session.
   *
   * Must run before the page loads.
   */
  async becomeHostile() {
    await this.cdp.send('Fetch.enable', {
      patterns: [
        { urlPattern: '*/', requestStage: 'Response' },
        { urlPattern: '*/index.html', requestStage: 'Response' },
        { urlPattern: '*/js/app.js', requestStage: 'Response' },
      ],
    }, this.sessionId);

    this.cdp.on(async (msg) => {
      if (msg.sessionId !== this.sessionId || msg.method !== 'Fetch.requestPaused') return;
      const { requestId, request, responseHeaders } = msg.params;
      try {
        const { body, base64Encoded } = await this.cdp.send(
          'Fetch.getResponseBody', { requestId }, this.sessionId);
        let text = base64Encoded ? Buffer.from(body, 'base64').toString('utf8') : body;
        if (request.url.endsWith('/js/app.js')) {
          text = text.replace('new DeadDrop();', 'window.__ddApp = new DeadDrop();');
        } else {
          text = text.replace(/\s+integrity="[^"]*"/g, '');
        }
        await this.cdp.send('Fetch.fulfillRequest', {
          requestId,
          responseCode: 200,
          responseHeaders: (responseHeaders || []).filter(
            (h) => !/^content-length$/i.test(h.name)),
          body: Buffer.from(text, 'utf8').toString('base64'),
        }, this.sessionId);
      } catch {
        try { await this.cdp.send('Fetch.continueRequest', { requestId }, this.sessionId); }
        catch { /* the request is already gone */ }
      }
    });
  }

  /**
   * Send a raw protocol frame to the peer, sealed and sent exactly as the real
   * client would — only at a moment the real client never would. Requires
   * becomeHostile().
   */
  sendRaw(frame) {
    return this.eval(`
      (async () => {
        const app = window.__ddApp;
        const session = [...app.peers.values()][0];
        if (!session) return false;
        await app._sendBestEffort(session.conn, ${JSON.stringify(frame)});
        return true;
      })()
    `);
  }

  /**
   * Record every RTCPeerConnection the page creates, so a test can read real
   * WebRTC stats. Must run before the page loads. This instruments the browser
   * from the outside — the app exposes nothing, and should not start to.
   */
  instrumentPeerConnections() {
    return this.cdp.send('Page.addScriptToEvaluateOnNewDocument', {
      source: `
        window.__ddPeerConnections = [];
        const Native = window.RTCPeerConnection;
        window.RTCPeerConnection = function (...args) {
          const pc = new Native(...args);
          window.__ddPeerConnections.push(pc);
          return pc;
        };
        window.RTCPeerConnection.prototype = Native.prototype;
      `,
    }, this.sessionId);
  }

  /** Bytes the peer connection has actually decoded from the remote end. */
  inboundMedia() {
    return this.eval(`
      (async () => {
        const pcs = window.__ddPeerConnections || [];
        let bytes = 0;
        for (const pc of pcs) {
          const report = await pc.getStats();
          report.forEach((s) => {
            if (s.type === 'inbound-rtp' && typeof s.bytesReceived === 'number') {
              bytes += s.bytesReceived;
            }
          });
        }
        return bytes;
      })()
    `);
  }
}

