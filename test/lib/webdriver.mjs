/**
 * A minimal W3C WebDriver client, so the suites can reach Safari.
 *
 * Chrome is driven over the DevTools Protocol and Firefox over BiDi, and neither
 * reaches WebKit. Safari speaks only classic WebDriver — plain HTTP against a
 * `safaridriver` process — which is also what chromedriver speaks, so this
 * client can be built and checked against Chrome on a machine with no Safari on
 * it and then pointed at the real thing.
 *
 * WebKit is the engine this project has never run on. Firefox was the second,
 * and running it for the first time turned up a handshake race that broke every
 * Gecko session outright: the app could not establish a single connection, and
 * nothing would have said so until a user tried. There is no reason to assume
 * the third engine is kinder.
 *
 * Only the handful of commands the suites need. This is a test driver, not a
 * client library.
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { sleep, waitFor } from './browser.mjs';

export class WebDriver {
  constructor(base, sessionId) {
    this.base = base;
    this.sessionId = sessionId;
    this.errors = [];
    this.logs = [];
  }

  static async connect(base, capabilities, { attempts = 60 } = {}) {
    for (let i = 0; i < attempts; i++) {
      try {
        const res = await fetch(`${base}/session`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ capabilities }),
        });
        const body = await res.json();
        const id = body?.value?.sessionId ?? body?.sessionId;
        if (id) return new WebDriver(base, id);
        if (i === attempts - 1) throw new Error(JSON.stringify(body).slice(0, 300));
      } catch (err) {
        if (i === attempts - 1) throw err;
      }
      await sleep(500);
    }
    throw new Error('no WebDriver session');
  }

  async send(method, path, body) {
    const res = await fetch(`${this.base}/session/${this.sessionId}${path}`, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    // WebDriver reports failures inside a 4xx/5xx body rather than by shape, so
    // an error has to be recognised rather than assumed absent.
    if (!res.ok || json?.value?.error) {
      const v = json?.value ?? {};
      throw new Error(`${v.error || res.status}: ${(v.message || '').split('\n')[0]}`);
    }
    return json.value;
  }

  /**
   * Evaluate in the page. The script body is wrapped so `await` works and the
   * result is returned through the synchronous execute endpoint, which is what
   * every driver implements consistently.
   */
  async eval(expression) {
    return this.send('POST', '/execute/async', {
      script: `const done = arguments[arguments.length - 1];
        (async () => (${expression}))().then((v) => done({ ok: v }), (e) => done({ err: String(e) }));`,
      args: [],
    }).then((r) => {
      if (r && typeof r === 'object' && 'err' in r) throw new Error(`${this.name || 'driver'}: ${r.err}`);
      return r?.ok;
    });
  }

  async goto(url, { expectApp = true } = {}) {
    await this.send('POST', '/url', { url });
    const ready = await waitFor(() => this.eval(`document.readyState === 'complete'`), { timeout: 45000 });
    if (!ready) throw new Error(`${this.name}: ${url} never finished loading`);
    if (expectApp) {
      const booted = await waitFor(() => this.eval(
        `document.querySelector('#call-btn')?.style.display === 'none'`), { timeout: 45000 });
      if (!booted) throw new Error(`${this.name}: the app never started on ${url}`);
    }
    await this.eval(`(() => { window.confirm = () => true; window.prompt = () => 'peer'; return true; })()`);
  }

  quit() {
    return this.send('DELETE', '').catch(() => {});
  }
}

/** The shared vocabulary the pair suites use, over whichever driver. */
export class DriverPeer {
  constructor(driver, name) {
    this.driver = driver;
    this.name = name;
    driver.name = name;
  }

  eval(expression) { return this.driver.eval(expression); }
  goto(url, opts) { return this.driver.goto(url, opts); }
  get errors() { return this.driver.errors; }

  async register(username, invite, password, { attempts = 3 } = {}) {
    for (let attempt = 1; attempt <= attempts; attempt++) {
      await this.eval(`(() => {
        document.querySelector('#auth-user').value = ${JSON.stringify(username)};
        document.querySelector('#auth-pass').value = ${JSON.stringify(password)};
        document.querySelector('#auth-invite').value = ${JSON.stringify(invite)};
        document.querySelector('#register-btn').click();
        return true;
      })()`);
      const outcome = await waitFor(async () => {
        if (await this.eval(`!document.querySelector('#landing').classList.contains('hidden')`)) return 'landed';
        return this.eval(`(() => {
          const el = document.querySelector('#auth-error');
          return el && !el.classList.contains('hidden') && el.textContent
            ? 'error: ' + el.textContent : false;
        })()`);
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

  inChat() { return this.eval(`!document.querySelector('#chat-wrap').classList.contains('hidden')`); }

  sas() {
    return this.eval(`(() => {
      const el = document.querySelector('.verify-sas');
      return el && el.textContent ? el.textContent : null;
    })()`);
  }

  verified() { return this.eval(`document.querySelector('#verify-bar').classList.contains('verified')`); }

  clickVerify() {
    return this.eval(`(() => {
      const btns = [...document.querySelectorAll('.verify-btn')].filter((b) => !b.disabled);
      if (!btns.length) return false;
      btns[0].click();
      return true;
    })()`);
  }

  transcript() {
    return this.eval(`[...document.querySelectorAll('.msg-text')].map((n) => n.textContent).join('\\n')`);
  }

  send(text) {
    return this.eval(`(() => {
      document.querySelector('#msg-input').value = ${JSON.stringify(text)};
      document.querySelector('#send-btn').click();
      return true;
    })()`);
  }
}

/**
 * Start a driver process and connect. `spec` names the binary, its arguments,
 * the port it listens on, and the capabilities to request.
 */
export async function launchDriver(spec) {
  if (!spec.binary || !existsSync(spec.binary)) {
    if (process.env[spec.requireEnv] === '1') {
      console.error(`${spec.label}: ${spec.binary || 'driver'} not found and ${spec.requireEnv}=1`);
      process.exit(1);
    }
    console.log(`${spec.label}: no ${spec.label} driver available — skipping`);
    process.exit(0);
  }
  const proc = spawn(spec.binary, spec.args, { stdio: ['ignore', 'ignore', 'pipe'], detached: true });
  let stderrTail = '';
  proc.stderr.on('data', (c) => { stderrTail = (stderrTail + c.toString()).slice(-2000); });

  const cleanup = () => {
    try { process.kill(-proc.pid, 'SIGKILL'); } catch { /* gone */ }
    try { proc.kill('SIGKILL'); } catch { /* gone */ }
  };
  process.on('exit', cleanup);

  try {
    const driver = await WebDriver.connect(`http://127.0.0.1:${spec.port}`, spec.capabilities);
    return { driver, cleanup };
  } catch (err) {
    cleanup();
    console.error(`${spec.label}: could not start a session — ${err.message}\n${stderrTail}`);
    process.exit(1);
  }
}
