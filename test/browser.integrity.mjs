/**
 * A module rewritten on the way to the browser must not run.
 *
 * SRI on <script src="js/app.js"> only ever covered the entry point. Everything
 * it imports — crypto.js, handshake.js, the ML-KEM code — was trusted on the
 * strength of having arrived, so a CDN, a TLS-terminating proxy or anything else
 * in the path could replace the encryption while leaving the page's own hashes
 * intact. The import map now pins a hash for every module.
 *
 * This plays the part of that proxy: it lets the page through untouched and
 * rewrites crypto.js in flight, then checks the app refuses to start. A second
 * page, untouched, must boot normally — otherwise "refused" would only prove
 * the app was broken.
 *
 * The public verifier gets the same treatment for the one rewrite it lets
 * through: Cloudflare's managed block in front of robots.txt, and nothing else.
 *
 *   DD_URL=http://127.0.0.1:8100 node test/browser.integrity.mjs
 */

import { launchBrowser, Peer, waitFor } from './lib/browser.mjs';

const URL_BASE = (process.env.DD_URL || 'http://127.0.0.1:8100').replace(/\/$/, '');

let failures = 0;
const ok = (cond, msg) => {
  if (cond) console.log('  ✓', msg);
  else { console.error('  ✗', msg); failures++; }
};

const { cdp, cleanup } = await launchBrowser('integrity');
try {
  console.log(`Module integrity against ${URL_BASE}`);

  const honest = await Peer.open(cdp, 'honest');
  await honest.goto(`${URL_BASE}/`);
  ok(await honest.eval(`!!document.querySelector('script[type=importmap]')`),
    'the page ships an import map');
  const refused = honest.logs.filter((line) => /integrity|Content Security Policy|import ?map/i.test(line));
  ok(refused.length === 0, `an untouched page boots with no refused script or map (${refused.join(' | ') || 'none'})`);

  const victim = await Peer.open(cdp, 'victim');
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*/js/crypto.js*', requestStage: 'Response' }] },
    victim.sessionId);
  let rewritten = 0;
  cdp.on(async (msg) => {
    if (msg.sessionId !== victim.sessionId || msg.method !== 'Fetch.requestPaused') return;
    const { requestId } = msg.params;
    const { body, base64Encoded } = await cdp.send('Fetch.getResponseBody', { requestId }, victim.sessionId);
    const source = base64Encoded ? Buffer.from(body, 'base64').toString('utf8') : body;
    // A one-line backdoor: exactly the kind of edit a hostile edge would make.
    const tampered = `${source}\nglobalThis.__exfiltrate = true;\n`;
    rewritten++;
    await cdp.send('Fetch.fulfillRequest', {
      requestId,
      responseCode: 200,
      responseHeaders: [{ name: 'Content-Type', value: 'text/javascript' }],
      body: Buffer.from(tampered).toString('base64'),
    }, victim.sessionId);
  });

  await victim.goto(`${URL_BASE}/`, { expectApp: false });
  await waitFor(async () => rewritten > 0, { timeout: 15000 });
  ok(rewritten > 0, 'the proxy rewrote crypto.js in flight');
  const booted = await waitFor(() => victim.eval(
    `document.querySelector('#call-btn')?.style.display === 'none'`), { timeout: 6000 });
  ok(!booted, 'the app does not start with a rewritten crypto module');
  ok(await victim.eval(`globalThis.__exfiltrate !== true`), 'the injected code never ran');
  ok(victim.logs.some((line) => /integrity/i.test(line)),
    `the browser names the integrity failure (${victim.logs.find((l) => /integrity/i.test(l)) || 'nothing logged'})`);

  // The verifier: Cloudflare's managed robots.txt in front of ours passes and
  // says so; the same block with our part changed is still a mismatch.
  const MANAGED = '# As a condition of accessing this website, you agree to abide by the following\n' +
    '# content signals:\n\n# BEGIN Cloudflare Managed content\n\n\nUser-agent: *\n' +
    'Content-Signal: search=yes,ai-train=no\nAllow: /\n\nUser-agent: GPTBot\nDisallow: /\n\n' +
    '# END Cloudflare Managed Content\n\n';
  const verifyWith = async (name, rewrite) => {
    const page = await Peer.open(cdp, name);
    await cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*/robots.txt*', requestStage: 'Response' }] },
      page.sessionId);
    cdp.on(async (msg) => {
      if (msg.sessionId !== page.sessionId || msg.method !== 'Fetch.requestPaused') return;
      const { requestId } = msg.params;
      const { body, base64Encoded } = await cdp.send('Fetch.getResponseBody', { requestId }, page.sessionId);
      const source = base64Encoded ? Buffer.from(body, 'base64').toString('utf8') : body;
      await cdp.send('Fetch.fulfillRequest', {
        requestId,
        responseCode: 200,
        responseHeaders: [{ name: 'Content-Type', value: 'text/plain; charset=utf-8' }],
        body: Buffer.from(rewrite(source)).toString('base64'),
      }, page.sessionId);
    });
    await page.goto(`${URL_BASE}/verify.html`, { expectApp: false });
    await waitFor(() => page.eval(`/verify-(ok|bad)/.test(document.getElementById('summary').className)`),
      { timeout: 20000 });
    return page.eval(`(() => {
      const row = [...document.querySelectorAll('.verify-row')]
        .find((r) => r.querySelector('.verify-path').textContent === 'robots.txt');
      return {
        summary: document.getElementById('summary').className,
        row: row?.className,
        detail: row?.querySelector('.verify-detail')?.textContent || '',
      };
    })()`);
  };

  const managed = await verifyWith('verify-cf', (ours) => MANAGED + ours);
  ok(/verify-ok/.test(managed.row) && /Cloudflare/.test(managed.detail),
    `the verifier accepts Cloudflare's block in front of robots.txt and names it (${managed.detail})`);
  ok(/verify-ok/.test(managed.summary), 'and the whole check still passes');

  const altered = await verifyWith('verify-cf-altered', (ours) => MANAGED + ours + 'Allow: /api/\n');
  ok(/verify-bad/.test(altered.row) && /verify-bad/.test(altered.summary),
    'the same block with our part changed is still a mismatch');

  const unmarked = await verifyWith('verify-unmarked', (ours) => 'User-agent: *\nAllow: /\n\n' + ours);
  ok(/verify-bad/.test(unmarked.row), 'an unmarked prefix is a mismatch');
} finally {
  cleanup();
}

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
