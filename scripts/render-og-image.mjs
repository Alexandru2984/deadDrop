#!/usr/bin/env node
/**
 * Render web/og.png, the preview card link unfurlers show.
 *
 *   node scripts/render-og-image.mjs
 *
 * Rendered here and committed rather than pulled from an image service: the card
 * is served from this origin like everything else, so previewing a link to Dead
 * Drop involves no third party. Re-run it and diff to see what changed.
 *
 * Driven over the DevTools Protocol rather than Chrome's --screenshot flag,
 * which does not reliably exit under the new headless mode. The harness the test
 * suites already use is known to work.
 */
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchBrowser, waitFor, sleep } from '../test/lib/browser.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const card = `<!doctype html><meta charset="utf-8"><style>
  html,body{margin:0;width:1200px;height:630px;overflow:hidden}
  body{background:#0a0a0f;color:#e8e8ee;display:flex;flex-direction:column;
       align-items:center;justify-content:center;gap:16px;
       font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
  .skull{width:132px;height:132px}
  h1{margin:0;font-size:80px;letter-spacing:.16em;font-weight:700}
  p{margin:0;font-size:32px;color:#9aa0b5;letter-spacing:.04em}
  .rule{width:220px;height:3px;background:#c8102e;border-radius:2px}
  .foot{font-size:24px;color:#6b7186;letter-spacing:.05em}
</style>
<!-- Drawn, not typed: a baked image that depends on an emoji font being
     installed renders as an empty box on machines that lack one, and the first
     run of this produced exactly that. -->
<svg class="skull" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M50 8C29 8 14 23 14 43c0 11 4 19 11 25 3 3 4 6 4 10v4a5 5 0 0 0 5 5h32a5 5 0 0 0 5-5v-4c0-4 1-7 4-10 7-6 11-14 11-25C86 23 71 8 50 8Z" fill="#e8e8ee"/>
  <ellipse cx="35" cy="45" rx="10" ry="12" fill="#0a0a0f"/>
  <ellipse cx="65" cy="45" rx="10" ry="12" fill="#0a0a0f"/>
  <path d="M50 58l-6 11h12l-6-11Z" fill="#0a0a0f"/>
  <rect x="38" y="80" width="5" height="10" rx="2" fill="#0a0a0f"/>
  <rect x="47.5" y="80" width="5" height="10" rx="2" fill="#0a0a0f"/>
  <rect x="57" y="80" width="5" height="10" rx="2" fill="#0a0a0f"/>
</svg>
<h1>DEAD DROP</h1><div class="rule"></div>
<p>Verified end-to-end encryption, peer to peer</p>
<div class="foot">post-quantum handshake &middot; nothing stored &middot; invite only</div>`;

const work = mkdtempSync(join(tmpdir(), 'dd-og-'));
const html = join(work, 'card.html');
writeFileSync(html, card);

const { cdp, cleanup } = await launchBrowser('og');
try {
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Runtime.enable', {}, sessionId);
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Emulation.setDeviceMetricsOverride',
    { width: 1200, height: 630, deviceScaleFactor: 1, mobile: false }, sessionId);
  await cdp.send('Page.navigate', { url: `file://${html}` }, sessionId);

  const ready = await waitFor(async () => {
    const res = await cdp.send('Runtime.evaluate',
      { expression: 'document.readyState === "complete"', returnByValue: true }, sessionId);
    return res.result.value;
  }, { timeout: 20000 });
  if (!ready) throw new Error('the card never finished rendering');
  // Emoji and font fallback settle a frame or two after load.
  await sleep(600);

  const shot = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
  const png = Buffer.from(shot.data, 'base64');
  writeFileSync(join(ROOT, 'web/og.png'), png);
  console.log(`wrote web/og.png — ${(png.length / 1024).toFixed(1)} KB`);
} finally {
  cdp.close();
  cleanup();
  rmSync(work, { recursive: true, force: true });
}
