#!/usr/bin/env node
/**
 * Render the app icons: web/icon.svg and the PNGs a home screen needs.
 *
 *   node scripts/render-icons.mjs
 *
 * The skull is drawn, not typed. The icon used to be the 💀 emoji inside an
 * SVG, which renders only where an emoji font is installed and as an empty box
 * everywhere else — the same failure render-og-image.mjs ran into. iOS also
 * ignores an SVG apple-touch-icon and falls back to a screenshot of the page,
 * so a PNG is required there. Rendered here and committed, like og.png: the
 * icons come from this origin, made by nothing but this script.
 */
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchBrowser, waitFor, sleep } from '../test/lib/browser.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const SKULL = `
  <path d="M50 8C29 8 14 23 14 43c0 11 4 19 11 25 3 3 4 6 4 10v4a5 5 0 0 0 5 5h32a5 5 0 0 0 5-5v-4c0-4 1-7 4-10 7-6 11-14 11-25C86 23 71 8 50 8Z" fill="#e8e8ee"/>
  <ellipse cx="35" cy="45" rx="10" ry="12" fill="#0a0a0f"/>
  <ellipse cx="65" cy="45" rx="10" ry="12" fill="#0a0a0f"/>
  <path d="M50 58l-6 11h12l-6-11Z" fill="#0a0a0f"/>
  <rect x="38" y="80" width="5" height="10" rx="2" fill="#0a0a0f"/>
  <rect x="47.5" y="80" width="5" height="10" rx="2" fill="#0a0a0f"/>
  <rect x="57" y="80" width="5" height="10" rx="2" fill="#0a0a0f"/>`;

/**
 * `rounded`: a tile with its own corners (browsers, Android "any").
 * `scale`: the skull's share of the tile. A maskable icon keeps it inside the
 * central 80% circle, since the launcher may crop to any shape it likes.
 */
function svg({ rounded, scale }) {
  const size = 512 * scale;
  const offset = (512 - size) / 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <rect width="512" height="512"${rounded ? ' rx="96"' : ''} fill="#0a0a0f"/>
  ${rounded ? '<rect x="16" y="16" width="480" height="480" rx="84" fill="none" stroke="#00e87b" stroke-opacity="0.35" stroke-width="6"/>' : ''}
  <svg x="${offset}" y="${offset}" width="${size}" height="${size}" viewBox="0 0 100 100">${SKULL}
  </svg>
</svg>
`;
}

const variants = [
  { file: 'icon-192.png', px: 192, rounded: true, scale: 0.62 },
  { file: 'icon-512.png', px: 512, rounded: true, scale: 0.62 },
  // iOS draws its own rounded mask over an opaque square.
  { file: 'apple-touch-icon.png', px: 180, rounded: false, scale: 0.62 },
  { file: 'icon-maskable-512.png', px: 512, rounded: false, scale: 0.5 },
];

writeFileSync(join(ROOT, 'web/icon.svg'), svg({ rounded: true, scale: 0.62 }));
console.log('wrote web/icon.svg');

const work = mkdtempSync(join(tmpdir(), 'dd-icons-'));
const { cdp, cleanup } = await launchBrowser('icons');
try {
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Runtime.enable', {}, sessionId);
  await cdp.send('Page.enable', {}, sessionId);
  // Transparent outside the tile, so rounded corners stay rounded.
  await cdp.send('Emulation.setDefaultBackgroundColorOverride',
    { color: { r: 0, g: 0, b: 0, a: 0 } }, sessionId);

  for (const v of variants) {
    const html = join(work, `${v.file}.html`);
    writeFileSync(html, `<!doctype html><meta charset="utf-8"><style>
      html,body{margin:0;width:${v.px}px;height:${v.px}px;overflow:hidden;background:transparent}
      svg{display:block;width:${v.px}px;height:${v.px}px}</style>${svg(v)}`);
    await cdp.send('Emulation.setDeviceMetricsOverride',
      { width: v.px, height: v.px, deviceScaleFactor: 1, mobile: false }, sessionId);
    await cdp.send('Page.navigate', { url: `file://${html}` }, sessionId);
    const ready = await waitFor(async () => {
      const res = await cdp.send('Runtime.evaluate',
        { expression: 'document.readyState === "complete"', returnByValue: true }, sessionId);
      return res.result.value;
    }, { timeout: 20000 });
    if (!ready) throw new Error(`${v.file} never finished rendering`);
    await sleep(200);
    const shot = await cdp.send('Page.captureScreenshot', { format: 'png' }, sessionId);
    const png = Buffer.from(shot.data, 'base64');
    writeFileSync(join(ROOT, 'web', v.file), png);
    console.log(`wrote web/${v.file} — ${(png.length / 1024).toFixed(1)} KB`);
  }
} finally {
  cdp.close();
  cleanup();
  rmSync(work, { recursive: true, force: true });
}
