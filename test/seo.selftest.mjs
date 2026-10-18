/**
 * The public surface: discoverable, and still nobody else's business.
 *
 *   node test/seo.selftest.mjs
 *
 * Being findable and being private are not in tension here — the service is not
 * a secret, its domain is public, and someone deciding whether to trust it
 * should be able to read what it protects before registering. What would be a
 * problem is the way sites usually become findable: an analytics tag, a font
 * from a CDN, a search-console verification script. Each is a third party
 * watching everyone who opens the page, on a site whose entire claim is that
 * nobody is.
 *
 * So this checks both halves. The metadata is present and correct, and every
 * byte the page pulls still comes from this origin.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const WEB = new URL('../web/', import.meta.url).pathname;
const read = (f) => readFileSync(join(WEB, f), 'utf8');
const pages = readdirSync(WEB).filter((f) => f.endsWith('.html'));

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

console.log('nothing on the public surface comes from anywhere else');

// Any absolute URL that is loaded — script, style, image, font, frame. Link
// metadata (canonical, og:url, og:image) legitimately names our own host, and is
// checked separately below.
const OURS = 'https://dead.micutu.com';
for (const page of pages) {
  const html = read(page);
  const loaded = [...html.matchAll(/\s(?:src|href)="(https?:\/\/[^"]+)"/g)].map((m) => m[1]);
  const foreign = loaded.filter((u) => !u.startsWith(OURS));
  ok(foreign.length === 0, `${page} loads nothing from another origin${foreign.length ? ': ' + foreign.join(', ') : ''}`);

  // The usual suspects, by name, so a future paste is caught even if it is
  // same-origin-looking or added as an inline snippet.
  const trackers = ['google-analytics', 'googletagmanager', 'gtag(', 'fbq(', 'hotjar',
    'plausible.io', 'matomo', 'segment.com', 'fonts.googleapis', 'fonts.gstatic',
    'cdn.jsdelivr', 'unpkg.com', 'cdnjs.cloudflare'];
  const found = trackers.filter((t) => html.includes(t));
  ok(found.length === 0, `${page} carries no tracker or CDN reference${found.length ? ': ' + found.join(', ') : ''}`);
}

console.log('\nwhat is meant to be found, and what is not');

const indexable = { 'index.html': true, 'about.html': true, 'about.ro.html': true, 'verify.html': false, 'verify.ro.html': false, '404.html': false };
for (const [page, wanted] of Object.entries(indexable)) {
  const html = read(page);
  const blocked = /<meta\s+name="robots"[^>]*content="[^"]*noindex/i.test(html);
  ok(blocked === !wanted,
    `${page} is ${wanted ? 'indexable' : 'kept out of search'}`);
}

for (const page of ['index.html', 'about.html', 'about.ro.html']) {
  const html = read(page);
  const desc = /<meta\s+name="description"\s+content="([^"]+)"/.exec(html)?.[1] ?? '';
  ok(desc.length >= 80 && desc.length <= 320,
    `${page} has a description of a useful length (${desc.length})`);
  ok(/<link\s+rel="canonical"\s+href="https:\/\/[^"]+"/.test(html), `${page} declares a canonical URL`);
  ok(/og:image"\s+content="https:\/\/[^"]+og\.png"/.test(html), `${page} points at the preview card`);
  ok(/<title>[^<]{10,70}<\/title>/.test(html), `${page} has a title of a useful length`);

  // Structured data has to be valid JSON or it is worse than absent: a crawler
  // that cannot parse it learns nothing and may distrust the rest.
  const ld = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(html)?.[1];
  let parsed = null;
  try { parsed = JSON.parse(ld); } catch { /* reported below */ }
  ok(parsed && parsed['@context'] === 'https://schema.org' && parsed['@type'],
    `${page} carries parseable structured data (${parsed?.['@type'] ?? 'invalid'})`);
}

console.log('\nthe security page in both languages');
{
  const en = read('about.html'), ro = read('about.ro.html');
  const ven = read('verify.html'), vro = read('verify.ro.html');
  const alt = (html, lang, url) => new RegExp(`<link rel="alternate" hreflang="${lang}" href="${url}"`).test(html);
  ok(alt(en, 'ro', OURS + '/about.ro.html') && alt(ro, 'en', OURS + '/about.html'),
    'each language version names the other as its alternate');
  ok(/<html lang="ro">/.test(ro) && /og:locale" content="ro"/.test(ro), 'the Romanian page says it is Romanian');
  // A translation that drops a section drops a caveat. Keep them in step.
  const count = (html, tag) => (html.match(new RegExp(`<${tag}[ >]`, 'g')) || []).length;
  ok(count(en, 'h2') === count(ro, 'h2') && count(en, 'li') === count(ro, 'li'),
    `both versions carry the same sections and points (${count(en, 'h2')}/${count(ro, 'h2')} sections, ${count(en, 'li')}/${count(ro, 'li')} points)`);
  ok(count(ven, 'h2') === count(vro, 'h2') && count(ven, 'li') === count(vro, 'li') && count(ven, 'p') === count(vro, 'p'),
    'the verifier carries the same steps and caveats in both languages');
  // The Romanian verifier must run the same check: same script, same ids.
  const ids = (html) => [...html.matchAll(/id="([^"]+)"/g)].map((m) => m[1]).sort().join();
  ok(ids(ven) === ids(vro) && /src="js\/verify\.js"/.test(vro), 'and runs the same script against the same elements');
}

console.log('\ninstalled on a home screen');
{
  const manifest = JSON.parse(read('manifest.json'));
  const pngSize = (rel) => {
    const buf = readFileSync(join(WEB, rel));
    return buf.toString('ascii', 1, 4) === 'PNG' ? [buf.readUInt32BE(16), buf.readUInt32BE(20)] : null;
  };
  const bad = manifest.icons.filter((icon) => {
    if (icon.type !== 'image/png') return false;
    const [w, h] = pngSize(icon.src.replace(/^\//, '')) || [];
    return `${w}x${h}` !== icon.sizes;
  });
  ok(bad.length === 0, `every PNG icon the manifest lists exists at the size it claims${bad.length ? ': ' + bad.map((i) => i.src).join(', ') : ''}`);
  ok(manifest.icons.some((i) => i.sizes === '192x192') && manifest.icons.some((i) => i.sizes === '512x512' && i.purpose === 'any'),
    'Android gets the 192 and 512 icons it asks for');
  // "any maskable" in one entry tells the launcher it may crop an icon that was
  // not drawn to be cropped. The maskable one keeps the skull in the safe zone.
  ok(manifest.icons.every((i) => !/any maskable|maskable any/.test(i.purpose || ''))
    && manifest.icons.some((i) => i.purpose === 'maskable'), 'a separate maskable icon, never "any maskable"');
  ok(!('orientation' in manifest), 'the installed app is not locked to portrait — calls and the landscape layout need it');
  const touch = /<link rel="apple-touch-icon" href="\/([^"]+)"/.exec(read('index.html'))?.[1];
  ok(touch && JSON.stringify(pngSize(touch)) === '[180,180]',
    `iOS gets a 180px PNG, not an SVG it would ignore for a page screenshot (${touch})`);
  ok(!/<text\b/.test(read('icon.svg')), 'the SVG icon is drawn, not an emoji that needs a font to show');
}

console.log('\nrobots and sitemap agree with the pages');
const robots = read('robots.txt');
ok(robots.includes('Disallow: /verify.html') && robots.includes('Disallow: /verify.ro.html'), 'robots.txt keeps the live verifier out of search, in both languages');
ok(robots.includes('Disallow: /api/'), 'robots.txt keeps the API out of search');
ok(/Sitemap:\s*https:\/\/\S+sitemap\.xml/.test(robots), 'robots.txt points at the sitemap');

const sitemap = read('sitemap.xml');
const locs = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
ok(locs.length > 0, `the sitemap lists ${locs.length} URL(s)`);
ok(locs.every((u) => u.startsWith(OURS)), 'every sitemap URL is on this origin');
// A sitemap that advertises a page robots.txt forbids is a contradiction a
// crawler resolves by trusting neither.
ok(!locs.some((u) => u.endsWith('/verify.html')),
  'the sitemap does not advertise a page robots.txt disallows');

console.log('\nthe app speaks one language at a time');

// Eighteen error strings were hardcoded English in a bilingual app, so a
// Romanian user got Romanian until something went wrong — including "do not
// trust this connection", the one message you least want misread. Nothing was
// watching, which is why they drifted.
const appjs = readFileSync(join(WEB, 'js/app.js'), 'utf8');
const shown = [...appjs.matchAll(
  /(?:_renderSystem|_showAuthError|_showCallStatus)\(\s*(['"])(.*?)\1/g)]
  .map((m) => m[2])
  .filter((text) => /[a-z]{3}/.test(text));
ok(shown.length === 0,
  `every message shown to a user goes through the translator${shown.length ? ': ' + shown.slice(0, 5).join(' | ') : ''}`);

const i18n = readFileSync(join(WEB, 'js/i18n.js'), 'utf8');
const keysIn = (block) => new Set([...block.matchAll(/^\s*'([\w.]+)':/gm)].map((m) => m[1]));
const en = keysIn(i18n.slice(i18n.indexOf('en: {'), i18n.indexOf('ro: {')));
const ro = keysIn(i18n.slice(i18n.indexOf('ro: {')));
const untranslated = [...en].filter((k) => !ro.has(k));
ok(untranslated.length === 0,
  `every string has both languages${untranslated.length ? ': missing ' + untranslated.join(', ') : ` (${en.size})`}`);

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
