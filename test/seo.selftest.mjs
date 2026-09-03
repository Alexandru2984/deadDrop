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

const indexable = { 'index.html': true, 'about.html': true, 'verify.html': false, '404.html': false };
for (const [page, wanted] of Object.entries(indexable)) {
  const html = read(page);
  const blocked = /<meta\s+name="robots"[^>]*content="[^"]*noindex/i.test(html);
  ok(blocked === !wanted,
    `${page} is ${wanted ? 'indexable' : 'kept out of search'}`);
}

for (const page of ['index.html', 'about.html']) {
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

console.log('\nrobots and sitemap agree with the pages');
const robots = read('robots.txt');
ok(robots.includes('Disallow: /verify.html'), 'robots.txt keeps the live verifier out of search');
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

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
