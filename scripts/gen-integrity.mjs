#!/usr/bin/env node
/**
 * Regenerate the code-integrity manifest for Dead Drop.
 *
 *   node scripts/gen-integrity.mjs           # rewrite web/SHA256SUMS + inject SRI
 *   node scripts/gen-integrity.mjs --check   # exit 1 if anything would change (CI)
 *
 * Why this exists: Dead Drop is a website, so every visit re-downloads the
 * JavaScript that does the encryption from the server. This records a canonical
 * SHA-256 for every served asset in web/SHA256SUMS, which is committed to git.
 * An independently obtained manifest can expose deployment drift; the in-page
 * verifier can only compare fresh same-origin responses and cannot attest to
 * bytes already executing. SRI also makes the browser reject a mismatched
 * stylesheet or entry script relative to the HTML response that named it.
 *
 * Run it before every deploy (scripts/deploy.sh does). CI runs --check so the
 * committed hashes can never drift from the code they describe.
 */

import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, renameSync, readdirSync, statSync } from 'node:fs';
import { join, relative, sep, posix } from 'node:path';

const WEB = 'web';
const SUMS = join(WEB, 'SHA256SUMS');

// Write via a temp file + atomic rename so an interrupted developer-side
// regeneration cannot leave a half-written manifest in the next build.
function atomicWrite(path, data) {
  const tmp = `${path}.${randomBytes(4).toString('hex')}.tmp`;
  writeFileSync(tmp, data);
  renameSync(tmp, path);
}

// Entry-point subresources that also get an SRI integrity="" attribute stamped
// into the HTML that references them. (ES-module imports beyond these entries
// are not SRI-coverable; SHA256SUMS records them for independent verification.)
const SRI_TARGETS = {
  'index.html': ['css/style.css', 'js/app.js'],
  'about.html': ['css/style.css', 'css/about.css'],
  'verify.html': ['css/style.css', 'css/about.css', 'js/verify.js'],
};

// Pages whose module graph the browser should verify, not just the entry. An
// import map's "integrity" section gives every module URL a hash; the browser
// then refuses any module — static import or dynamic import() — whose bytes do
// not match, instead of trusting whatever the network handed back for it.
// Each page carries a `<script type="importmap">…</script>` placeholder in its
// head, before any module script. The server derives the CSP hash for it from
// the embedded page (see appassets.ImportMapHashes).
const IMPORTMAP_PAGES = ['index.html', 'verify.html'];

const sha256hex = (buf) => createHash('sha256').update(buf).digest('hex');
const sha256b64 = (buf) => createHash('sha256').update(buf).digest('base64');

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

// Stamp SRI onto the exact `<... href="P"|src="P" ...>` tags we manage. The HTML
// is authored with `integrity=""` placeholders right after the href/src, so the
// replacement is a tight, unambiguous regex (no general HTML parsing).
function injectSRI(check) {
  let changed = false;
  for (const [htmlRel, refs] of Object.entries(SRI_TARGETS)) {
    const htmlPath = join(WEB, htmlRel);
    let content;
    try {
      content = readFileSync(htmlPath, 'utf8');
    } catch {
      continue; // page may not exist yet
    }
    let updated = content;
    for (const ref of refs) {
      const b64 = sha256b64(readFileSync(join(WEB, ref)));
      const esc = ref.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
      const re = new RegExp(`((?:href|src)="${esc}")\\s+integrity="[^"]*"`);
      if (!re.test(updated)) {
        throw new Error(`${htmlRel}: no integrity="" placeholder next to "${ref}" — add one`);
      }
      updated = updated.replace(re, `$1 integrity="sha256-${b64}"`);
    }
    if (updated !== content) {
      changed = true;
      if (!check) atomicWrite(htmlPath, updated);
    }
  }
  return changed;
}

function importMap() {
  const modules = walk(join(WEB, 'js'))
    .filter((f) => f.endsWith('.js'))
    .map((f) => relative(WEB, f).split(sep).join('/'))
    .sort();
  const integrity = {};
  for (const rel of modules) integrity[`/${rel}`] = `sha256-${sha256b64(readFileSync(join(WEB, rel)))}`;
  return JSON.stringify({ integrity });
}

function injectImportMaps(check) {
  const map = importMap();
  let changed = false;
  for (const page of IMPORTMAP_PAGES) {
    const htmlPath = join(WEB, page);
    const content = readFileSync(htmlPath, 'utf8');
    const re = /<script type="importmap">[^<]*<\/script>/;
    if (!re.test(content)) {
      throw new Error(`${page}: no <script type="importmap"> placeholder — add one before the first module script`);
    }
    const updated = content.replace(re, `<script type="importmap">${map}</script>`);
    if (updated !== content) {
      changed = true;
      if (!check) atomicWrite(htmlPath, updated);
    }
  }
  return changed;
}

// Modules reach the browser one level at a time: app.js names crypto.js, which
// names handshake.js, which names the ML-KEM code — each level a round trip
// before the next can even be asked for. Listing the whole static graph as
// modulepreload links up front lets the browser fetch it in one go. Each link
// carries the same hash as the import map, so a preload is held to it too.
// Dynamic import() is left out on purpose: that code loads only when used.
const PRELOAD_ENTRIES = { 'index.html': 'js/app.js', 'verify.html': 'js/verify.js' };
const STATIC_IMPORT = /(?:^|[;\n])\s*(?:import|export)\s+(?:[\w*{}\s,$]+?\s+from\s+)?['"](\.{1,2}\/[^'"]+)['"]/g;

function staticGraph(entry) {
  const seen = new Set();
  const visit = (rel) => {
    if (seen.has(rel)) return;
    seen.add(rel);
    const source = readFileSync(join(WEB, rel), 'utf8');
    for (const [, spec] of source.matchAll(STATIC_IMPORT)) {
      visit(posix.normalize(posix.join(posix.dirname(rel), spec)));
    }
  };
  visit(entry);
  seen.delete(entry); // the page's own <script> already fetches the entry
  return [...seen].sort();
}

function injectModulePreloads(check) {
  let changed = false;
  for (const [page, entry] of Object.entries(PRELOAD_ENTRIES)) {
    const htmlPath = join(WEB, page);
    const content = readFileSync(htmlPath, 'utf8');
    const re = /<!-- modulepreload -->[\s\S]*?<!-- \/modulepreload -->/;
    if (!re.test(content)) {
      throw new Error(`${page}: no <!-- modulepreload --><!-- /modulepreload --> placeholder after the import map`);
    }
    const links = staticGraph(entry).map((rel) =>
      `<link rel="modulepreload" href="/${rel}" integrity="sha256-${sha256b64(readFileSync(join(WEB, rel)))}" />`);
    const block = `<!-- modulepreload -->\n  ${links.join('\n  ')}\n  <!-- /modulepreload -->`;
    const updated = content.replace(re, block);
    if (updated !== content) {
      changed = true;
      if (!check) atomicWrite(htmlPath, updated);
    }
  }
  return changed;
}

function buildSums() {
  const files = walk(WEB)
    .filter((f) => f !== SUMS && !f.endsWith('.tmp'))
    .map((f) => relative(WEB, f).split(sep).join('/'))
    .sort();
  return files.map((rel) => `${sha256hex(readFileSync(join(WEB, rel)))}  ${rel}`).join('\n') + '\n';
}

const check = process.argv.includes('--check');

// SRI must be stamped BEFORE hashing, since it changes the HTML bytes.
const sriChanged = injectImportMaps(check) | injectModulePreloads(check) | injectSRI(check);
const sums = buildSums();
const prev = (() => {
  try { return readFileSync(SUMS, 'utf8'); } catch { return ''; }
})();
const sumsChanged = sums !== prev;

if (check) {
  if (sriChanged || sumsChanged) {
    console.error('integrity: OUT OF DATE — run `node scripts/gen-integrity.mjs` and commit the result.');
    process.exit(1);
  }
  console.log('integrity: up to date ✓');
} else {
  if (sumsChanged) atomicWrite(SUMS, sums);
  const n = sums.trim().split('\n').length;
  console.log(`integrity: wrote web/SHA256SUMS (${n} files)${sriChanged ? ' + updated SRI' : ''}`);
}
