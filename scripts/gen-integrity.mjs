#!/usr/bin/env node
/**
 * Regenerate the code-integrity manifest for Dead Drop.
 *
 *   node scripts/gen-integrity.mjs           # rewrite web/SHA256SUMS + inject SRI
 *   node scripts/gen-integrity.mjs --check   # exit 1 if anything would change (CI)
 *
 * Why this exists: Dead Drop is a website, so every visit re-downloads the
 * JavaScript that does the encryption from the server. A visitor can't otherwise
 * tell whether the served code matches the open-source repo. This writes a
 * canonical SHA-256 of every served asset into web/SHA256SUMS, which is committed
 * to public git — so the served bundle can be checked, independently, against
 * GitHub (and by the in-app /verify page). It also stamps SRI hashes onto the
 * HTML entry points so the browser itself refuses a tampered stylesheet/entry.
 *
 * Run it before every deploy (scripts/deploy.sh does). CI runs --check so the
 * committed hashes can never drift from the code they describe.
 */

import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, renameSync, readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

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

function buildSums() {
  const files = walk(WEB)
    .filter((f) => f !== SUMS && !f.endsWith('.tmp'))
    .map((f) => relative(WEB, f).split(sep).join('/'))
    .sort();
  return files.map((rel) => `${sha256hex(readFileSync(join(WEB, rel)))}  ${rel}`).join('\n') + '\n';
}

const check = process.argv.includes('--check');

// SRI must be stamped BEFORE hashing, since it changes the HTML bytes.
const sriChanged = injectSRI(check);
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
