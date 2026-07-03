#!/usr/bin/env node
/**
 * Auto-regenerate the code-integrity manifest whenever anything under web/
 * changes.
 *
 * Because the server serves web/ straight off disk, editing a file that an SRI
 * hash points at (e.g. js/app.js) without rerunning gen-integrity leaves a stale
 * integrity="…" in the HTML, and the browser then BLOCKS that file — a blank
 * site. This watcher closes that gap: on any change it regenerates SHA256SUMS
 * and re-stamps SRI within a fraction of a second, so a stale hash can never sit
 * live. Runs as deaddrop-integrity.service.
 *
 *   node scripts/watch-integrity.mjs
 */

import { watch } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const WEB = join(ROOT, 'web');

function regen(reason) {
  const r = spawnSync('node', ['scripts/gen-integrity.mjs'], { cwd: ROOT, encoding: 'utf8' });
  const out = (r.stdout || '').trim();
  const stamp = new Date().toISOString();
  if (r.status !== 0) {
    console.error(`${stamp} [integrity] FAILED (${reason}):`, (r.stderr || '').trim());
  } else if (out.includes('wrote')) {
    console.log(`${stamp} [integrity] ${out} (${reason})`);
  }
}

// Sync once at startup so we never inherit a stale manifest.
regen('startup');

let timer = null;
watch(WEB, { recursive: true }, (_evt, file) => {
  // Ignore our own outputs to avoid a self-trigger loop (gen only writes when
  // something actually changed, so this is belt-and-suspenders).
  if (!file || file.endsWith('SHA256SUMS') || file.endsWith('.tmp')) return;
  clearTimeout(timer);
  timer = setTimeout(() => regen(`changed: ${file}`), 300);
});

console.log(`[integrity] watching ${WEB} for changes`);
