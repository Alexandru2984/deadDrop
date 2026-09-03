/** Self-test for the strict browser integrity-manifest parser. */

import { parseIntegrityManifest, REQUIRED_INTEGRITY_PATHS } from '../web/js/manifest.js';

let failures = 0;
const ok = (condition, message) => {
  if (condition) console.log('  ✓', message);
  else { console.error('  ✗', message); failures++; }
};
const hash = 'a'.repeat(64);
const valid = REQUIRED_INTEGRITY_PATHS.map((path) => `${hash}  ${path}`).join('\n') + '\n';

function rejects(text, expected, options) {
  try {
    parseIntegrityManifest(text, options);
    return false;
  } catch (error) {
    return error.message.includes(expected);
  }
}

console.log('strict integrity manifest');
const parsed = parseIntegrityManifest(valid);
ok(parsed.length === REQUIRED_INTEGRITY_PATHS.length, 'accepts a complete canonical manifest');
ok(parsed[0].hash === hash && parsed[0].path === 'index.html', 'returns exact hash/path pairs');
ok(rejects(valid.slice(0, -1), 'final newline'), 'rejects a truncated final line');
ok(rejects(valid.replace('  index.html', ' index.html'), 'invalid line'), 'requires two separators');
ok(rejects(valid.replace(hash, hash.toUpperCase()), 'invalid line'), 'rejects non-canonical hashes');
ok(rejects(`${hash}  assets/../index.html\n`, 'unsafe path', { requiredPaths: [] }), 'rejects traversal paths');
ok(rejects(`${hash}  index.html\n${hash}  index.html\n`, 'duplicate', { requiredPaths: [] }),
  'rejects duplicate paths');
ok(rejects(`${hash}  index.html\n`, 'omits required path'), 'requires critical application paths');
ok(rejects(valid, 'too many files', { maxFiles: 1, requiredPaths: [] }), 'enforces a file-count bound');
ok(rejects('', 'final newline'), 'rejects an empty manifest');

if (failures) {
  console.error(`\n${failures} manifest self-test(s) failed`);
  process.exit(1);
}
/* ── The required list must keep up with the bundle ── */

// The verifier checks what the manifest lists and nothing else. A file missing
// from the manifest is a file nobody checks, while the page still says every
// file matched — so the required list is the whole defence, and it had fallen
// six modules behind twenty-three. This is what stops that happening twice.
import { readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const WEB = new URL('../web/', import.meta.url).pathname;

function modules(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) modules(p, out);
    else if (name.endsWith('.js')) out.push(relative(WEB, p).replace(/\\/g, '/'));
  }
  return out;
}

const onDisk = modules(join(WEB, 'js')).sort();
const required = new Set(REQUIRED_INTEGRITY_PATHS);
const unguarded = onDisk.filter((m) => !required.has(m));
ok(unguarded.length === 0,
   `every module in the bundle is a required manifest path${unguarded.length ? ': missing ' + unguarded.join(', ') : ` (${onDisk.length})`}`);

// And the other direction: a required path that no longer exists would make
// every manifest unparseable, which is a different kind of outage.
const missing = [...required].filter((p) => p !== 'index.html' && !onDisk.includes(p));
ok(missing.length === 0,
   `every required path still exists${missing.length ? ': stale ' + missing.join(', ') : ''}`);

// A manifest that drops one file must be refused rather than silently checked
// short — the exact shape of a doctored build.
const trimmed = [...onDisk].filter((m) => m !== 'js/srp.js')
  .map((m) => `${'0'.repeat(64)}  ${m}`).join('\n') + '\n';
let refused = false;
try { parseIntegrityManifest(trimmed); } catch { refused = true; }
ok(refused, 'a manifest omitting js/srp.js is rejected, not quietly accepted');

console.log('\nAll integrity-manifest self-tests passed.');
