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
console.log('\nAll integrity-manifest self-tests passed.');
