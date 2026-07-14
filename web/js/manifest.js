/** Strict parser for the generated browser-asset integrity manifest. */

export const REQUIRED_INTEGRITY_PATHS = Object.freeze([
  'index.html',
  'js/app.js',
  'js/crypto.js',
  'js/handshake.js',
  'js/manifest.js',
  'js/peer.js',
]);

export function parseIntegrityManifest(text, {
  maxFiles = 1024,
  requiredPaths = REQUIRED_INTEGRITY_PATHS,
} = {}) {
  if (typeof text !== 'string') throw new Error('manifest is not text');
  if (!Number.isSafeInteger(maxFiles) || maxFiles < 1) throw new Error('invalid file limit');
  if (!text.endsWith('\n')) throw new Error('manifest has no final newline');

  const out = [];
  const seen = new Set();
  for (const line of text.slice(0, -1).split('\n')) {
    const match = /^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)$/.exec(line);
    if (!match) throw new Error('manifest contains an invalid line');

    const path = match[2];
    const parts = path.split('/');
    if (parts.some((part) => part === '' || part === '.' || part === '..')) {
      throw new Error('manifest contains an unsafe path');
    }
    if (seen.has(path)) throw new Error('manifest contains a duplicate path');

    seen.add(path);
    out.push({ hash: match[1], path });
    if (out.length > maxFiles) throw new Error('manifest has too many files');
  }

  if (out.length === 0) throw new Error('manifest is empty');
  for (const path of requiredPaths) {
    if (!seen.has(path)) throw new Error(`manifest omits required path: ${path}`);
  }
  return out;
}
