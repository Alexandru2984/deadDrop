/** Strict parser for the generated browser-asset integrity manifest. */

/**
 * Every module the bundle can load, and the entry page.
 *
 * The verifier checks what the manifest lists and nothing else, so a manifest
 * that simply omits a file leaves that file unchecked while the page still
 * reports success. ES module imports carry no subresource integrity — index.html
 * pins app.js, but app.js pins nothing it imports — so this list is the only
 * thing standing between a trimmed manifest and a green result.
 *
 * It held six entries while the bundle grew to twenty-three, leaving srp.js,
 * which turns a password into an SRP proof, and the whole post-quantum
 * implementation unguarded. `test/manifest.selftest.mjs` now fails when a module
 * exists on disk and is missing here, so the list cannot drift again.
 */
export const REQUIRED_INTEGRITY_PATHS = Object.freeze([
  'index.html',
  'js/app.js',
  'js/callsignal.js',
  'js/crypto.js',
  'js/filetransfer.js',
  'js/handshake.js',
  'js/i18n.js',
  'js/identity.js',
  'js/manifest.js',
  'js/messages.js',
  'js/peer.js',
  'js/srp.js',
  'js/support.js',
  'js/util.js',
  'js/vendor/jsqr.js',
  'js/vendor/noble/_crystals.js',
  'js/vendor/noble/_u64.js',
  'js/vendor/noble/fft.js',
  'js/vendor/noble/hash-utils.js',
  'js/vendor/noble/ml-kem.js',
  'js/vendor/noble/pq-utils.js',
  'js/vendor/noble/sha3.js',
  'js/vendor/qrcode.js',
  'js/verify.js',
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
