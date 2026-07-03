/**
 * Dead Drop — in-page code verifier.
 *
 * Fetches the server's /SHA256SUMS manifest, then re-hashes every asset the
 * server just sent (with the browser's own SubtleCrypto) and compares. This
 * proves the delivered files agree with the manifest THIS server gave you.
 *
 * It deliberately does NOT reach out to GitHub: the page's CSP is connect-src
 * 'self', and more importantly, a page fetching its own "proof" from a source
 * the server also controls would be circular. The independent check — comparing
 * the manifest fingerprint below against the public repo — is a manual step, by
 * design. See verify.html.
 */

const GH_REPO = 'Alexandru2984/deadDrop';
const GH_BRANCH = 'main';
const MANIFEST_PATH = 'web/SHA256SUMS';

const $ = (id) => document.getElementById(id);

const toHex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

async function sha256Hex(buf) {
  return toHex(await crypto.subtle.digest('SHA-256', buf));
}

function parseManifest(text) {
  const out = [];
  for (const line of text.split('\n')) {
    const m = /^([0-9a-f]{64})\s+(.+)$/.exec(line.trim());
    if (m) out.push({ hash: m[1], path: m[2] });
  }
  return out;
}

function row(path, state, detail) {
  const el = document.createElement('div');
  el.className = `verify-row verify-${state}`;
  const mark = document.createElement('span');
  mark.className = 'verify-mark';
  mark.textContent = state === 'ok' ? '✓' : state === 'bad' ? '✗' : '…';
  const name = document.createElement('span');
  name.className = 'verify-path';
  name.textContent = path;
  el.append(mark, name);
  if (detail) {
    const d = document.createElement('span');
    d.className = 'verify-detail';
    d.textContent = detail;
    el.append(d);
  }
  return el;
}

async function run() {
  const results = $('results');
  const summary = $('summary');
  results.replaceChildren();
  summary.textContent = 'Fetching manifest…';
  summary.className = 'verify-summary';

  let manifestText;
  try {
    const res = await fetch('/SHA256SUMS', { cache: 'no-store' });
    if (!res.ok) throw new Error(String(res.status));
    manifestText = await res.text();
  } catch (e) {
    summary.textContent = `Could not load /SHA256SUMS (${e.message}).`;
    summary.className = 'verify-summary verify-bad';
    return;
  }

  // Manifest fingerprint — the one short value to compare against GitHub.
  const fp = await sha256Hex(new TextEncoder().encode(manifestText));
  $('fingerprint').textContent = 'sha256:' + fp;

  const files = parseManifest(manifestText);
  summary.textContent = `Checking ${files.length} files…`;

  let ok = 0;
  let bad = 0;
  for (const { hash, path } of files) {
    const pending = row(path, 'pending');
    results.append(pending);
    let got;
    try {
      const res = await fetch('/' + path, { cache: 'no-store' });
      if (!res.ok) throw new Error(String(res.status));
      got = await sha256Hex(await res.arrayBuffer());
    } catch (e) {
      pending.replaceWith(row(path, 'bad', 'fetch failed: ' + e.message));
      bad++;
      continue;
    }
    if (got === hash) {
      pending.replaceWith(row(path, 'ok'));
      ok++;
    } else {
      pending.replaceWith(row(path, 'bad', 'HASH MISMATCH'));
      bad++;
    }
  }

  if (bad === 0) {
    summary.textContent = `✓ All ${ok} files match the served manifest.`;
    summary.className = 'verify-summary verify-ok';
  } else {
    summary.textContent = `✗ ${bad} of ${files.length} files DO NOT match — do not trust this page.`;
    summary.className = 'verify-summary verify-bad';
  }
}

function wireStaticBits() {
  const origin = location.origin;
  const ghRaw = `https://raw.githubusercontent.com/${GH_REPO}/${GH_BRANCH}/${MANIFEST_PATH}`;
  const cmd =
    `diff <(curl -s ${origin}/SHA256SUMS) \\\n` +
    `     <(curl -s ${ghRaw}) \\\n` +
    `  && echo "✓ MATCHES the open-source repo" || echo "✗ DIFFERENT — investigate"`;
  $('cmd').textContent = cmd;
  const link = $('gh-link');
  link.href = `https://github.com/${GH_REPO}/blob/${GH_BRANCH}/${MANIFEST_PATH}`;
}

wireStaticBits();
$('run').addEventListener('click', run);
run();
