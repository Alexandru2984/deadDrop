#!/usr/bin/env node
/**
 * Prove the vendored cryptography is upstream's, byte for byte.
 *
 *   node scripts/verify-vendor.mjs           # fetch, rewrite, diff
 *   node scripts/verify-vendor.mjs --offline # use a previously fetched cache
 *
 * The post-quantum half of the handshake is third-party code compiled into the
 * server binary, and it is the one part of this repository nobody here wrote. It
 * was vendored so the client stays free of package managers and third-party
 * origins — a real gain — but it moved the supply chain from "npm resolves it at
 * build time" to "somebody copied these files once", and the only thing standing
 * between that and a modified ML-KEM was a note asking the next person to diff.
 *
 * So: fetch the pinned tarballs, apply the one documented modification, and
 * compare. Anything else is a difference nobody approved.
 *
 * The rewrite is deliberately the narrowest possible transformation — bare
 * specifiers to relative paths, nothing else — because every character this
 * script is willing to change is a character an attacker could hide in.
 */

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const VENDOR = join(ROOT, 'web/js/vendor/noble');
const CACHE = join(tmpdir(), 'deaddrop-vendor-cache');

/** Pinned exactly as web/js/vendor/noble/README.md records them. */
const PACKAGES = {
  '@noble/post-quantum': '0.6.1',
  '@noble/hashes': '2.2.0',
  '@noble/curves': '2.2.0',
};

/** vendored file → [package, path inside the tarball] */
const FILES = {
  'ml-kem.js': ['@noble/post-quantum', 'ml-kem.js'],
  '_crystals.js': ['@noble/post-quantum', '_crystals.js'],
  'pq-utils.js': ['@noble/post-quantum', 'utils.js'],
  'sha3.js': ['@noble/hashes', 'sha3.js'],
  'hash-utils.js': ['@noble/hashes', 'utils.js'],
  '_u64.js': ['@noble/hashes', '_u64.js'],
  'fft.js': ['@noble/curves', 'abstract/fft.js'],
};

/**
 * The only accepted modification: bare package specifiers become relative paths,
 * because the bundle loads as plain same-origin ES modules under a CSP that
 * allows no other origin. Nothing here rewrites code.
 */
const SPECIFIERS = [
  ['@noble/post-quantum/utils.js', './pq-utils.js'],
  ['@noble/hashes/sha3.js', './sha3.js'],
  ['@noble/hashes/utils.js', './hash-utils.js'],
  ['@noble/hashes/_u64.js', './_u64.js'],
  ['@noble/curves/abstract/fft.js', './fft.js'],
  ['@noble/curves/utils.js', './hash-utils.js'],
];

/**
 * Two of the three packages ship a file called `utils.js`, so the flat vendor
 * directory had to rename them — and every relative specifier that pointed at
 * one had to follow. Which rename applies depends on the package the file came
 * from, so this is keyed by source package rather than applied globally.
 */
const RENAMES = {
  '@noble/post-quantum': [['./utils.js', './pq-utils.js']],
  '@noble/hashes': [['./utils.js', './hash-utils.js']],
  '@noble/curves': [['./utils.js', './hash-utils.js']],
};

/**
 * Rewrite specifiers on real import/export statements only.
 *
 * Not in comments. Upstream's JSDoc is full of `import { x } from '@noble/…'`
 * examples, and touching those would mean this script accepts a class of edit
 * that the vendoring never made — comments do not affect module loading, so a
 * difference in one is a difference somebody should look at.
 */
function rewrite(source, pkg) {
  const rules = [...SPECIFIERS, ...(RENAMES[pkg] || [])];
  return source.split('\n').map((line) => {
    const trimmed = line.trimStart();
    if (!trimmed.startsWith('import') && !trimmed.startsWith('export')) return line;
    let out = line;
    for (const [from, to] of rules) {
      out = out.replaceAll(`'${from}'`, `'${to}'`).replaceAll(`"${from}"`, `"${to}"`);
    }
    return out;
  }).join('\n');
}

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const offline = process.argv.includes('--offline');

function fetchPackage(name, version) {
  const slug = name.replace('@', '').replace('/', '-');
  const dir = join(CACHE, `${slug}-${version}`);
  if (existsSync(join(dir, 'package'))) return join(dir, 'package');
  if (offline) {
    console.error(`vendor: --offline but ${name}@${version} is not cached at ${dir}`);
    process.exit(2);
  }
  mkdirSync(dir, { recursive: true });
  const short = name.split('/').pop();
  const url = `https://registry.npmjs.org/${name}/-/${short}-${version}.tgz`;
  execFileSync('curl', ['-sSL', '--fail', '-o', join(dir, 'pkg.tgz'), url], { stdio: 'inherit' });
  execFileSync('tar', ['-xzf', join(dir, 'pkg.tgz'), '-C', dir]);
  return join(dir, 'package');
}

console.log('Verifying vendored cryptography against the pinned upstream releases\n');

const roots = {};
for (const [name, version] of Object.entries(PACKAGES)) {
  roots[name] = fetchPackage(name, version);
  console.log(`  fetched ${name}@${version}`);
}
console.log();

let mismatches = 0;
for (const [vendored, [pkg, original]] of Object.entries(FILES)) {
  const upstreamPath = join(roots[pkg], original);
  if (!existsSync(upstreamPath)) {
    console.error(`  ✗ ${vendored}: ${pkg}/${original} is not in the published tarball`);
    mismatches++;
    continue;
  }
  const expected = rewrite(readFileSync(upstreamPath, 'utf8'), pkg);
  const actual = readFileSync(join(VENDOR, vendored), 'utf8');
  if (expected === actual) {
    console.log(`  ✓ ${vendored.padEnd(16)} ${sha256(actual).slice(0, 16)}  (${pkg}/${original})`);
    continue;
  }

  mismatches++;
  console.error(`  ✗ ${vendored}: differs from ${pkg}@${PACKAGES[pkg]}/${original}`);
  const a = expected.split('\n');
  const b = actual.split('\n');
  let shown = 0;
  for (let i = 0; i < Math.max(a.length, b.length) && shown < 6; i++) {
    if (a[i] !== b[i]) {
      console.error(`      line ${i + 1}`);
      console.error(`        upstream: ${JSON.stringify(a[i] ?? '<missing>').slice(0, 120)}`);
      console.error(`        vendored: ${JSON.stringify(b[i] ?? '<missing>').slice(0, 120)}`);
      shown++;
    }
  }
}

if (process.argv.includes('--clean')) rmSync(CACHE, { recursive: true, force: true });

if (mismatches > 0) {
  console.error(`\n${mismatches} vendored file(s) do not match upstream.`);
  console.error('Either the copy was modified, or the pin in README.md is stale.');
  process.exit(1);
}
console.log('\nEvery vendored file matches its pinned upstream release, after the'
  + '\nimport-specifier rewrite and nothing else. ✅');
