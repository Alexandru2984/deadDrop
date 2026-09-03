#!/usr/bin/env node
/**
 * Rebuild test/vectors/ml-kem-768.json from NIST's published ACVP vectors.
 *
 *   node scripts/fetch-mlkem-vectors.mjs
 *
 * The fixture is a derivative of NIST's files, not a copy: inputs in full,
 * because they are 32 bytes, and SHA-256 of the official output bytes for the
 * keys and ciphertexts, because those are kilobytes each. A hash binds the
 * answer exactly as the bytes would, and keeps a complete vector set small
 * enough to read.
 *
 * This exists so nobody has to take the fixture on trust: run it and diff.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BASE = 'https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files';
const KEEP = { keyGen: 25, encap: 10, decap: 10 };

const work = mkdtempSync(join(tmpdir(), 'mlkem-vectors-'));
const get = (path) => {
  const out = join(work, path.replace(/\//g, '_'));
  execFileSync('curl', ['-sSL', '--fail', '-o', out, `${BASE}/${path}`], { stdio: 'inherit' });
  return JSON.parse(readFileSync(out, 'utf8'));
};

const sha256 = (hex) => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const group = (doc, fn) => doc.testGroups.find(fn);

const kgPrompt = get('ML-KEM-keyGen-FIPS203/prompt.json');
const kgExpect = get('ML-KEM-keyGen-FIPS203/expectedResults.json');
const edPrompt = get('ML-KEM-encapDecap-FIPS203/prompt.json');
const edExpect = get('ML-KEM-encapDecap-FIPS203/expectedResults.json');

function pair(promptDoc, expectDoc, match) {
  const g = group(promptDoc, match);
  const e = group(expectDoc, (x) => x.tgId === g.tgId);
  const byId = new Map(e.tests.map((t) => [t.tcId, t]));
  return g.tests.map((t) => ({ prompt: t, expected: byId.get(t.tcId), groupLevel: g }));
}

const is768 = (x) => x.parameterSet === 'ML-KEM-768';
const out = {
  _source: 'NIST ACVP-Server, gen-val/json-files (ML-KEM-keyGen-FIPS203, ML-KEM-encapDecap-FIPS203)',
  _note: 'Inputs in full (32 bytes each); keys and ciphertexts as SHA-256 of the official bytes. '
    + 'Shared secrets are 32 bytes and held in full.',
  _regenerate: 'scripts/fetch-mlkem-vectors.mjs',
  keyGen: pair(kgPrompt, kgExpect, is768).slice(0, KEEP.keyGen).map(({ prompt, expected }) => ({
    tcId: prompt.tcId, d: prompt.d.toLowerCase(), z: prompt.z.toLowerCase(),
    ekSha256: sha256(expected.ek), dkSha256: sha256(expected.dk),
  })),
  encap: pair(edPrompt, edExpect, (x) => is768(x) && x.function === 'encapsulation')
    .slice(0, KEEP.encap).map(({ prompt, expected }) => ({
      tcId: prompt.tcId, ek: prompt.ek.toLowerCase(), m: prompt.m.toLowerCase(),
      cSha256: sha256(expected.c), k: expected.k.toLowerCase(),
    })),
  decap: pair(edPrompt, edExpect, (x) => is768(x) && x.function === 'decapsulation')
    .slice(0, KEEP.decap).map(({ prompt, expected, groupLevel }) => ({
      tcId: prompt.tcId, dk: (prompt.dk || groupLevel.dk).toLowerCase(),
      c: prompt.c.toLowerCase(), k: expected.k.toLowerCase(),
    })),
};

writeFileSync(join(ROOT, 'test/vectors/ml-kem-768.json'), JSON.stringify(out, null, 1) + '\n');
rmSync(work, { recursive: true, force: true });
console.log(`wrote test/vectors/ml-kem-768.json — ${out.keyGen.length} keyGen, `
  + `${out.encap.length} encap, ${out.decap.length} decap`);
