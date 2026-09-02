/**
 * Dead Drop — SRP-6a client (RFC 5054 2048-bit group, SHA-256).
 *
 * In these SRP flows, the password is turned into a verifier locally and is not
 * sent to the server, so a TLS-terminating middlebox sees proofs, not the password.
 * The separate legacy-login migration path is documented in README.md.
 * This mirrors internal/srp/srp.go byte-for-byte (group elements are zero-padded to
 * the byte length of N before hashing); the two are cross-checked with deterministic
 * vectors in test/srp.selftest.mjs ↔ internal/srp/srp_test.go.
 */

import { concatBytes } from './util.js';

const N = BigInt('0x' +
  'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050' +
  'A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50' +
  'E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8' +
  '55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B' +
  'CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748' +
  '54523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6A' +
  'F874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB69' +
  '4B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73');
const g = 2n;
const N_LEN = (N.toString(16).length + 1) >> 1; // bytes in N (256)

let _k = null;
async function kParam() {
  if (_k === null) _k = bytesToBig(await sha256(concatBytes(pad(N), pad(g))));
  return _k;
}

/* ── public API ── */

/**
 * Default password-hardening KDF applied BEFORE the SRP x derivation.
 *
 * RFC 5054 derives x with two bare SHA-256 calls, so a leaked verifier database
 * can be brute-forced at GPU hash speed. Stretching the password client-side with
 * PBKDF2-SHA256 (WebCrypto-native, no dependencies) makes each offline guess cost
 * 600k hash iterations instead of two. The kdf string is stored per credential and
 * echoed by the login challenge, so old (unstretched) accounts keep working and
 * upgrade transparently on their next login.
 */
export const DEFAULT_KDF = 'pbkdf2:600000';

/** Stretch the password per `kdf` ('' = legacy pass-through). */
async function stretch(username, password, saltBytes, kdf) {
  if (!kdf) return password;
  const m = /^pbkdf2:(\d+)$/.exec(kdf);
  if (!m) throw new Error('SRP: unsupported KDF ' + kdf);
  const iterations = Number(m[1]);
  if (!Number.isSafeInteger(iterations) || iterations < 10_000 || iterations > 5_000_000) {
    throw new Error('SRP: unsafe KDF cost');
  }
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  // Bind the stretch to the account and the SRP salt so identical passwords on
  // different accounts (or after a salt rotation) never collide.
  const salt = concatBytes(enc.encode(`deaddrop/srp/kdf/v1:${username}:`), saltBytes);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, 256,
  );
  return bytesToHex(new Uint8Array(bits));
}

/** Build a registration verifier. Returns hex salt + verifier + the kdf used. */
export async function register(username, password, kdf = DEFAULT_KDF) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const stretched = await stretch(username, password, salt, kdf);
  const x = await computeX(salt, username, stretched);
  const v = modpow(g, x, N);
  return { salt: bytesToHex(salt), verifier: bigToHex(v), kdf };
}

/** A login attempt. start() → finish(salt,B) → verifyServer(M2). */
export class ClientLogin {
  constructor(username, password, aOverride) {
    this.username = username;
    this.password = password;
    this.a = aOverride ?? randomScalar();
    if (typeof this.a !== 'bigint' || this.a <= 0n || this.a >= N) {
      throw new Error('SRP: invalid client ephemeral');
    }
    this.A = modpow(g, this.a, N);
    this._expectedM2 = null;
    this.K = null;
  }

  /** First message: our public ephemeral A. */
  start() {
    return { A: bigToHex(this.A) };
  }

  /** Given the server's salt, B and advertised kdf, produce the client proof M1. */
  async finish(saltHex, Bhex, kdf = '') {
    if (typeof saltHex !== 'string' || !/^[0-9a-f]{32}$/i.test(saltHex)) {
      throw new Error('SRP: invalid salt');
    }
    if (typeof Bhex !== 'string' || Bhex.length < 1 || Bhex.length > N_LEN * 2 || !/^[0-9a-f]+$/i.test(Bhex)) {
      throw new Error('SRP: invalid server public value');
    }
    const B = hexToBig(Bhex);
    if (B <= 0n || B >= N) throw new Error('SRP: invalid server public value');
    const salt = hexToBytes(saltHex);
    const k = await kParam();
    const stretched = await stretch(this.username, this.password, salt, kdf);
    const x = await computeX(salt, this.username, stretched);
    const u = bytesToBig(await sha256(concatBytes(pad(this.A), pad(B))));
    if (u === 0n) throw new Error('SRP: u ≡ 0');

    // S = (B - k * g^x) ^ (a + u*x) mod N
    let base = (B - (k * modpow(g, x, N)) % N) % N;
    if (base < 0n) base += N;
    const S = modpow(base, this.a + u * x, N);

    const Sp = pad(S);
    this.K = bytesToHex(await sha256(Sp));
    const M1 = await sha256(concatBytes(pad(this.A), pad(B), Sp));
    this._expectedM2 = bytesToHex(await sha256(concatBytes(pad(this.A), M1, Sp)));
    return { M1: bytesToHex(M1) };
  }

  /** Authenticate the server's proof M2. */
  verifyServer(M2hex) {
    return this._expectedM2 !== null && timingSafeHexEqual(M2hex, this._expectedM2);
  }
}

/* ── shared math (mirrors internal/srp/srp.go) ── */

async function computeX(saltBytes, username, password) {
  const inner = await sha256(new TextEncoder().encode(`${username}:${password}`));
  return bytesToBig(await sha256(concatBytes(saltBytes, inner)));
}

// Square-and-multiply with a data-dependent branch on the exponent, which here
// contains a + u*x — and x derives from the password. This is not constant-time.
// JavaScript BigInt exposes no constant-time primitives, so there is no fix in
// pure JS; every browser SRP implementation shares the property. Exploiting it
// needs a timing-observation position inside the victim's own browser, which
// already implies better attacks. Recorded as a known limitation, not an
// oversight — see the security-model notes in README.md.
function modpow(base, exp, mod) {
  base %= mod;
  if (base < 0n) base += mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}


/** Big-endian bytes of x, left-padded to N_LEN. */
function pad(x) {
  let hex = x.toString(16);
  if (hex.length & 1) hex = '0' + hex;
  const bytes = hexToBytes(hex);
  if (bytes.length >= N_LEN) return bytes;
  const out = new Uint8Array(N_LEN);
  out.set(bytes, N_LEN - bytes.length);
  return out;
}

function bytesToBig(u8) {
  let h = '';
  for (const b of u8) h += b.toString(16).padStart(2, '0');
  return h === '' ? 0n : BigInt('0x' + h);
}
function randomScalar() {
  let scalar = 0n;
  while (scalar === 0n) {
    scalar = bytesToBig(crypto.getRandomValues(new Uint8Array(32)));
  }
  return scalar;
}
function bigToHex(x) {
  let h = x.toString(16);
  return h.length & 1 ? '0' + h : h;
}
function hexToBig(h) {
  if (typeof h !== 'string' || !/^[0-9a-f]+$/i.test(h)) throw new Error('SRP: invalid hex');
  return BigInt('0x' + h);
}
function bytesToHex(u8) {
  let h = '';
  for (const b of u8) h += b.toString(16).padStart(2, '0');
  return h;
}
function hexToBytes(h) {
  if (typeof h !== 'string' || !/^[0-9a-f]*$/i.test(h)) throw new Error('SRP: invalid hex');
  if (h.length & 1) h = '0' + h;
  const u8 = new Uint8Array(h.length >> 1);
  for (let i = 0; i < u8.length; i++) u8[i] = parseInt(h.substr(i * 2, 2), 16);
  return u8;
}
function timingSafeHexEqual(a, b) {
  if (typeof a !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Exposed for the cross-implementation self-test only.
export const _srp = { N, g, N_LEN, kParam, computeX, modpow, pad, bytesToBig, bigToHex, hexToBig, bytesToHex, sha256, concat: concatBytes };
