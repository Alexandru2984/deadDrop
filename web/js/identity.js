/**
 * Dead Drop — opt-in long-term identity (protocol v5)
 *
 * By default Dead Drop presents nothing that survives a session: the handshake
 * uses fresh ECDH and ML-KEM keys every time, so two conversations with the same
 * person are not linkable to each other by either side. That is the whole point
 * of the "ephemeral" claim, and it is why every session needs its own
 * out-of-band safety-code comparison.
 *
 * A saved contact trades a piece of that away deliberately. When the user turns
 * it on, this module mints an ECDSA P-256 keypair that lives in IndexedDB and is
 * presented during the handshake. A peer who sees it can tell that two sessions
 * came from the same browser — that is exactly what makes pinning possible, and
 * exactly what costs unlinkability. Nothing is generated or presented until the
 * user opts in, and a panic wipe destroys it.
 *
 * The private key is non-extractable, so page script can ask for signatures but
 * can never read the key itself.
 */

import { concatBytes } from './util.js';

const DB_NAME = 'deaddrop-identity';
const DB_VERSION = 1;
const KEY_STORE = 'identity';
const TRUST_STORE = 'contacts';
const SELF_ID = 'self';

const enc = new TextEncoder();

/* ── IndexedDB plumbing ── */

function openDB() {
  return new Promise((resolve, reject) => {
    let request;
    try {
      request = indexedDB.open(DB_NAME, DB_VERSION);
    } catch (err) {
      reject(err);
      return;
    }
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(KEY_STORE)) db.createObjectStore(KEY_STORE);
      if (!db.objectStoreNames.contains(TRUST_STORE)) db.createObjectStore(TRUST_STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function withStore(name, mode, fn) {
  const db = await openDB();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(name, mode);
      const request = fn(tx.objectStore(name));
      tx.onabort = () => reject(tx.error);
      tx.onerror = () => reject(tx.error);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}

/* ── Identity ── */

/** The stored identity, or null when the user has never opted in. */
export async function loadIdentity() {
  try {
    const record = await withStore(KEY_STORE, 'readonly', (store) => store.get(SELF_ID));
    if (!record?.privateKey || !record?.publicKeyRaw) return null;
    return {
      privateKey: record.privateKey,
      publicKeyRaw: new Uint8Array(record.publicKeyRaw),
    };
  } catch {
    return null; // private browsing, blocked storage — behave as if not opted in
  }
}

/**
 * Mint an identity if none exists, and return it. The private key is stored as a
 * non-extractable CryptoKey: IndexedDB can hold the handle, but nothing — not
 * this module, not injected script — can read the key material back out.
 */
export async function ensureIdentity() {
  const existing = await loadIdentity();
  if (existing) return existing;

  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify'],
  );
  const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  await withStore(KEY_STORE, 'readwrite', (store) => store.put({
    privateKey: pair.privateKey,
    publicKeyRaw,
  }, SELF_ID));
  return { privateKey: pair.privateKey, publicKeyRaw };
}

/** Destroy the identity and every pinned contact. Used by the panic wipe. */
export async function clearIdentity() {
  try {
    await withStore(KEY_STORE, 'readwrite', (store) => store.delete(SELF_ID));
    await withStore(TRUST_STORE, 'readwrite', (store) => store.clear());
  } catch { /* nothing stored, or storage unavailable */ }
}

/* ── Signing ── */

// Domain separation keeps an identity signature from ever being replayable as
// anything else the app might one day sign.
const SIG_CONTEXT = 'deaddrop/v5/identity\0';

/** Sign a handshake transcript hash, proving possession of the identity key. */
export async function signTranscript(privateKey, transcriptHash) {
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    concatBytes(enc.encode(SIG_CONTEXT), transcriptHash),
  );
  return new Uint8Array(signature);
}

/**
 * Verify a peer's proof of possession.
 *
 * Presenting a public key is not evidence of holding it. Without this check an
 * attacker could replay a pinned contact's public key, match the pin, and be
 * trusted without the user ever comparing a safety code again.
 */
export async function verifyTranscript(publicKeyRaw, transcriptHash, signature) {
  if (!(publicKeyRaw instanceof Uint8Array) || publicKeyRaw.length !== 65
      || publicKeyRaw[0] !== 4) {
    return false;
  }
  if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey(
      'raw', publicKeyRaw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      signature,
      concatBytes(enc.encode(SIG_CONTEXT), transcriptHash),
    );
  } catch {
    return false;
  }
}

/** Short, stable, human-comparable name for an identity key. */
export async function fingerprint(publicKeyRaw) {
  const digest = await crypto.subtle.digest('SHA-256', publicKeyRaw);
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

/* ── Pinned contacts ── */

/**
 * Remember that this identity was verified out of band. Keyed by fingerprint, so
 * a peer presenting a different key is a different contact — never a silent
 * upgrade of an existing one.
 */
export async function pinContact(fp, label) {
  await withStore(TRUST_STORE, 'readwrite', (store) => store.put({
    fingerprint: fp,
    label: String(label || '').slice(0, 40),
    verifiedAt: Date.now(),
  }, fp));
}

export async function findContact(fp) {
  try {
    return (await withStore(TRUST_STORE, 'readonly', (store) => store.get(fp))) || null;
  } catch {
    return null;
  }
}

export async function listContacts() {
  try {
    return (await withStore(TRUST_STORE, 'readonly', (store) => store.getAll())) || [];
  } catch {
    return [];
  }
}

export async function forgetContact(fp) {
  try {
    await withStore(TRUST_STORE, 'readwrite', (store) => store.delete(fp));
  } catch { /* already gone */ }
}

