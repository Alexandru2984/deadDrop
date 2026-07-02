/**
 * Dead Drop — Encryption Layer (v3)
 *
 * Hybrid post-quantum key agreement: ephemeral ECDH (P-256) + ML-KEM-768
 * (FIPS 203) → HKDF-SHA256 → AES-256-GCM.
 *
 * Improvements over v2:
 *  - The session secret mixes a classical ECDH share with an ML-KEM-768 share, so
 *    recorded traffic stays confidential even against a future quantum computer
 *    ("harvest now, decrypt later"). Breaking the session requires breaking BOTH.
 *  - A 32-byte post-quantum root secret from the initial handshake is mixed into
 *    every DH ratchet, so rekeyed epochs inherit the PQ resistance too.
 *
 * Carried over from v2: transcript-bound HKDF salts, 6-symbol SAS (2^36),
 * symmetric rekey epochs with a short retention window.
 *
 * ECDH/HKDF/AES use the Web Crypto API; ML-KEM-768 is the vendored, audited
 * noble implementation (same-origin ESM, no third parties). Keys are never
 * persisted; everything is regenerated per connection and wiped on destroy().
 */

import { bufToB64, b64ToBuf } from './util.js';
import { ml_kem768 } from './vendor/noble/ml-kem.js';

const RETAINED_EPOCHS = 3; // keep current + 2 previous keys for in-flight messages
const SAS_LENGTH = 6;      // 6 symbols from a 64-emoji alphabet = 2^36 combinations

// Padding buckets for sealed envelopes: every ciphertext length lands on one of
// these sizes (bytes of plaintext), so an observer of the encrypted channel—
// DTLS-MitM relay included—learns only the bucket, not the exact message length,
// and typing notices are indistinguishable from short chat messages.
const PAD_BUCKETS = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];
const PAD_STEP_ABOVE_MAX = 16384; // beyond the largest bucket, round up to this

const SAS_EMOJI = [
  '🐶','🐱','🐭','🐹','🐰','🦊','🐻','🐼',
  '🐨','🐯','🦁','🐮','🐷','🐸','🐵','🐔',
  '🐧','🐦','🐤','🦆','🦅','🦉','🦇','🐺',
  '🐗','🐴','🦄','🐝','🐛','🦋','🐌','🐞',
  '🍎','🍐','🍊','🍋','🍌','🍉','🍇','🍓',
  '🍈','🍒','🍑','🥭','🍍','🥥','🥝','🍅',
  '🌵','🌲','🌴','🌿','🍀','🌺','🌻','🌹',
  '🔥','⚡','❄️','🌊','💎','🔑','🎯','💀',
];

const enc = new TextEncoder();
const dec = new TextDecoder();

export class CryptoLayer {
  constructor() {
    this.keyPair = null;             // current ephemeral ECDH pair (handshake / rekey)
    this._myPubRaw = null;           // raw bytes of our current ECDH public key
    this._kemKeys = null;            // ephemeral ML-KEM-768 keypair (handshake only)
    this._kemPubRaw = null;          // raw bytes of our KEM public key
    this._rootSecret = null;         // 32B PQ root mixed into every rekey epoch
    this.epochs = new Map();         // epoch number → AES-GCM CryptoKey
    this.sendEpoch = -1;             // epoch we encrypt under
    this._pendingRekey = null;       // { epoch, keyPair, myPubRaw } while a rekey is in flight
    this._sasSecret = null;          // bytes for the SAS (initial handshake only)
    this._confirmSecret = null;      // bytes for the key-confirmation tags
    this.seenNonces = new Set();     // replay protection (text)
    this.seenBinaryNonces = new Set();
    this._maxNonces = 10000;
  }

  /** Generate an ephemeral ECDH key pair; returns the raw public key bytes. */
  async generateKeyPair() {
    this.keyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    );
    this._myPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', this.keyPair.publicKey));
    return this._myPubRaw;
  }

  /** Generate the ephemeral ML-KEM-768 keypair; returns the encapsulation key bytes. */
  generateKemKeys() {
    this._kemKeys = ml_kem768.keygen();
    this._kemPubRaw = this._kemKeys.publicKey;
    return this._kemPubRaw;
  }

  /** Encapsulate to the peer's KEM public key → { cipherText, sharedSecret }. */
  kemEncapsulate(peerKemPubRaw) {
    return ml_kem768.encapsulate(peerKemPubRaw);
  }

  /** Decapsulate a ciphertext with our KEM secret key → sharedSecret bytes. */
  kemDecapsulate(cipherText) {
    if (!this._kemKeys) throw new Error('No KEM keypair');
    return ml_kem768.decapsulate(cipherText, this._kemKeys.secretKey);
  }

  /**
   * Establish the initial session key (epoch 0) from the hybrid transcript:
   * the peer's ECDH public key, the ML-KEM shared secret, and the KEM transcript
   * bytes (decapsulator's public key ‖ ciphertext). The HKDF salt binds to the
   * sorted ECDH keys AND the KEM transcript, so the derived key, the SAS and the
   * confirmation tags are all bound to the exact handshake that took place.
   */
  async deriveSession(peerPubRaw, kemShared, kemTranscript) {
    const ecdhSecret = new Uint8Array(await this._ecdh(this.keyPair.privateKey, peerPubRaw));
    const ikm = new Uint8Array(ecdhSecret.length + kemShared.length);
    ikm.set(ecdhSecret, 0);
    ikm.set(kemShared, ecdhSecret.length);
    const salt = await this._transcriptSalt(this._myPubRaw, peerPubRaw, kemTranscript);

    const key = await this._hkdfAesKey(ikm, salt, 'deaddrop/v3/aead/epoch/0');
    this.epochs.set(0, key);
    this.sendEpoch = 0;

    this._sasSecret = await this._hkdfBytes(ikm, salt, 'deaddrop/v3/sas', 16);
    this._confirmSecret = await this._hkdfBytes(ikm, salt, 'deaddrop/v3/confirm', 32);
    // The PQ root: mixed into every future rekey so post-quantum resistance
    // survives the ratchet, while fresh ECDH still provides forward secrecy.
    this._rootSecret = await this._hkdfBytes(ikm, salt, 'deaddrop/v3/root', 32);
    ecdhSecret.fill(0);
    ikm.fill(0);
  }

  /** Key-confirmation tag for one direction ('e' = encapsulator, 'd' = decapsulator). */
  async confirmTag(role) {
    if (!this._confirmSecret) throw new Error('No session established');
    return this._hkdfBytes(this._confirmSecret, new Uint8Array(32), `deaddrop/v3/confirm/${role}`, 16);
  }

  /** 6-symbol SAS string both peers compute identically — compare out-of-band to detect MitM. */
  computeSAS() {
    if (!this._sasSecret) throw new Error('No session established');
    let sas = '';
    for (let i = 0; i < SAS_LENGTH; i++) {
      sas += SAS_EMOJI[this._sasSecret[i] % SAS_EMOJI.length];
    }
    return sas;
  }

  get established() {
    return this.sendEpoch >= 0 && this.epochs.has(this.sendEpoch);
  }

  /* ── Rekey (DH ratchet → forward secrecy) ──
   * Initiator: beginRekey() → send offer; on answer → completeRekey().
   * Responder: on offer → acceptRekey() → send answer.
   * Each rekey derives a brand-new key from fresh ephemeral ECDH keys; once we
   * advance past the retention window the old key is destroyed and the messages it
   * protected can never be decrypted again, even if the device is later seized.
   */

  async beginRekey() {
    const epoch = this.sendEpoch + 1;
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    );
    const myPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    this._pendingRekey = { epoch, keyPair: kp, myPubRaw };
    return { epoch, publicKey: bufToB64(myPubRaw) };
  }

  async acceptRekey(peerPubB64, epoch) {
    if (!Number.isInteger(epoch) || epoch <= this.sendEpoch) throw new Error('stale rekey epoch');
    const peerPubRaw = new Uint8Array(b64ToBuf(peerPubB64));
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    );
    const myPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    await this._installRatchetKey(kp.privateKey, myPubRaw, peerPubRaw, epoch);
    return { epoch, publicKey: bufToB64(myPubRaw) };
  }

  async completeRekey(peerPubB64, epoch) {
    if (!this._pendingRekey || this._pendingRekey.epoch !== epoch) throw new Error('no matching pending rekey');
    const peerPubRaw = new Uint8Array(b64ToBuf(peerPubB64));
    const { keyPair, myPubRaw } = this._pendingRekey;
    await this._installRatchetKey(keyPair.privateKey, myPubRaw, peerPubRaw, epoch);
    this._pendingRekey = null;
  }

  async _installRatchetKey(privateKey, myPubRaw, peerPubRaw, epoch) {
    const secret = await this._ecdh(privateKey, peerPubRaw);
    // Mixing the PQ root into the salt makes every ratcheted epoch as
    // quantum-resistant as the initial hybrid handshake; the fresh ECDH share
    // still provides forward secrecy against classical compromise.
    const salt = await this._transcriptSalt(myPubRaw, peerPubRaw, this._rootSecret);
    const key = await this._hkdfAesKey(secret, salt, `deaddrop/v3/aead/epoch/${epoch}`);
    this.epochs.set(epoch, key);
    this.sendEpoch = epoch;
    // Drop keys that have fallen out of the retention window.
    for (const e of this.epochs.keys()) {
      if (e <= epoch - RETAINED_EPOCHS) this.epochs.delete(e);
    }
  }

  /* ── Text messages ── */

  async encrypt(plaintext) {
    const key = this._sendKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(8)));
    const envelope = JSON.stringify({ text: plaintext, nonce, ts: Date.now() });
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(envelope));
    return { ciphertext: bufToB64(ciphertext), iv: bufToB64(iv), epoch: this.sendEpoch };
  }

  async decrypt(ciphertextB64, ivB64, epoch) {
    const key = this._recvKey(epoch);
    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBuf(ivB64) }, key, b64ToBuf(ciphertextB64),
    );
    const envelope = JSON.parse(dec.decode(plainBuf));
    if (!Array.isArray(envelope.nonce) || envelope.nonce.length !== 8) throw new Error('Invalid nonce');
    this._checkReplay(this.seenNonces, envelope.nonce.join(','));
    return envelope.text;
  }

  /* ── Sealed envelopes (all app-level channel traffic) ──
   * seal() wraps an arbitrary JS object in an encrypted, replay-protected,
   * length-padded envelope. Used by the peer layer for EVERY post-handshake
   * message (chat, typing, read receipts, deletes, call signaling, file
   * chunks), so a compromised relay sees only uniform ciphertext blobs. */

  async seal(obj) {
    const key = this._sendKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(8)));
    const ts = Date.now();
    // Measure with an empty pad, then re-serialize with ASCII filler so the
    // plaintext byte length lands exactly on the bucket (non-ASCII content is
    // measured in encoded bytes, and each 'x' adds exactly one byte).
    const bareBytes = enc.encode(JSON.stringify({ msg: obj, nonce, ts, pad: '' })).byteLength;
    const envelope = JSON.stringify({ msg: obj, nonce, ts, pad: 'x'.repeat(padBucket(bareBytes) - bareBytes) });
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(envelope));
    return { ciphertext: bufToB64(ciphertext), iv: bufToB64(iv), epoch: this.sendEpoch };
  }

  async open(ciphertextB64, ivB64, epoch) {
    const key = this._recvKey(epoch);
    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBuf(ivB64) }, key, b64ToBuf(ciphertextB64),
    );
    const envelope = JSON.parse(dec.decode(plainBuf));
    if (!Array.isArray(envelope.nonce) || envelope.nonce.length !== 8) throw new Error('Invalid nonce');
    this._checkReplay(this.seenNonces, envelope.nonce.join(','));
    return envelope.msg;
  }

  /* ── Binary (files) ── */

  async encryptBinary(data) {
    const key = this._sendKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const nonce = crypto.getRandomValues(new Uint8Array(8));
    const withNonce = new Uint8Array(nonce.length + data.byteLength);
    withNonce.set(nonce, 0);
    withNonce.set(new Uint8Array(data), nonce.length);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, withNonce);
    return { ciphertext, iv: bufToB64(iv), epoch: this.sendEpoch };
  }

  async decryptBinary(ciphertextBuf, ivB64, epoch) {
    const key = this._recvKey(epoch);
    const withNonce = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBuf(ivB64) }, key, ciphertextBuf);
    if (withNonce.byteLength < 8) throw new Error('Invalid encrypted file payload');
    const nonce = Array.from(new Uint8Array(withNonce.slice(0, 8))).join(',');
    this._checkReplay(this.seenBinaryNonces, nonce);
    return withNonce.slice(8);
  }

  /** Destroy all key material. */
  destroy() {
    this.keyPair = null;
    this._myPubRaw = null;
    if (this._kemKeys) {
      this._kemKeys.secretKey.fill(0);
      this._kemKeys.publicKey.fill(0);
      this._kemKeys = null;
    }
    this._kemPubRaw = null;
    for (const b of [this._rootSecret, this._sasSecret, this._confirmSecret]) {
      if (b) b.fill(0);
    }
    this._rootSecret = null;
    this._sasSecret = null;
    this._confirmSecret = null;
    this.epochs.clear();
    this.sendEpoch = -1;
    this._pendingRekey = null;
    this.seenNonces.clear();
    this.seenBinaryNonces.clear();
  }

  /* ── Private helpers ── */

  _sendKey() {
    const key = this.epochs.get(this.sendEpoch);
    if (!key) throw new Error('No session key established');
    return key;
  }

  _recvKey(epoch) {
    // Backwards/missing epoch defaults to the send epoch (v1 peers send no epoch).
    const e = Number.isInteger(epoch) ? epoch : this.sendEpoch;
    const key = this.epochs.get(e);
    if (!key) throw new Error('Unknown key epoch — message dropped');
    return key;
  }

  _checkReplay(set, nonceKey) {
    if (set.has(nonceKey)) throw new Error('Replay attack detected — duplicate nonce');
    set.add(nonceKey);
    if (set.size > this._maxNonces) set.delete(set.values().next().value);
  }

  async _ecdh(privateKey, peerPubRaw) {
    const peerKey = await crypto.subtle.importKey(
      'raw', peerPubRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, [],
    );
    return crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, privateKey, 256);
  }

  async _transcriptSalt(pubA, pubB, extra) {
    const a = new Uint8Array(pubA);
    const b = new Uint8Array(pubB);
    // Order-independent: sort the two public keys so both peers compute one salt.
    // `extra` (KEM transcript on handshake, PQ root on rekey) is identical on
    // both sides already, so it is appended as-is.
    const [first, second] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
    const extraLen = extra ? extra.length : 0;
    const buf = new Uint8Array(first.length + second.length + extraLen);
    buf.set(first, 0);
    buf.set(second, first.length);
    if (extra) buf.set(extra, first.length + second.length);
    return crypto.subtle.digest('SHA-256', buf);
  }

  async _hkdfBytes(secret, salt, info, length) {
    const base = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) }, base, length * 8,
    );
    return new Uint8Array(bits);
  }

  async _hkdfAesKey(secret, salt, info) {
    const base = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
    );
  }
}

/** Smallest padding bucket that fits `n` plaintext bytes. */
function padBucket(n) {
  for (const b of PAD_BUCKETS) {
    if (n <= b) return b;
  }
  return Math.ceil(n / PAD_STEP_ABOVE_MAX) * PAD_STEP_ABOVE_MAX;
}

export function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
