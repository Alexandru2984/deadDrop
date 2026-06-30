/**
 * Dead Drop — Encryption Layer (v2)
 *
 * Ephemeral ECDH (P-256) → HKDF-SHA256 → AES-256-GCM.
 *
 * Improvements over v1:
 *  - HKDF key separation with a transcript-bound salt (both public keys), instead
 *    of feeding the raw ECDH secret straight into AES-GCM.
 *  - The Short Authentication String (SAS) is derived from the same transcript via
 *    a dedicated HKDF label, and is 6 symbols (2^36) instead of 4 (2^24).
 *  - Symmetric "epochs": a fresh ECDH ratchet can be run mid-session (rekey) for
 *    forward secrecy. Each ciphertext carries its epoch so the peer decrypts with
 *    the right key; old epoch keys are destroyed after a short retention window.
 *
 * All operations use the Web Crypto API — no external dependencies. Keys are never
 * persisted; everything is regenerated per connection and wiped on destroy().
 */

import { bufToB64, b64ToBuf } from './util.js';

const RETAINED_EPOCHS = 3; // keep current + 2 previous keys for in-flight messages
const SAS_LENGTH = 6;      // 6 symbols from a 64-emoji alphabet = 2^36 combinations

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
    this._myPubRaw = null;           // raw bytes of our current public key
    this.epochs = new Map();         // epoch number → AES-GCM CryptoKey
    this.sendEpoch = -1;             // epoch we encrypt under
    this._pendingRekey = null;       // { epoch, keyPair, myPubRaw } while a rekey is in flight
    this._sasSecret = null;          // bytes for the SAS (initial handshake only)
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

  /**
   * Establish the initial session key (epoch 0) from the peer's raw public key.
   * The HKDF salt binds to both public keys (sorted, so both sides agree), so the
   * derived key and SAS are bound to the exact handshake transcript.
   */
  async deriveSession(peerPubRaw) {
    const secret = await this._ecdh(this.keyPair.privateKey, peerPubRaw);
    const salt = await this._transcriptSalt(this._myPubRaw, peerPubRaw);

    const key = await this._hkdfAesKey(secret, salt, 'deaddrop/v2/aead/epoch/0');
    this.epochs.set(0, key);
    this.sendEpoch = 0;

    this._sasSecret = await this._hkdfBytes(secret, salt, 'deaddrop/v2/sas', 16);
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
    const salt = await this._transcriptSalt(myPubRaw, peerPubRaw);
    const key = await this._hkdfAesKey(secret, salt, `deaddrop/v2/aead/epoch/${epoch}`);
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
    this.epochs.clear();
    this.sendEpoch = -1;
    this._pendingRekey = null;
    this._sasSecret = null;
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

  async _transcriptSalt(pubA, pubB) {
    const a = new Uint8Array(pubA);
    const b = new Uint8Array(pubB);
    // Order-independent: sort the two public keys so both peers compute one salt.
    const [first, second] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
    const buf = new Uint8Array(first.length + second.length);
    buf.set(first, 0);
    buf.set(second, first.length);
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

function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
