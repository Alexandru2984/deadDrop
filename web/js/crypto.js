/**
 * Dead Drop — Encryption Layer (protocol v5)
 *
 * Hybrid post-quantum key agreement: ephemeral ECDH (P-256) + ML-KEM-768
 * (FIPS 203) → HKDF-SHA256 → AES-256-GCM.
 *
 * Protocol v5 derives independent traffic keys for each direction and content
 * type, authenticates the protocol context and epoch as AEAD additional data,
 * and tracks authenticated 96-bit IVs for the complete retained key lifetime.
 * Rekeys mix a fresh ephemeral ECDH share with the evolving post-quantum root.
 *
 * ECDH/HKDF/AES use the Web Crypto API; ML-KEM-768 is vendored same-origin.
 * The application does not persist keys. Private ECDH keys are non-extractable
 * and references to obsolete material are dropped when no longer needed; the
 * browser/OS still controls physical memory and may retain copies.
 */

import { bufToB64, b64ToBuf } from './util.js';
import { ml_kem768 } from './vendor/noble/ml-kem.js';

export const PROTOCOL_VERSION = 5;

const RETAINED_EPOCHS = 3; // current + 2 previous epochs for ordered in-flight data
const MAX_IVS_PER_EPOCH = 100000; // fail closed instead of forgetting replay history
const SAS_LENGTH = 6;      // 6 symbols from a 64-emoji alphabet = 2^36 combinations
const TRAFFIC_CONTEXTS = ['text', 'sealed', 'binary'];

// Padding buckets for sealed envelopes. This hides exact plaintext length within
// a bucket; it does not hide traffic timing, packet counts, or large transfers.
const PAD_BUCKETS = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];
const PAD_STEP_ABOVE_MAX = 16384;

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
    this.keyPair = null;
    this._myPubRaw = null;
    this._kemKeys = null;
    this._kemPubRaw = null;
    this._rootSecret = null;
    this.sendEpochs = new Map(); // epoch → { text, sealed, binary } CryptoKeys
    this.recvEpochs = new Map();
    this.sendEpoch = -1;
    this._pendingRekey = null;
    this._sasSecret = null;
    this._confirmSecret = null;
    this.transcriptHash = null;
    this._seenIVs = Object.fromEntries(TRAFFIC_CONTEXTS.map((c) => [c, new Map()]));
  }

  /** Generate an ephemeral, non-extractable ECDH private key. */
  async generateKeyPair() {
    this.keyPair = await generateEcdhKeyPair();
    this._myPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', this.keyPair.publicKey));
    return this._myPubRaw;
  }

  generateKemKeys() {
    this._kemKeys = ml_kem768.keygen();
    this._kemPubRaw = this._kemKeys.publicKey;
    return this._kemPubRaw;
  }

  kemEncapsulate(peerKemPubRaw) {
    if (!(peerKemPubRaw instanceof Uint8Array) || peerKemPubRaw.length !== 1184) {
      throw new Error('Invalid ML-KEM public key');
    }
    return ml_kem768.encapsulate(peerKemPubRaw);
  }

  kemDecapsulate(cipherText) {
    if (!this._kemKeys) throw new Error('No KEM keypair');
    if (!(cipherText instanceof Uint8Array) || cipherText.length !== 1088) {
      throw new Error('Invalid ML-KEM ciphertext');
    }
    return ml_kem768.decapsulate(cipherText, this._kemKeys.secretKey);
  }

  /**
   * Establish epoch 0. `role` is `e` (KEM encapsulator) or `d`
   * (decapsulator); `transcript` is the canonical, role-ordered full handshake.
   */
  async deriveSession(peerPubRaw, kemShared, transcript, role) {
    if (!['e', 'd'].includes(role)) throw new Error('Invalid handshake role');
    if (!(kemShared instanceof Uint8Array) || kemShared.length !== 32) {
      throw new Error('Invalid ML-KEM shared secret');
    }
    if (!(transcript instanceof Uint8Array) || transcript.length === 0) {
      throw new Error('Invalid handshake transcript');
    }

    let ecdhSecret;
    let ikm;
    try {
      ecdhSecret = new Uint8Array(await this._ecdh(this.keyPair?.privateKey, peerPubRaw));
      ikm = concatBytes(ecdhSecret, kemShared);
      const salt = await crypto.subtle.digest('SHA-256', transcript);
      // Kept so an opt-in identity can sign exactly this session. It is derived
      // from public handshake values and is not secret.
      this.transcriptHash = new Uint8Array(salt);

      const eToD = await this._deriveTrafficKeys(ikm, salt, 'encapsulator-to-decapsulator', 0);
      const dToE = await this._deriveTrafficKeys(ikm, salt, 'decapsulator-to-encapsulator', 0);
      this.sendEpochs.set(0, role === 'e' ? eToD : dToE);
      this.recvEpochs.set(0, role === 'e' ? dToE : eToD);
      this.sendEpoch = 0;

      this._sasSecret = await this._hkdfBytes(ikm, salt, 'deaddrop/v5/sas', 16);
      this._confirmSecret = await this._hkdfBytes(ikm, salt, 'deaddrop/v5/confirm', 32);
      this._rootSecret = await this._hkdfBytes(ikm, salt, 'deaddrop/v5/root/epoch/0', 32);
    } finally {
      if (ecdhSecret) ecdhSecret.fill(0);
      if (ikm) ikm.fill(0);
      kemShared.fill(0);
      this.keyPair = null;
      this._discardKemKeys();
    }
  }

  async confirmTag(role) {
    if (!this._confirmSecret) throw new Error('No session established');
    if (!['e', 'd'].includes(role)) throw new Error('Invalid confirmation role');
    return this._hkdfBytes(
      this._confirmSecret,
      new Uint8Array(32),
      `deaddrop/v5/confirm/${role}`,
      16,
    );
  }

  /** Drop handshake-only material after both key-confirmation tags match. */
  finishHandshake() {
    if (this._confirmSecret) this._confirmSecret.fill(0);
    this._confirmSecret = null;
    if (this._myPubRaw) this._myPubRaw.fill(0);
    this._myPubRaw = null;
    this.keyPair = null;
    this._discardKemKeys();
  }

  computeSAS() {
    if (!this._sasSecret) throw new Error('No session established');
    let sas = '';
    for (let i = 0; i < SAS_LENGTH; i++) {
      sas += SAS_EMOJI[this._sasSecret[i] % SAS_EMOJI.length];
    }
    return sas;
  }

  computeSASToken() {
    if (!this._sasSecret) throw new Error('No session established');
    let hex = '';
    for (const byte of this._sasSecret) hex += byte.toString(16).padStart(2, '0');
    return hex;
  }

  get established() {
    return this.sendEpoch >= 0
      && this.sendEpochs.has(this.sendEpoch)
      && this.recvEpochs.has(this.sendEpoch);
  }

  /* ── Authenticated DH ratchet ── */

  async beginRekey() {
    if (!this.established) throw new Error('No session established');
    if (this._pendingRekey) throw new Error('Rekey already in progress');
    const epoch = this.sendEpoch + 1;
    const kp = await generateEcdhKeyPair();
    const myPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    this._pendingRekey = { epoch, keyPair: kp, myPubRaw };
    return { epoch, publicKey: bufToB64(myPubRaw) };
  }

  async acceptRekey(peerPubB64, epoch) {
    if (this._pendingRekey) throw new Error('Conflicting rekey in progress');
    this._requireNextEpoch(epoch);
    const peerPubRaw = decodePublicKey(peerPubB64);
    const kp = await generateEcdhKeyPair();
    const myPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    try {
      await this._installRatchetKeys(kp.privateKey, myPubRaw, peerPubRaw, epoch, 'answerer');
      return { epoch, publicKey: bufToB64(myPubRaw) };
    } finally {
      myPubRaw.fill(0);
      peerPubRaw.fill(0);
    }
  }

  async completeRekey(peerPubB64, epoch) {
    if (!this._pendingRekey || this._pendingRekey.epoch !== epoch) {
      throw new Error('No matching pending rekey');
    }
    const peerPubRaw = decodePublicKey(peerPubB64);
    const { keyPair, myPubRaw } = this._pendingRekey;
    try {
      this._requireNextEpoch(epoch);
      await this._installRatchetKeys(
        keyPair.privateKey,
        myPubRaw,
        peerPubRaw,
        epoch,
        'offerer',
      );
    } finally {
      myPubRaw.fill(0);
      peerPubRaw.fill(0);
      this._pendingRekey = null;
    }
  }

  async _installRatchetKeys(privateKey, myPubRaw, peerPubRaw, epoch, role) {
    if (compareBytes(myPubRaw, peerPubRaw) === 0) throw new Error('Reflected rekey public key');
    const offerPub = role === 'offerer' ? myPubRaw : peerPubRaw;
    const answerPub = role === 'answerer' ? myPubRaw : peerPubRaw;
    let ecdhSecret;
    let ikm;
    try {
      ecdhSecret = new Uint8Array(await this._ecdh(privateKey, peerPubRaw));
      ikm = concatBytes(this._rootSecret, ecdhSecret);
      const ratchetTranscript = concatBytes(
        enc.encode(`deaddrop/v5/ratchet/epoch/${epoch}\0`),
        offerPub,
        answerPub,
      );
      const salt = await crypto.subtle.digest('SHA-256', ratchetTranscript);
      const offerToAnswer = await this._deriveTrafficKeys(
        ikm, salt, 'offerer-to-answerer', epoch,
      );
      const answerToOffer = await this._deriveTrafficKeys(
        ikm, salt, 'answerer-to-offerer', epoch,
      );
      const nextRoot = await this._hkdfBytes(
        ikm, salt, `deaddrop/v5/root/epoch/${epoch}`, 32,
      );

      this.sendEpochs.set(epoch, role === 'offerer' ? offerToAnswer : answerToOffer);
      this.recvEpochs.set(epoch, role === 'offerer' ? answerToOffer : offerToAnswer);
      if (this._rootSecret) this._rootSecret.fill(0);
      this._rootSecret = nextRoot;
      this.sendEpoch = epoch;
      this._pruneEpochs(epoch);
    } finally {
      if (ecdhSecret) ecdhSecret.fill(0);
      if (ikm) ikm.fill(0);
    }
  }

  /* ── Text messages ── */

  async encrypt(plaintext) {
    const epoch = this.sendEpoch;
    const body = enc.encode(JSON.stringify({ text: plaintext, ts: Date.now() }));
    const { ciphertext, iv } = await this._encryptBytes(body, 'text', epoch);
    return { ciphertext: bufToB64(ciphertext), iv: bufToB64(iv), epoch };
  }

  async decrypt(ciphertextB64, ivB64, epoch) {
    const plain = await this._decryptBytes(ciphertextB64, ivB64, epoch, 'text');
    const envelope = JSON.parse(dec.decode(plain));
    return envelope.text;
  }

  /* ── Sealed envelopes (all post-handshake channel traffic) ── */

  async seal(obj, epoch = this.sendEpoch) {
    this._requireEpoch(epoch);
    const ts = Date.now();
    const bareBytes = enc.encode(JSON.stringify({ msg: obj, ts, pad: '' })).byteLength;
    const envelope = JSON.stringify({
      msg: obj,
      ts,
      pad: 'x'.repeat(padBucket(bareBytes) - bareBytes),
    });
    const { ciphertext, iv } = await this._encryptBytes(
      enc.encode(envelope), 'sealed', epoch,
    );
    return { ciphertext: bufToB64(ciphertext), iv: bufToB64(iv), epoch };
  }

  async open(ciphertextB64, ivB64, epoch) {
    const plain = await this._decryptBytes(ciphertextB64, ivB64, epoch, 'sealed');
    const envelope = JSON.parse(dec.decode(plain));
    return envelope.msg;
  }

  /* ── Binary (files) ── */

  async encryptBinary(data) {
    const epoch = this.sendEpoch;
    const bytes = data instanceof ArrayBuffer
      ? new Uint8Array(data)
      : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    const { ciphertext, iv } = await this._encryptBytes(bytes, 'binary', epoch);
    return { ciphertext, iv: bufToB64(iv), epoch };
  }

  async decryptBinary(ciphertextBuf, ivB64, epoch) {
    const plain = await this._decryptBytes(ciphertextBuf, ivB64, epoch, 'binary');
    return plain.buffer.slice(plain.byteOffset, plain.byteOffset + plain.byteLength);
  }

  destroy() {
    this.keyPair = null;
    if (this._myPubRaw) this._myPubRaw.fill(0);
    this._myPubRaw = null;
    this._discardKemKeys();
    for (const b of [this._rootSecret, this._sasSecret, this._confirmSecret]) {
      if (b) b.fill(0);
    }
    this._rootSecret = null;
    this._sasSecret = null;
    this._confirmSecret = null;
    this.transcriptHash = null;
    if (this._pendingRekey?.myPubRaw) this._pendingRekey.myPubRaw.fill(0);
    this._pendingRekey = null;
    this.sendEpochs.clear();
    this.recvEpochs.clear();
    this.sendEpoch = -1;
    for (const context of TRAFFIC_CONTEXTS) this._seenIVs[context].clear();
  }

  /* ── Private helpers ── */

  async _encryptBytes(data, context, epoch) {
    const key = this._sendKey(context, epoch);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: this._aad(context, epoch),
      },
      key,
      data,
    );
    return { ciphertext, iv };
  }

  async _decryptBytes(ciphertext, ivB64, epoch, context) {
    this._requireEpoch(epoch);
    const key = this._recvKey(context, epoch);
    const iv = decodeIV(ivB64);
    const ivKey = bufToB64(iv);
    this._checkReplay(context, epoch, ivKey);

    const ciphertextBytes = typeof ciphertext === 'string'
      ? b64ToBuf(ciphertext)
      : ciphertext;
    const plain = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: this._aad(context, epoch),
      },
      key,
      ciphertextBytes,
    );
    this._markAuthenticatedIV(context, epoch, ivKey);
    return new Uint8Array(plain);
  }

  _sendKey(context, epoch) {
    const key = this.sendEpochs.get(epoch)?.[context];
    if (!key) throw new Error('No sending key for epoch and context');
    return key;
  }

  _recvKey(context, epoch) {
    const key = this.recvEpochs.get(epoch)?.[context];
    if (!key) throw new Error('Unknown receiving key epoch — message dropped');
    return key;
  }

  _aad(context, epoch) {
    return enc.encode(`deaddrop/v5/aead/${context}/epoch/${epoch}`);
  }

  _checkReplay(context, epoch, ivKey) {
    const set = this._seenIVs[context].get(epoch);
    if (set?.has(ivKey)) throw new Error('Replay attack detected — duplicate IV');
    if (set && set.size >= MAX_IVS_PER_EPOCH) {
      throw new Error('Replay tracking capacity exceeded');
    }
  }

  _markAuthenticatedIV(context, epoch, ivKey) {
    let set = this._seenIVs[context].get(epoch);
    if (!set) {
      set = new Set();
      this._seenIVs[context].set(epoch, set);
    }
    if (set.has(ivKey)) throw new Error('Replay attack detected — duplicate IV');
    if (set.size >= MAX_IVS_PER_EPOCH) throw new Error('Replay tracking capacity exceeded');
    set.add(ivKey);
  }

  _requireEpoch(epoch) {
    if (!Number.isSafeInteger(epoch) || epoch < 0) throw new Error('Invalid key epoch');
  }

  _requireNextEpoch(epoch) {
    this._requireEpoch(epoch);
    if (epoch !== this.sendEpoch + 1) throw new Error('Unexpected rekey epoch');
  }

  _pruneEpochs(current) {
    for (const epochs of [this.sendEpochs, this.recvEpochs]) {
      for (const epoch of epochs.keys()) {
        if (epoch <= current - RETAINED_EPOCHS) epochs.delete(epoch);
      }
    }
    for (const context of TRAFFIC_CONTEXTS) {
      for (const epoch of this._seenIVs[context].keys()) {
        if (epoch <= current - RETAINED_EPOCHS) this._seenIVs[context].delete(epoch);
      }
    }
  }

  async _ecdh(privateKey, peerPubRaw) {
    if (!privateKey) throw new Error('No ECDH private key');
    if (!(peerPubRaw instanceof Uint8Array)
        || peerPubRaw.length !== 65
        || peerPubRaw[0] !== 4) {
      throw new Error('Invalid P-256 public key');
    }
    const peerKey = await crypto.subtle.importKey(
      'raw', peerPubRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, [],
    );
    return crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, privateKey, 256);
  }

  async _deriveTrafficKeys(secret, salt, direction, epoch) {
    const entries = await Promise.all(TRAFFIC_CONTEXTS.map(async (context) => [
      context,
      await this._hkdfAesKey(
        secret,
        salt,
        `deaddrop/v5/aead/${direction}/${context}/epoch/${epoch}`,
      ),
    ]));
    return Object.fromEntries(entries);
  }

  async _hkdfBytes(secret, salt, info, length) {
    const base = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) },
      base,
      length * 8,
    );
    return new Uint8Array(bits);
  }

  async _hkdfAesKey(secret, salt, info) {
    const base = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }

  _discardKemKeys() {
    if (this._kemKeys) {
      this._kemKeys.secretKey.fill(0);
      this._kemKeys.publicKey.fill(0);
    }
    this._kemKeys = null;
    this._kemPubRaw = null;
  }
}

async function generateEcdhKeyPair() {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
}

function decodePublicKey(value) {
  if (typeof value !== 'string') throw new Error('Invalid rekey public key');
  let raw;
  try {
    raw = new Uint8Array(b64ToBuf(value));
  } catch {
    throw new Error('Invalid rekey public key');
  }
  if (raw.length !== 65 || raw[0] !== 4) throw new Error('Invalid rekey public key');
  return raw;
}

function decodeIV(value) {
  if (typeof value !== 'string') throw new Error('Invalid AES-GCM IV');
  let iv;
  try {
    iv = new Uint8Array(b64ToBuf(value));
  } catch {
    throw new Error('Invalid AES-GCM IV');
  }
  if (iv.length !== 12) throw new Error('Invalid AES-GCM IV');
  return iv;
}

function concatBytes(...arrs) {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const arr of arrs) {
    const bytes = new Uint8Array(arr);
    out.set(bytes, off);
    off += bytes.length;
  }
  return out;
}

function padBucket(n) {
  for (const bucket of PAD_BUCKETS) {
    if (n <= bucket) return bucket;
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
