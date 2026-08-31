/**
 * Dead Drop — Authenticated hybrid key exchange (protocol v5)
 *
 * Both parties commit to their ephemeral P-256 key, ML-KEM-768 key, optional
 * long-term identity key and random nonce before revealing them. Binding the
 * identity into the commitment and the transcript means the safety code already
 * authenticates it: a man-in-the-middle who swaps the identity changes the code
 * both users compare. The lexicographically smaller ECDH key becomes
 * the ML-KEM encapsulator. A role-ordered transcript binds both complete reveals
 * and the KEM ciphertext into every derived secret and confirmation tag.
 *
 * The SAS authenticates the otherwise unauthenticated exchange only after users
 * compare it out of band. Until then, encryption protects against passive
 * observers but a malicious signaling/transport service can still interpose.
 */

import { bufToB64, b64ToBuf } from './util.js';
import { compareBytes, PROTOCOL_VERSION } from './crypto.js';

const COMMIT_NONCE_BYTES = 16;
const ECDH_PUB_BYTES = 65;
const IDENTITY_PUB_BYTES = 65;
// A peer that has not opted into saved contacts still occupies the identity slot
// with a fixed all-zero block. Keeping the field a constant size means the
// commitment and transcript are byte-identical in shape either way, so nothing
// about whether the feature is on can be inferred from message lengths.
const NO_IDENTITY = new Uint8Array(IDENTITY_PUB_BYTES);
const KEM_PUB_BYTES = 1184;
const KEM_CT_BYTES = 1088;
const enc = new TextEncoder();

export class Handshake {
  constructor(cryptoLayer, send, { onEstablished, onError, identityPub = null }) {
    this.crypto = cryptoLayer;
    this.send = send;
    this.onEstablished = onEstablished;
    this.onError = onError;
    // Presented only when the user has opted into saved contacts.
    this.identityPub = identityPub instanceof Uint8Array
      && identityPub.length === IDENTITY_PUB_BYTES ? identityPub : NO_IDENTITY;
    this.peerIdentityPub = null;
    this._myNonce = null;
    this._peerCommit = null;
    this._peerRecord = null;
    this._revealed = false;
    this._isEncapsulator = false;
    this._awaitingCt = false;
    this._derived = false;
    this._confirmed = false;
    this._done = false;
    this._queue = Promise.resolve();
  }

  async start() {
    const myEcdhPub = await this.crypto.generateKeyPair();
    const myKemPub = this.crypto.generateKemKeys();
    this._myNonce = crypto.getRandomValues(new Uint8Array(COMMIT_NONCE_BYTES));
    const commit = await commitment(myEcdhPub, myKemPub, this.identityPub, this._myNonce);
    this.send({ type: 'kex-commit', v: PROTOCOL_VERSION, commit: bufToB64(commit) });
  }

  /** Returns true if a key-exchange message was consumed. */
  async handle(msg) {
    if (!msg || !['kex-commit', 'kex-reveal', 'kex-encaps', 'kex-confirm'].includes(msg.type)) {
      return false;
    }
    if (msg.v !== PROTOCOL_VERSION) {
      this._fail('unsupported encryption protocol version');
      return true;
    }
    this._queue = this._queue
      .then(() => this._dispatch(msg))
      .catch(() => this._fail('handshake processing failed'));
    await this._queue;
    return true;
  }

  async _dispatch(msg) {
    if (msg.type === 'kex-commit') return this._onCommit(msg);
    if (msg.type === 'kex-reveal') return this._onReveal(msg);
    if (msg.type === 'kex-encaps') return this._onEncaps(msg);
    return this._onConfirm(msg);
  }

  async _onCommit(msg) {
    if (this._done || this._revealed) return;
    if (typeof msg.commit !== 'string') return this._fail('malformed commitment');
    try {
      this._peerCommit = new Uint8Array(b64ToBuf(msg.commit));
    } catch {
      return this._fail('malformed commitment');
    }
    if (this._peerCommit.length !== 32) return this._fail('bad commitment length');

    this._revealed = true;
    this.send({
      type: 'kex-reveal',
      v: PROTOCOL_VERSION,
      publicKey: bufToB64(this.crypto._myPubRaw),
      kemPublicKey: bufToB64(this.crypto._kemPubRaw),
      identityKey: bufToB64(this.identityPub),
      nonce: bufToB64(this._myNonce),
    });
  }

  async _onReveal(msg) {
    if (this._done || this._derived || this._awaitingCt) return;
    if (!this._peerCommit) return this._fail('reveal before commit');
    if (typeof msg.publicKey !== 'string'
        || typeof msg.kemPublicKey !== 'string'
        || typeof msg.identityKey !== 'string'
        || typeof msg.nonce !== 'string') {
      return this._fail('malformed reveal');
    }

    let peerEcdh, peerKem, peerIdentity, peerNonce;
    try {
      peerEcdh = new Uint8Array(b64ToBuf(msg.publicKey));
      peerKem = new Uint8Array(b64ToBuf(msg.kemPublicKey));
      peerIdentity = new Uint8Array(b64ToBuf(msg.identityKey));
      peerNonce = new Uint8Array(b64ToBuf(msg.nonce));
    } catch {
      return this._fail('malformed reveal');
    }
    if (peerEcdh.length !== ECDH_PUB_BYTES || peerEcdh[0] !== 4) {
      return this._fail('invalid public key');
    }
    if (peerKem.length !== KEM_PUB_BYTES) return this._fail('invalid KEM key length');
    if (peerIdentity.length !== IDENTITY_PUB_BYTES) return this._fail('invalid identity length');
    if (peerNonce.length !== COMMIT_NONCE_BYTES) return this._fail('invalid nonce length');

    const expect = await commitment(peerEcdh, peerKem, peerIdentity, peerNonce);
    if (!timingSafeEqual(new Uint8Array(expect), this._peerCommit)) {
      return this._fail('commitment mismatch — possible MitM');
    }

    const order = compareBytes(this.crypto._myPubRaw, peerEcdh);
    if (order === 0) return this._fail('reflected public key — possible MitM');
    this._isEncapsulator = order < 0;
    this._peerRecord = {
      ecdh: peerEcdh, kem: peerKem, identity: peerIdentity, nonce: peerNonce,
    };
    // Null unless the peer actually presented one; the all-zero slot means
    // "ephemeral only" and must never be pinned as a contact.
    this.peerIdentityPub = isZero(peerIdentity) ? null : peerIdentity;

    try {
      if (this._isEncapsulator) {
        const { cipherText, sharedSecret } = this.crypto.kemEncapsulate(peerKem);
        this.send({
          type: 'kex-encaps',
          v: PROTOCOL_VERSION,
          ct: bufToB64(cipherText),
        });
        const transcript = handshakeTranscript(
          this._myRecord(),
          this._peerRecord,
          cipherText,
        );
        await this._deriveAndConfirm(peerEcdh, sharedSecret, transcript, 'e');
      } else {
        this._awaitingCt = true;
      }
    } catch {
      return this._fail('key derivation failed');
    }
  }

  async _onEncaps(msg) {
    if (this._done || this._derived) return;
    if (!this._awaitingCt || !this._peerRecord) {
      return this._fail('unexpected KEM ciphertext');
    }
    if (typeof msg.ct !== 'string') return this._fail('malformed KEM ciphertext');
    let ciphertext;
    try {
      ciphertext = new Uint8Array(b64ToBuf(msg.ct));
    } catch {
      return this._fail('malformed KEM ciphertext');
    }
    if (ciphertext.length !== KEM_CT_BYTES) {
      return this._fail('invalid KEM ciphertext length');
    }

    try {
      const sharedSecret = this.crypto.kemDecapsulate(ciphertext);
      const transcript = handshakeTranscript(
        this._peerRecord,
        this._myRecord(),
        ciphertext,
      );
      await this._deriveAndConfirm(
        this._peerRecord.ecdh,
        sharedSecret,
        transcript,
        'd',
      );
    } catch {
      return this._fail('key derivation failed');
    }
  }

  async _deriveAndConfirm(peerPub, kemShared, transcript, role) {
    await this.crypto.deriveSession(peerPub, kemShared, transcript, role);
    this._derived = true;
    this._awaitingCt = false;
    const tag = await this.crypto.confirmTag(role);
    this.send({ type: 'kex-confirm', v: PROTOCOL_VERSION, tag: bufToB64(tag) });
    if (this._peerConfirm) await this._checkConfirm(this._peerConfirm);
  }

  async _onConfirm(msg) {
    if (this._done || this._confirmed) return;
    if (typeof msg.tag !== 'string') return this._fail('malformed confirmation');
    let tag;
    try {
      tag = new Uint8Array(b64ToBuf(msg.tag));
    } catch {
      return this._fail('malformed confirmation');
    }
    if (tag.length !== 16) return this._fail('invalid confirmation length');
    if (!this._derived) {
      if (this._peerConfirm) return this._fail('duplicate early confirmation');
      this._peerConfirm = tag;
      return;
    }
    await this._checkConfirm(tag);
  }

  async _checkConfirm(tag) {
    const expect = await this.crypto.confirmTag(this._isEncapsulator ? 'd' : 'e');
    if (!timingSafeEqual(tag, expect)) {
      return this._fail('key confirmation failed — possible MitM');
    }
    this._confirmed = true;
    this._done = true;
    const sas = this.crypto.computeSAS();
    this.crypto.finishHandshake();
    this.onEstablished(sas);
  }

  _myRecord() {
    return {
      ecdh: this.crypto._myPubRaw,
      kem: this.crypto._kemPubRaw,
      identity: this.identityPub,
      nonce: this._myNonce,
    };
  }

  _fail(reason) {
    if (this._done) return;
    this._done = true;
    this.onError(reason);
  }
}

async function commitment(ecdhPub, kemPub, identityPub, nonce) {
  return crypto.subtle.digest(
    'SHA-256',
    concatBytes(enc.encode('deaddrop/v5/commit\0'), ecdhPub, kemPub, identityPub, nonce),
  );
}

function handshakeTranscript(encapsulator, decapsulator, ciphertext) {
  return concatBytes(
    enc.encode('deaddrop/v5/handshake\0'),
    encapsulator.ecdh,
    encapsulator.kem,
    encapsulator.identity,
    encapsulator.nonce,
    decapsulator.ecdh,
    decapsulator.kem,
    decapsulator.identity,
    decapsulator.nonce,
    ciphertext,
  );
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

function isZero(bytes) {
  let acc = 0;
  for (const b of bytes) acc |= b;
  return acc === 0;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
