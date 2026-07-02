/**
 * Dead Drop — Authenticated Hybrid Key Exchange (commit-reveal, ECDH + ML-KEM-768)
 *
 * A man-in-the-middle who relays the WebRTC connection (e.g. a malicious signaling
 * server) could substitute its own keys toward each peer. The Short Authentication
 * String (SAS) lets users detect that out-of-band — but only if the attacker cannot
 * *grind* keys to force both sides to show the same SAS.
 *
 * This commit-reveal handshake removes the attacker's ability to grind: each side
 * publishes H(ecdhPub ‖ kemPub ‖ nonce) BEFORE either side reveals its keys. A relay
 * therefore has to commit to its substituted keys blind, gets exactly one guess at
 * matching the SAS, and succeeds only with probability 2^-36. (ZRTP-style.)
 *
 * The session secret is hybrid: an ECDH (P-256) share AND an ML-KEM-768 (FIPS 203)
 * share, combined in HKDF. Recorded traffic therefore stays confidential even if
 * large quantum computers arrive later — an attacker must break both primitives.
 *
 *   A ── commit_A ──►             ◄── commit_B ── B    (both commit first)
 *   A ── reveal_A ──►             ◄── reveal_B ── B    (reveal only after peer's commit)
 *   both verify H(reveal)==commit; the side with the lexicographically smaller
 *   ECDH key becomes the ENCAPSULATOR:
 *   E ── encaps(ct) ──► D                              (KEM ciphertext)
 *   E ── confirm_e ──►             ◄── confirm_d ── D  (key confirmation)
 *   both verify the peer's confirmation tag, then show the SAS.
 *
 * The explicit confirmation step matters because ML-KEM uses implicit rejection:
 * a tampered ciphertext decapsulates to a *different* secret instead of an error,
 * which without confirmation would surface as confusing decrypt failures later.
 */

import { bufToB64, b64ToBuf } from './util.js';
import { compareBytes } from './crypto.js';

const COMMIT_NONCE_BYTES = 16;
const ECDH_PUB_BYTES = 65;    // uncompressed P-256 point
const KEM_PUB_BYTES = 1184;   // ML-KEM-768 encapsulation key (FIPS 203)
const KEM_CT_BYTES = 1088;    // ML-KEM-768 ciphertext (FIPS 203)

export class Handshake {
  /**
   * @param {CryptoLayer} crypto
   * @param {(msg:object)=>void} send  – sends a JS object over the data channel
   * @param {{onEstablished:(sas:string)=>void, onError:(reason:string)=>void}} cb
   */
  constructor(crypto, send, { onEstablished, onError }) {
    this.crypto = crypto;
    this.send = send;
    this.onEstablished = onEstablished;
    this.onError = onError;
    this._myNonce = null;
    this._peerCommit = null;
    this._revealed = false;
    this._isEncapsulator = false;
    this._awaitingCt = false;
    this._derived = false;
    this._confirmed = false;
    this._done = false;
    this._queue = Promise.resolve(); // serialize async message handling
  }

  /** Generate our keys, publish our commitment. Called once when the channel opens. */
  async start() {
    const myEcdhPub = await this.crypto.generateKeyPair();
    const myKemPub = this.crypto.generateKemKeys();
    this._myNonce = crypto.getRandomValues(new Uint8Array(COMMIT_NONCE_BYTES));
    const commit = await commitment(myEcdhPub, myKemPub, this._myNonce);
    this.send({ type: 'kex-commit', commit: bufToB64(commit) });
  }

  /** Returns true if the message was a handshake message (and was consumed). */
  async handle(msg) {
    if (!['kex-commit', 'kex-reveal', 'kex-encaps', 'kex-confirm'].includes(msg.type)) {
      return false;
    }
    // Chain, so a slow async step never processes two messages concurrently.
    this._queue = this._queue.then(() => this._dispatch(msg)).catch(() => {});
    await this._queue;
    return true;
  }

  async _dispatch(msg) {
    if (msg.type === 'kex-commit') return this._onCommit(msg);
    if (msg.type === 'kex-reveal') return this._onReveal(msg);
    if (msg.type === 'kex-encaps') return this._onEncaps(msg);
    if (msg.type === 'kex-confirm') return this._onConfirm(msg);
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
    // Only now — after the peer has committed — do we reveal our public keys.
    this._revealed = true;
    this.send({
      type: 'kex-reveal',
      publicKey: bufToB64(this.crypto._myPubRaw),
      kemPublicKey: bufToB64(this.crypto._kemPubRaw),
      nonce: bufToB64(this._myNonce),
    });
  }

  async _onReveal(msg) {
    if (this._done || this._derived || this._awaitingCt) return;
    if (!this._peerCommit) return this._fail('reveal before commit');
    if (typeof msg.publicKey !== 'string' || typeof msg.kemPublicKey !== 'string'
        || typeof msg.nonce !== 'string') {
      return this._fail('malformed reveal');
    }
    let peerPub, peerKemPub, peerNonce;
    try {
      peerPub = new Uint8Array(b64ToBuf(msg.publicKey));
      peerKemPub = new Uint8Array(b64ToBuf(msg.kemPublicKey));
      peerNonce = new Uint8Array(b64ToBuf(msg.nonce));
    } catch {
      return this._fail('malformed reveal');
    }
    if (peerPub.length !== ECDH_PUB_BYTES) return this._fail('invalid public key length');
    if (peerKemPub.length !== KEM_PUB_BYTES) return this._fail('invalid KEM key length');

    // The decisive check: the revealed keys must match what the peer committed to.
    const expect = await commitment(peerPub, peerKemPub, peerNonce);
    if (!timingSafeEqual(new Uint8Array(expect), this._peerCommit)) {
      return this._fail('commitment mismatch — possible MitM');
    }

    // Deterministic, symmetric role choice: the smaller ECDH key encapsulates.
    this._isEncapsulator = compareBytes(this.crypto._myPubRaw, peerPub) < 0;
    try {
      if (this._isEncapsulator) {
        const { cipherText, sharedSecret } = this.crypto.kemEncapsulate(peerKemPub);
        this.send({ type: 'kex-encaps', ct: bufToB64(cipherText) });
        // KEM transcript = decapsulator's public key ‖ ciphertext (both known here).
        await this._deriveAndConfirm(peerPub, sharedSecret, concatBytes(peerKemPub, cipherText));
      } else {
        this._peerEcdhPub = peerPub;
        this._awaitingCt = true; // wait for the peer's kex-encaps
      }
    } catch {
      return this._fail('key derivation failed');
    }
  }

  async _onEncaps(msg) {
    if (this._done || this._derived) return;
    if (!this._awaitingCt) return this._fail('unexpected KEM ciphertext');
    if (typeof msg.ct !== 'string') return this._fail('malformed KEM ciphertext');
    let ct;
    try {
      ct = new Uint8Array(b64ToBuf(msg.ct));
    } catch {
      return this._fail('malformed KEM ciphertext');
    }
    if (ct.length !== KEM_CT_BYTES) return this._fail('invalid KEM ciphertext length');
    try {
      const sharedSecret = this.crypto.kemDecapsulate(ct);
      await this._deriveAndConfirm(this._peerEcdhPub, sharedSecret,
        concatBytes(this.crypto._kemPubRaw, ct));
    } catch {
      return this._fail('key derivation failed');
    }
  }

  async _deriveAndConfirm(peerPub, kemShared, kemTranscript) {
    await this.crypto.deriveSession(peerPub, kemShared, kemTranscript);
    this._derived = true;
    this._awaitingCt = false;
    // Prove we hold the session key; the tag is direction-bound so it cannot be
    // reflected back. If the peer's tag never verifies, we never show a SAS.
    const tag = await this.crypto.confirmTag(this._isEncapsulator ? 'e' : 'd');
    this.send({ type: 'kex-confirm', tag: bufToB64(tag) });
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
    if (!this._derived) {
      this._peerConfirm = tag; // encapsulator's confirm can arrive before our derive
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
    this.onEstablished(this.crypto.computeSAS());
  }

  _fail(reason) {
    if (this._done) return;
    this._done = true;
    this.onError(reason);
  }
}

async function commitment(ecdhPub, kemPub, nonce) {
  return crypto.subtle.digest('SHA-256', concatBytes(ecdhPub, kemPub, nonce));
}

function concatBytes(...arrs) {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrs) { out.set(new Uint8Array(a), off); off += a.length; }
  return out;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
