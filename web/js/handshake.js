/**
 * Dead Drop — Authenticated Key Exchange (commit-reveal)
 *
 * A man-in-the-middle who relays the WebRTC connection (e.g. a malicious signaling
 * server) could substitute its own ECDH keys toward each peer. The Short
 * Authentication String (SAS) lets users detect that out-of-band — but only if the
 * attacker cannot *grind* keys to force both sides to show the same SAS.
 *
 * This commit-reveal handshake removes the attacker's ability to grind: each side
 * publishes H(publicKey ‖ nonce) BEFORE either side reveals its public key. A relay
 * therefore has to commit to its substituted keys blind, gets exactly one guess at
 * matching the SAS, and succeeds only with probability 2^-36. (ZRTP-style.)
 *
 *   A ── commit_A ──►            ◄── commit_B ── B      (both commit first)
 *   A ── reveal_A ──►            ◄── reveal_B ── B      (reveal only after peer's commit)
 *   both verify H(reveal)==commit, derive the session key, compute the SAS.
 */

import { bufToB64, b64ToBuf } from './util.js';

const COMMIT_NONCE_BYTES = 16;

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
    this._done = false;
  }

  /** Generate our key, publish our commitment. Called once when the channel opens. */
  async start() {
    const myPub = await this.crypto.generateKeyPair();
    this._myNonce = crypto.getRandomValues(new Uint8Array(COMMIT_NONCE_BYTES));
    const commit = await commitment(myPub, this._myNonce);
    this.send({ type: 'kex-commit', commit: bufToB64(commit) });
  }

  /** Returns true if the message was a handshake message (and was consumed). */
  async handle(msg) {
    if (msg.type === 'kex-commit') { await this._onCommit(msg); return true; }
    if (msg.type === 'kex-reveal') { await this._onReveal(msg); return true; }
    return false;
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
    // Only now — after the peer has committed — do we reveal our public key.
    this._revealed = true;
    this.send({
      type: 'kex-reveal',
      publicKey: bufToB64(this.crypto._myPubRaw),
      nonce: bufToB64(this._myNonce),
    });
  }

  async _onReveal(msg) {
    if (this._done) return;
    if (!this._peerCommit) return this._fail('reveal before commit');
    if (typeof msg.publicKey !== 'string' || typeof msg.nonce !== 'string') {
      return this._fail('malformed reveal');
    }
    let peerPub, peerNonce;
    try {
      peerPub = new Uint8Array(b64ToBuf(msg.publicKey));
      peerNonce = new Uint8Array(b64ToBuf(msg.nonce));
    } catch {
      return this._fail('malformed reveal');
    }
    if (peerPub.length !== 65) return this._fail('invalid public key length');

    // The decisive check: the revealed key must match what the peer committed to.
    const expect = await commitment(peerPub, peerNonce);
    if (!timingSafeEqual(new Uint8Array(expect), this._peerCommit)) {
      return this._fail('commitment mismatch — possible MitM');
    }

    try {
      await this.crypto.deriveSession(peerPub);
    } catch (e) {
      return this._fail('key derivation failed');
    }
    this._done = true;
    this.onEstablished(this.crypto.computeSAS());
  }

  _fail(reason) {
    if (this._done) return;
    this._done = true;
    this.onError(reason);
  }
}

async function commitment(pubRaw, nonce) {
  const buf = new Uint8Array(pubRaw.length + nonce.length);
  buf.set(new Uint8Array(pubRaw), 0);
  buf.set(nonce, pubRaw.length);
  return crypto.subtle.digest('SHA-256', buf);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
