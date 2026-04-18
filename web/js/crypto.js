/**
 * Dead Drop — Encryption Layer
 *
 * Ephemeral ECDH (P-256) key exchange + AES-256-GCM symmetric encryption.
 * All operations use the Web Crypto API — no external dependencies.
 * Keys are never persisted; a fresh pair is generated per connection.
 */

import { bufToB64, b64ToBuf } from './util.js';

export class CryptoLayer {
  constructor() {
    this.keyPair = null;
    this.sharedKey = null;
    this.seenNonces = new Set(); // replay-attack protection
  }

  /** Generate an ephemeral ECDH key pair and return the raw public key bytes. */
  async generateKeyPair() {
    this.keyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,  // extractable — we need to export the public half
      ['deriveKey']
    );
    return await crypto.subtle.exportKey('raw', this.keyPair.publicKey);
  }

  /** Derive a shared AES-256-GCM key from the peer's raw public key. */
  async deriveSharedKey(peerPublicKeyRaw) {
    const peerKey = await crypto.subtle.importKey(
      'raw',
      peerPublicKeyRaw,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    this.sharedKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: peerKey },
      this.keyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt a plaintext string.
   * Returns { ciphertext: base64, iv: base64 }.
   * A random 96-bit IV and 64-bit nonce are generated per message.
   */
  async encrypt(plaintext) {
    if (!this.sharedKey) throw new Error('No shared key established');

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(8)));

    const envelope = JSON.stringify({
      text: plaintext,
      nonce,
      ts: Date.now(),
    });

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.sharedKey,
      new TextEncoder().encode(envelope)
    );

    return {
      ciphertext: bufToB64(ciphertext),
      iv: bufToB64(iv),
    };
  }

  /** Decrypt and verify a message. Throws on replay or tamper. */
  async decrypt(ciphertextB64, ivB64) {
    if (!this.sharedKey) throw new Error('No shared key established');

    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBuf(ivB64) },
      this.sharedKey,
      b64ToBuf(ciphertextB64)
    );

    const envelope = JSON.parse(new TextDecoder().decode(plainBuf));

    // Replay protection — reject duplicate nonces
    const nonceKey = envelope.nonce.join(',');
    if (this.seenNonces.has(nonceKey)) {
      throw new Error('Replay attack detected — duplicate nonce');
    }
    this.seenNonces.add(nonceKey);

    return envelope.text;
  }

  /** Encrypt raw binary data (for files). Returns { ciphertext: ArrayBuffer, iv: base64 }. */
  async encryptBinary(data) {
    if (!this.sharedKey) throw new Error('No shared key established');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.sharedKey,
      data,
    );
    return { ciphertext, iv: bufToB64(iv) };
  }

  /** Decrypt raw binary data (for files). Returns ArrayBuffer. */
  async decryptBinary(ciphertextBuf, ivB64) {
    if (!this.sharedKey) throw new Error('No shared key established');
    return await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBuf(ivB64) },
      this.sharedKey,
      ciphertextBuf,
    );
  }

  /** Destroy all key material. */
  destroy() {
    this.keyPair = null;
    this.sharedKey = null;
    this.seenNonces.clear();
  }
}


