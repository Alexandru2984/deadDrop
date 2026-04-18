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
    this._maxNonces = 10000;     // cap to prevent memory leak
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
      true, // extractable so we can compute SAS fingerprint
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Compute a Short Authentication String (SAS) from the shared key.
   * Both peers derive the same SAS — users can compare to detect MitM.
   * Returns a 4-emoji string (16,777,216 combinations — 64^4).
   */
  async computeSAS() {
    if (!this.sharedKey) throw new Error('No shared key established');
    const raw = await crypto.subtle.exportKey('raw', this.sharedKey);
    const hash = await crypto.subtle.digest('SHA-256', raw);
    const bytes = new Uint8Array(hash);
    // Use first 8 bytes to pick 4 emoji from a set of 64
    const emoji = [
      '🐶','🐱','🐭','🐹','🐰','🦊','🐻','🐼',
      '🐨','🐯','🦁','🐮','🐷','🐸','🐵','🐔',
      '🐧','🐦','🐤','🦆','🦅','🦉','🦇','🐺',
      '🐗','🐴','🦄','🐝','🐛','🦋','🐌','🐞',
      '🍎','🍐','🍊','🍋','🍌','🍉','🍇','🍓',
      '🍈','🍒','🍑','🥭','🍍','🥥','🥝','🍅',
      '🌵','🌲','🌴','🌿','🍀','🌺','🌻','🌹',
      '🔥','⚡','❄️','🌊','💎','🔑','🎯','💀',
    ];
    let sas = '';
    for (let i = 0; i < 4; i++) {
      sas += emoji[bytes[i] % emoji.length];
    }
    return sas;
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
    // Evict oldest nonces if the set grows too large
    if (this.seenNonces.size > this._maxNonces) {
      const first = this.seenNonces.values().next().value;
      this.seenNonces.delete(first);
    }

    return envelope.text;
  }

  /**
   * Encrypt raw binary data (for files).
   * Prepends an 8-byte random nonce to the plaintext before encryption
   * for application-layer replay protection (defense-in-depth over DTLS).
   * Returns { ciphertext: ArrayBuffer, iv: base64 }.
   */
  async encryptBinary(data) {
    if (!this.sharedKey) throw new Error('No shared key established');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const nonce = crypto.getRandomValues(new Uint8Array(8));
    // Prepend nonce to data
    const withNonce = new Uint8Array(nonce.length + data.byteLength);
    withNonce.set(nonce, 0);
    withNonce.set(new Uint8Array(data), nonce.length);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.sharedKey,
      withNonce,
    );
    return { ciphertext, iv: bufToB64(iv) };
  }

  /**
   * Decrypt raw binary data (for files).
   * Strips the 8-byte nonce prefix added during encryption.
   * Returns ArrayBuffer.
   */
  async decryptBinary(ciphertextBuf, ivB64) {
    if (!this.sharedKey) throw new Error('No shared key established');
    const withNonce = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBuf(ivB64) },
      this.sharedKey,
      ciphertextBuf,
    );
    // Strip the 8-byte nonce prefix
    return withNonce.slice(8);
  }

  /** Destroy all key material. */
  destroy() {
    this.keyPair = null;
    this.sharedKey = null;
    this.seenNonces.clear();
  }
}


