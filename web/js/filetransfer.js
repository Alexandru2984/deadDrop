/**
 * Dead Drop — bounded, peer-scoped file transfer.
 *
 * File bytes and metadata are encrypted before they enter sealed data-channel
 * messages. Receiver allocations are reserved up front against a global budget,
 * and transfer IDs are scoped to the authenticated peer that created them.
 */

const CHUNK_SIZE = 48 * 1024;
const MAX_FILE_SIZE = 25 * 1024 * 1024;
const MAX_ENCRYPTED_FILE_SIZE = MAX_FILE_SIZE + 16; // AES-GCM tag
const MAX_ACTIVE_INBOUND = 4;
const MAX_RESERVED_INBOUND_BYTES = MAX_ENCRYPTED_FILE_SIZE * 2;
const MAX_ACTIVE_OUTBOUND = 1;
const BUFFER_HIGH = 1024 * 1024;
const BUFFER_WAIT_TIMEOUT = 30 * 1000;
const INBOUND_TIMEOUT = 2 * 60 * 1000;
const MESSAGE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export { MAX_FILE_SIZE };

/**
 * Bind authenticated file metadata to the bytes that were actually received.
 * A verified but malicious peer must not be able to under-report a Blob's size
 * and bypass MessageManager's retained-memory budget.
 */
export function assertFileSizeBinding(fileSize, encryptedSize, plaintextSize = undefined) {
  if (!Number.isSafeInteger(fileSize) || fileSize < 0 || fileSize > MAX_FILE_SIZE) {
    throw new Error('Invalid declared file size');
  }
  if (!Number.isSafeInteger(encryptedSize) || encryptedSize !== fileSize + 16) {
    throw new Error('Encrypted file size does not match metadata');
  }
  if (plaintextSize !== undefined
      && (!Number.isSafeInteger(plaintextSize) || plaintextSize !== fileSize)) {
    throw new Error('Decrypted file size does not match metadata');
  }
}

export class FileTransferManager {
  constructor() {
    this.inbound = new Map();
    this.outbound = new Map();
    this._reservedInboundBytes = 0;
  }

  async send(file, id, cryptoLayer, peer, ttl, burn, onProgress, scope = '') {
    if (!this._validID(id)) throw new Error('Invalid file transfer ID');
    if (!Number.isSafeInteger(file?.size) || file.size < 0 || file.size > MAX_FILE_SIZE) {
      throw new Error(`File too large (max ${MAX_FILE_SIZE / 1024 / 1024} MB)`);
    }
    if (this.outbound.size >= MAX_ACTIVE_OUTBOUND) {
      throw new Error('Another file transfer is already active');
    }
    const key = this._key(scope, id);
    if (this.outbound.has(key)) throw new Error('Duplicate outbound transfer ID');
    this.outbound.set(key, { aborted: false });

    let plaintext;
    let encrypted;
    try {
      plaintext = new Uint8Array(await file.arrayBuffer());
      const fileEnvelope = await cryptoLayer.encryptBinary(plaintext);
      encrypted = new Uint8Array(fileEnvelope.ciphertext);
      plaintext.fill(0);
      plaintext = null;

      const metaEnvelope = await cryptoLayer.encrypt(JSON.stringify({
        fileName: String(file.name || 'file').slice(0, 180),
        fileType: String(file.type || 'application/octet-stream').slice(0, 100),
        fileSize: file.size,
      }));
      const totalChunks = Math.ceil(encrypted.length / CHUNK_SIZE);

      if (this.outbound.get(key)?.aborted) return;

      await peer.send({
        type: 'file',
        id,
        meta: metaEnvelope,
        fileIv: fileEnvelope.iv,
        fileEpoch: fileEnvelope.epoch,
        totalChunks,
        totalSize: encrypted.length,
        ttl,
        burnAfterReading: burn,
      });

      for (let index = 0; index < totalChunks; index++) {
        if (this.outbound.get(key)?.aborted) return;
        await this._waitForBuffer(peer);
        const start = index * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, encrypted.length);
        await peer.send({
          type: 'file-chunk',
          id,
          index,
          data: uint8ToB64(encrypted.subarray(start, end)),
        });
        if (onProgress) onProgress(index + 1, totalChunks);
      }

      if (!this.outbound.get(key)?.aborted) await peer.send({ type: 'file-end', id });
    } finally {
      if (plaintext) plaintext.fill(0);
      if (encrypted) encrypted.fill(0);
      this.outbound.delete(key);
    }
  }

  handleMessage(msg, scope = '') {
    if (!msg || !this._validID(msg.id)) return null;
    const key = this._key(scope, msg.id);
    switch (msg.type) {
      case 'file': return this._onStart(msg, scope, key);
      case 'file-chunk': return this._onChunk(msg, key);
      case 'file-end': return this._onEnd(msg, key);
      default: return null;
    }
  }

  abort(id, scope = '') {
    const key = this._key(scope, id);
    const outbound = this.outbound.get(key);
    if (outbound) outbound.aborted = true;
    this._discardInbound(key);
  }

  abortScope(scope) {
    const prefix = `${scope}\0`;
    for (const [key, transfer] of this.outbound) {
      if (key.startsWith(prefix)) transfer.aborted = true;
    }
    for (const key of [...this.inbound.keys()]) {
      if (key.startsWith(prefix)) this._discardInbound(key);
    }
  }

  destroyAll() {
    for (const transfer of this.outbound.values()) transfer.aborted = true;
    for (const key of [...this.inbound.keys()]) this._discardInbound(key);
  }

  _onStart(msg, scope, key) {
    if (this.inbound.has(key)) {
      console.warn('File transfer rejected: duplicate active id');
      return null;
    }
    if (!Number.isSafeInteger(msg.totalSize)
        || msg.totalSize < 16
        || msg.totalSize > MAX_ENCRYPTED_FILE_SIZE) {
      console.warn('File transfer rejected: invalid totalSize');
      return null;
    }
    const expectedChunks = Math.ceil(msg.totalSize / CHUNK_SIZE);
    if (!Number.isSafeInteger(msg.totalChunks)
        || msg.totalChunks !== expectedChunks) {
      console.warn('File transfer rejected: inconsistent chunk count');
      return null;
    }
    if (!this._validEncryptedMeta(msg.meta)
        || typeof msg.fileIv !== 'string'
        || msg.fileIv.length > 32
        || !Number.isSafeInteger(msg.fileEpoch)
        || msg.fileEpoch < 0) {
      console.warn('File transfer rejected: invalid encrypted metadata');
      return null;
    }
    if (this.inbound.size >= MAX_ACTIVE_INBOUND
        || this._reservedInboundBytes + msg.totalSize > MAX_RESERVED_INBOUND_BYTES) {
      console.warn('File transfer rejected: receiver memory budget exceeded');
      return null;
    }

    let buffer;
    try {
      buffer = new Uint8Array(msg.totalSize);
    } catch {
      console.warn('File transfer rejected: allocation failed');
      return null;
    }
    this._reservedInboundBytes += msg.totalSize;
    const transfer = {
      scope,
      id: msg.id,
      meta: msg.meta,
      fileIv: msg.fileIv,
      fileEpoch: msg.fileEpoch,
      totalChunks: msg.totalChunks,
      totalSize: msg.totalSize,
      ttl: msg.ttl,
      burnAfterReading: msg.burnAfterReading,
      buffer,
      receivedChunks: new Uint8Array(msg.totalChunks),
      received: 0,
      receivedBytes: 0,
      timer: null,
    };
    transfer.timer = setTimeout(() => {
      console.warn(`File transfer ${msg.id} timed out — cleaning up`);
      this._discardInbound(key);
    }, INBOUND_TIMEOUT);
    this.inbound.set(key, transfer);
    return { event: 'start', id: msg.id, scope, totalChunks: msg.totalChunks };
  }

  _onChunk(msg, key) {
    const transfer = this.inbound.get(key);
    if (!transfer) return null;
    if (!Number.isSafeInteger(msg.index)
        || msg.index < 0
        || msg.index >= transfer.totalChunks
        || typeof msg.data !== 'string') {
      console.warn('File chunk rejected: invalid fields');
      return this._failInbound(key, 'Invalid file chunk');
    }
    if (transfer.receivedChunks[msg.index]) {
      return {
        event: 'progress',
        id: transfer.id,
        scope: transfer.scope,
        received: transfer.received,
        totalChunks: transfer.totalChunks,
      };
    }

    const offset = msg.index * CHUNK_SIZE;
    const expectedLength = Math.min(CHUNK_SIZE, transfer.totalSize - offset);
    if (msg.data.length !== 4 * Math.ceil(expectedLength / 3)) {
      console.warn('File chunk rejected: invalid encoded size');
      return this._failInbound(key, 'Invalid file chunk size');
    }
    let chunk;
    try {
      chunk = b64ToUint8(msg.data);
    } catch {
      console.warn('File chunk rejected: invalid base64');
      return this._failInbound(key, 'Invalid file chunk encoding');
    }
    if (chunk.byteLength !== expectedLength) {
      console.warn('File chunk rejected: invalid decoded size');
      chunk.fill(0);
      return this._failInbound(key, 'Invalid file chunk size');
    }

    transfer.buffer.set(chunk, offset);
    chunk.fill(0);
    transfer.receivedChunks[msg.index] = 1;
    transfer.received++;
    transfer.receivedBytes += expectedLength;
    return {
      event: 'progress',
      id: transfer.id,
      scope: transfer.scope,
      received: transfer.received,
      totalChunks: transfer.totalChunks,
    };
  }

  _onEnd(msg, key) {
    const transfer = this.inbound.get(key);
    if (!transfer) return null;
    if (transfer.received !== transfer.totalChunks
        || transfer.receivedBytes !== transfer.totalSize) {
      const id = transfer.id;
      const scope = transfer.scope;
      this._discardInbound(key);
      return { event: 'error', id, scope, error: 'Incomplete or inconsistent transfer' };
    }

    clearTimeout(transfer.timer);
    this.inbound.delete(key);
    this._reservedInboundBytes -= transfer.totalSize;
    return {
      event: 'complete',
      id: transfer.id,
      scope: transfer.scope,
      ciphertext: transfer.buffer.buffer,
      fileIv: transfer.fileIv,
      fileEpoch: transfer.fileEpoch,
      meta: transfer.meta,
      ttl: transfer.ttl,
      burnAfterReading: transfer.burnAfterReading,
    };
  }

  _discardInbound(key) {
    const transfer = this.inbound.get(key);
    if (!transfer) return;
    clearTimeout(transfer.timer);
    transfer.buffer.fill(0);
    this._reservedInboundBytes -= transfer.totalSize;
    this.inbound.delete(key);
  }

  _failInbound(key, error) {
    const transfer = this.inbound.get(key);
    if (!transfer) return null;
    const result = { event: 'error', id: transfer.id, scope: transfer.scope, error };
    this._discardInbound(key);
    return result;
  }

  _waitForBuffer(peer) {
    return new Promise((resolve, reject) => {
      if (!peer.dc || peer.dc.readyState !== 'open') {
        reject(new Error('Data channel closed'));
        return;
      }
      if (peer.dc.bufferedAmount <= BUFFER_HIGH) {
        resolve();
        return;
      }
      peer.dc.bufferedAmountLowThreshold = BUFFER_HIGH / 2;
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error('Data channel backpressure timeout'));
      }, BUFFER_WAIT_TIMEOUT);
      const low = () => { cleanup(); resolve(); };
      const closed = () => { cleanup(); reject(new Error('Data channel closed')); };
      const cleanup = () => {
        clearTimeout(timer);
        peer.dc?.removeEventListener('bufferedamountlow', low);
        peer.dc?.removeEventListener('close', closed);
      };
      peer.dc.addEventListener('bufferedamountlow', low);
      peer.dc.addEventListener('close', closed);
    });
  }

  _key(scope, id) {
    if (typeof scope !== 'string' || scope.length > 128) throw new Error('Invalid peer scope');
    return `${scope}\0${id}`;
  }

  _validID(id) {
    return typeof id === 'string' && MESSAGE_ID_RE.test(id);
  }

  _validEncryptedMeta(meta) {
    return meta
      && typeof meta === 'object'
      && typeof meta.ciphertext === 'string'
      && meta.ciphertext.length > 0
      && meta.ciphertext.length <= 4096
      && typeof meta.iv === 'string'
      && meta.iv.length <= 32
      && Number.isSafeInteger(meta.epoch)
      && meta.epoch >= 0;
  }
}

function uint8ToB64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function b64ToUint8(value) {
  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new Error('Invalid base64');
  }
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
