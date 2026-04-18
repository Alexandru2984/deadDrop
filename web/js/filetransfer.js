/**
 * Dead Drop — File Transfer Layer
 *
 * Chunked file transfers over the WebRTC data channel.
 * Files are encrypted with AES-256-GCM before chunking so the
 * plaintext never touches the wire.
 *
 * Flow:  encrypt whole file → chunk ciphertext → send chunks
 *        receive chunks → reassemble → decrypt → display
 */

const CHUNK_SIZE = 48 * 1024;   // 48 KB raw → ~64 KB base64
const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB
const BUFFER_HIGH = 1024 * 1024; // pause sending above 1 MB buffered

export { MAX_FILE_SIZE };

export class FileTransferManager {
  constructor() {
    this.inbound  = new Map(); // id → { meta, chunks[], received, … }
    this.outbound = new Map(); // id → { aborted }
  }

  /**
   * Encrypt and send a file in chunks.
   *
   * @param {File}            file
   * @param {string}          id          – message ID
   * @param {CryptoLayer}     crypto
   * @param {PeerConnection}  peer
   * @param {number}          ttl
   * @param {boolean}         burn
   * @param {Function}        onProgress  – (sentChunks, totalChunks)
   */
  async send(file, id, crypto, peer, ttl, burn, onProgress) {
    if (file.size > MAX_FILE_SIZE) {
      throw new Error(`File too large (max ${MAX_FILE_SIZE / 1024 / 1024} MB)`);
    }

    const data = await file.arrayBuffer();

    // Encrypt file content
    const { ciphertext, iv: fileIv } = await crypto.encryptBinary(data);

    // Encrypt metadata (file name, type, size)
    const metaStr = JSON.stringify({
      fileName: file.name,
      fileType: file.type || 'application/octet-stream',
      fileSize: file.size,
    });
    const encMeta = await crypto.encrypt(metaStr);

    // Chunk the ciphertext
    const bytes = new Uint8Array(ciphertext);
    const totalChunks = Math.ceil(bytes.length / CHUNK_SIZE);

    // 1. File header
    peer.send({
      type: 'file',
      id,
      meta: encMeta,
      fileIv,
      totalChunks,
      totalSize: bytes.length,
      ttl,
      burnAfterReading: burn,
    });

    this.outbound.set(id, { aborted: false });

    // 2. Chunks (with backpressure)
    for (let i = 0; i < totalChunks; i++) {
      if (this.outbound.get(id)?.aborted) break;

      const start = i * CHUNK_SIZE;
      const end   = Math.min(start + CHUNK_SIZE, bytes.length);

      await this._waitForBuffer(peer);

      peer.send({
        type: 'file-chunk',
        id,
        index: i,
        data: _uint8ToB64(bytes.slice(start, end)),
      });

      if (onProgress) onProgress(i + 1, totalChunks);
    }

    // 3. End marker
    peer.send({ type: 'file-end', id });
    this.outbound.delete(id);
  }

  /**
   * Process an incoming file-related message.
   * @returns {{ event, id, … } | null}
   */
  handleMessage(msg) {
    switch (msg.type) {
      case 'file':       return this._onStart(msg);
      case 'file-chunk': return this._onChunk(msg);
      case 'file-end':   return this._onEnd(msg);
      default: return null;
    }
  }

  abort(id) {
    const out = this.outbound.get(id);
    if (out) out.aborted = true;
    this.inbound.delete(id);
    this.outbound.delete(id);
  }

  /* ── Private ── */

  _onStart(msg) {
    // Validate totalSize to prevent memory exhaustion from malicious peers
    // Encrypted size can be slightly larger than MAX_FILE_SIZE due to AES-GCM overhead
    const maxEncryptedSize = MAX_FILE_SIZE + 1024 * 1024; // 26 MB
    if (!msg.totalSize || msg.totalSize > maxEncryptedSize || msg.totalSize < 0) {
      console.warn('File transfer rejected: invalid totalSize', msg.totalSize);
      return null;
    }
    if (!msg.totalChunks || msg.totalChunks < 1 || msg.totalChunks > Math.ceil(maxEncryptedSize / CHUNK_SIZE) + 1) {
      console.warn('File transfer rejected: invalid totalChunks', msg.totalChunks);
      return null;
    }
    this.inbound.set(msg.id, {
      meta:            msg.meta,
      fileIv:          msg.fileIv,
      totalChunks:     msg.totalChunks,
      totalSize:       msg.totalSize,
      ttl:             msg.ttl,
      burnAfterReading: msg.burnAfterReading,
      chunks:          new Array(msg.totalChunks),
      received:        0,
    });
    return { event: 'start', id: msg.id, totalChunks: msg.totalChunks };
  }

  _onChunk(msg) {
    const t = this.inbound.get(msg.id);
    if (!t) return null;
    // Validate chunk index to prevent sparse array attacks
    if (typeof msg.index !== 'number' || msg.index < 0 || msg.index >= t.totalChunks) {
      console.warn('File chunk rejected: invalid index', msg.index);
      return null;
    }
    t.chunks[msg.index] = _b64ToUint8(msg.data);
    t.received++;
    return { event: 'progress', id: msg.id, received: t.received, totalChunks: t.totalChunks };
  }

  _onEnd(msg) {
    const t = this.inbound.get(msg.id);
    if (!t) return null;

    // Reassemble ciphertext
    let offset = 0;
    const buf = new Uint8Array(t.totalSize);
    for (const chunk of t.chunks) {
      if (chunk) { buf.set(chunk, offset); offset += chunk.length; }
    }

    const result = {
      event:           'complete',
      id:              msg.id,
      ciphertext:      buf.buffer,
      fileIv:          t.fileIv,
      meta:            t.meta,
      ttl:             t.ttl,
      burnAfterReading: t.burnAfterReading,
    };
    this.inbound.delete(msg.id);
    return result;
  }

  /** Pause until the data-channel send buffer drains below threshold. */
  _waitForBuffer(peer) {
    return new Promise((resolve) => {
      if (!peer.dc || peer.dc.bufferedAmount <= BUFFER_HIGH) { resolve(); return; }
      peer.dc.bufferedAmountLowThreshold = BUFFER_HIGH / 2;
      const handler = () => { peer.dc.removeEventListener('bufferedamountlow', handler); resolve(); };
      peer.dc.addEventListener('bufferedamountlow', handler);
    });
  }
}

/* ── Base64 helpers (keep local to avoid import cycle) ── */

function _uint8ToB64(u8) {
  let bin = '';
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

function _b64ToUint8(b64) {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}
