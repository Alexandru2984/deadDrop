/**
 * Dead Drop — file transfer, streamed in sealed parts.
 *
 * A file goes as an offer, then numbered parts, then an end marker, all inside
 * the pair's sealed channel. Each part is encrypted on its own with its place
 * in the file bound into it (CryptoLayer.encryptPart), so neither side holds
 * more than a few megabytes of it in script memory: the sender reads it from
 * disk one part at a time, and the receiver hands what it decrypts to the
 * browser as Blobs, which the browser may keep on disk rather than in memory.
 *
 * Nothing but the offer is sent before the receiver says yes. Files up to
 * AUTO_ACCEPT_SIZE — the old limit — are accepted by the receiving client at
 * once, as before; anything larger waits until the person accepts it, so
 * nobody has a gigabyte pushed at them over mobile data unasked.
 *
 * Transfer IDs are scoped to the authenticated peer that created them, and
 * everything a peer can make this side hold is counted against a budget.
 */

import { MAX_BYTES_PER_WINDOW, MAX_MESSAGES_PER_WINDOW, TRAFFIC_WINDOW_MS } from './peer.js';

export const PART_SIZE = 64 * 1024;
export const MAX_FILE_SIZE = 1024 * 1024 * 1024;
export const AUTO_ACCEPT_SIZE = 25 * 1024 * 1024;
const GCM_TAG = 16;

// ── Receiving ──
const MAX_ACTIVE_INBOUND = 4;
// Declared bytes arriving at once: one large file, accepted by hand, and a
// couple of ordinary ones beside it.
const MAX_INBOUND_BYTES = MAX_FILE_SIZE + 2 * AUTO_ACCEPT_SIZE;
const MAX_PENDING_OFFERS = 8;
// How long an offer waits for an answer. The sender gives up at the same time.
export const OFFER_TTL = 10 * 60 * 1000;
// A transfer that stops arriving for this long is dropped.
const INBOUND_IDLE_TIMEOUT = 60 * 1000;
// Decrypted parts become a Blob every this many bytes, so they leave script
// memory instead of piling up there until the end.
const FLUSH_BYTES = 4 * 1024 * 1024;

// ── Sending ──
const MAX_ACTIVE_OUTBOUND = 12;
// A small file is answered as soon as it is offered. No answer means a client
// too old to know offers, and there is no point waiting ten minutes for it.
const AUTO_ANSWER_WAIT = 30 * 1000;
const BUFFER_HIGH = 1024 * 1024;
const BUFFER_WAIT_TIMEOUT = 30 * 1000;
// The receiver ends a connection that sends more than its traffic limit
// (peer.js). A sender keeps well under it: the two sides' windows are not
// aligned, so one receiver window can see two of the sender's, and chat,
// rekeys and cover traffic share the same allowance.
const PACE_BYTES = Math.floor(MAX_BYTES_PER_WINDOW * 0.4);
const PACE_MESSAGES = Math.floor(MAX_MESSAGES_PER_WINDOW * 0.4);
export const SEND_PACE = Object.freeze({ bytes: PACE_BYTES, messages: PACE_MESSAGES });
// Upper bound of one part on the wire: the part, its tag, base64, the sealed
// envelope's padding and base64 again. Checked against the real thing in the
// self-test.
export const MAX_PART_WIRE_BYTES = 140 * 1024;

const MESSAGE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

// The types a received file may keep. Everything else becomes an opaque
// download. The declared type is the peer's word, and the browser believes it:
// a Blob labelled text/html or image/svg+xml, opened from its blob: URL ("open
// link in new tab"), is a document running at this origin. Raster images and
// plain media are inert, so those are the only ones previewed.
const INLINE_TYPES = new Set([
  'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif', 'image/bmp',
  'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime',
  'audio/mpeg', 'audio/ogg', 'audio/webm', 'audio/wav', 'audio/x-wav', 'audio/mp4',
  'audio/aac', 'audio/flac', 'audio/opus',
]);

// C0/C1 controls, bidirectional overrides and isolates, zero-width characters,
// and path separators. A right-to-left override turns "invoice‮fdp.exe"
// into "invoiceexe.pdf" on screen; the browser saves the real thing.
const UNSAFE_NAME_CHARS = /[\u0000-\u001f\u007f-\u009f؜​-‏‪-‮⁠-⁩﻿/\\]/g;

/**
 * Normalise peer-supplied file metadata into something safe to render and to
 * hand to the browser. Never trusts the declared type for anything but a
 * preview, and never lets the name lie about what it is.
 */
export function safeFileMeta(meta) {
  if (!meta || typeof meta !== 'object') return null;
  let fileName = typeof meta.fileName === 'string'
    ? meta.fileName.normalize('NFC').replace(UNSAFE_NAME_CHARS, '_').trim()
    : '';
  fileName = fileName.replace(/^\.+/, '').slice(0, 180);
  if (!fileName) fileName = 'file';
  const declared = typeof meta.fileType === 'string'
    ? meta.fileType.split(';')[0].trim().toLowerCase()
    : '';
  const fileType = INLINE_TYPES.has(declared) ? declared : 'application/octet-stream';
  const fileSize = Number.isSafeInteger(meta.fileSize) && meta.fileSize >= 0
    && meta.fileSize <= MAX_FILE_SIZE
    ? meta.fileSize
    : 0;
  return { fileName, fileType, fileSize };
}

/**
 * The size in the encrypted metadata must be the size that was offered, which
 * is what the receiver budgets for and what the parts are counted against. A
 * verified but malicious peer must not show one size and send another.
 */
export function assertFileSizeBinding(declaredSize, offeredSize) {
  if (!Number.isSafeInteger(declaredSize) || declaredSize < 0 || declaredSize > MAX_FILE_SIZE) {
    throw new Error('Invalid declared file size');
  }
  if (declaredSize !== offeredSize) throw new Error('Declared file size does not match the offer');
}

/** How many parts a file of this size travels in. */
export function partsFor(size) {
  return Math.ceil(size / PART_SIZE);
}

function partLength(size, index) {
  return Math.min(PART_SIZE, size - index * PART_SIZE);
}

export class FileTransferManager {
  constructor() {
    this.offers = new Map();   // key → an offer waiting for this side's answer
    this.inbound = new Map();  // key → a file this side accepted, arriving
    this.outbound = new Map(); // key → a file this side is offering or sending
    this._inboundBytes = 0;
    this._pace = new Map();    // scope → what was sent to that peer this window
    // (scope, id, why) — an offer went unanswered, or a transfer stopped
    // arriving. Set by the app, which removes what it showed for it.
    this.onLapse = null;
  }

  /* ── Sending ── */

  /**
   * Offer `file` to one peer and, once accepted, send it. Resolves true when
   * all of it has gone, false when it was called off — refused, withdrawn,
   * or the peer left. Throws when it could not be sent; an offer nobody
   * answered throws with `code: 'unanswered'`.
   */
  async send(file, id, cryptoLayer, peer, ttl, burn, onProgress, scope = '', onWaiting = null) {
    if (!this._validID(id)) throw new Error('Invalid file transfer ID');
    const size = file?.size;
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_FILE_SIZE) {
      throw new Error('File too large');
    }
    if (this.outbound.size >= MAX_ACTIVE_OUTBOUND) throw new Error('Too many files being sent at once');
    const key = this._key(scope, id);
    if (this.outbound.has(key)) throw new Error('Duplicate outbound transfer ID');
    const transfer = { aborted: false, accepted: false, answer: null, timer: null };
    this.outbound.set(key, transfer);
    const parts = partsFor(size);

    try {
      const meta = await cryptoLayer.encrypt(JSON.stringify({
        fileName: String(file.name || 'file').slice(0, 180),
        fileType: String(file.type || 'application/octet-stream').slice(0, 100),
        fileSize: size,
      }));
      if (transfer.aborted) return false;

      const asks = size > AUTO_ACCEPT_SIZE;
      const answered = new Promise((resolve) => {
        transfer.answer = resolve;
        transfer.timer = setTimeout(() => resolve(false), asks ? OFFER_TTL : AUTO_ANSWER_WAIT);
      });
      await peer.send({
        type: 'file-offer', id, meta, size, parts, ttl, burnAfterReading: burn,
      });
      if (asks) onWaiting?.();
      if (!await answered) {
        if (transfer.aborted) return false;
        throw Object.assign(new Error('The file was not accepted in time'), { code: 'unanswered' });
      }

      for (let index = 0; index < parts; index++) {
        if (transfer.aborted) return false;
        await this._waitForBuffer(peer);
        await this._waitForPace(scope, transfer);
        if (transfer.aborted) return false;
        const start = index * PART_SIZE;
        const length = partLength(size, index);
        const bytes = new Uint8Array(await file.slice(start, start + length).arrayBuffer());
        let sealed;
        try {
          // Read from disk as it goes: a file changed or truncated meanwhile
          // must not go out as something it never was.
          if (bytes.byteLength !== length) throw new Error('The file changed while it was being sent');
          sealed = await cryptoLayer.encryptPart(bytes, id, index, parts);
        } finally {
          bytes.fill(0);
        }
        if (transfer.aborted) return false;
        const wire = await peer.send({
          type: 'file-part', id, index,
          data: uint8ToB64(new Uint8Array(sealed.ciphertext)), iv: sealed.iv, epoch: sealed.epoch,
        });
        this._spend(scope, wire);
        onProgress?.(index + 1, parts);
      }
      if (transfer.aborted) return false;
      await peer.send({ type: 'file-done', id });
      return true;
    } finally {
      clearTimeout(transfer.timer);
      this.outbound.delete(key);
    }
  }

  /** The peer said yes to a file we offered it. */
  accepted(scope, id) {
    if (!this._validID(id)) return false;
    const transfer = this.outbound.get(this._key(scope, id));
    if (!transfer || transfer.accepted || transfer.aborted) return false;
    transfer.accepted = true;
    clearTimeout(transfer.timer);
    transfer.answer?.(true);
    return true;
  }

  /** Stop sending this file to anyone it is still going to — or, given a
   *  scope, only to that peer. Reports whether anything was being sent. */
  abortOutbound(id, scope = null) {
    let found = false;
    for (const [key, transfer] of this.outbound) {
      if (scope === null ? key.endsWith(`\0${id}`) : key === this._key(scope, id)) {
        this._abort(transfer);
        found = true;
      }
    }
    return found;
  }

  _abort(transfer) {
    transfer.aborted = true;
    clearTimeout(transfer.timer);
    transfer.answer?.(false);
  }

  /** Wait until one more part fits in what this peer may be sent this window. */
  async _waitForPace(scope, transfer) {
    for (;;) {
      const now = Date.now();
      let pace = this._pace.get(scope);
      if (!pace || now - pace.windowAt >= TRAFFIC_WINDOW_MS) {
        pace = { windowAt: now, bytes: 0, messages: 0 };
        this._pace.set(scope, pace);
      }
      if (pace.bytes + MAX_PART_WIRE_BYTES <= PACE_BYTES && pace.messages < PACE_MESSAGES) return;
      if (transfer.aborted) return;
      await new Promise((resolve) => setTimeout(resolve, pace.windowAt + TRAFFIC_WINDOW_MS - now));
    }
  }

  _spend(scope, wireBytes) {
    const pace = this._pace.get(scope);
    if (!pace) return;
    pace.messages++;
    pace.bytes += Number.isSafeInteger(wireBytes) && wireBytes > 0 ? wireBytes : MAX_PART_WIRE_BYTES;
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

  /* ── Receiving ── */

  /**
   * Route one transfer message from `scope`. Resolves with what the app has
   * to show — an offer, progress, a finished file, an error — or null.
   */
  async handleMessage(msg, scope = '') {
    if (!msg || !this._validID(msg.id)) return null;
    const key = this._key(scope, msg.id);
    switch (msg.type) {
      case 'file-offer': return this._onOffer(msg, scope, key);
      case 'file-part': return this._onPart(msg, key);
      case 'file-done': return this._onDone(key);
      default: return null;
    }
  }

  _onOffer(msg, scope, key) {
    if (this.offers.has(key) || this.inbound.has(key)) return null;
    if (!Number.isSafeInteger(msg.size) || msg.size < 0 || msg.size > MAX_FILE_SIZE
        || msg.parts !== partsFor(msg.size)
        || !this._validEncryptedMeta(msg.meta)) {
      console.warn('File offer rejected: malformed');
      return null;
    }
    // Too many questions left unanswered: turned away, and the sender told.
    if (this.offers.size >= MAX_PENDING_OFFERS) {
      return { event: 'busy', id: msg.id, scope };
    }
    const offer = {
      scope, id: msg.id, size: msg.size, parts: msg.parts, meta: msg.meta,
      ttl: msg.ttl, burnAfterReading: msg.burnAfterReading, timer: null,
    };
    offer.timer = setTimeout(() => {
      if (this.offers.get(key) !== offer) return;
      this.offers.delete(key);
      this.onLapse?.(scope, msg.id, 'offer');
    }, OFFER_TTL);
    this.offers.set(key, offer);
    return {
      event: 'offer', id: msg.id, scope, size: msg.size, meta: msg.meta,
      ttl: msg.ttl, burnAfterReading: msg.burnAfterReading,
      ask: msg.size > AUTO_ACCEPT_SIZE,
    };
  }

  /**
   * Say yes to an offer: from here its parts are taken. `cryptoLayer` is the
   * pair's, and `meta` what the app made of the encrypted metadata. Returns
   * 'ok', 'busy' when this side is already taking in as much as it will, or
   * 'gone' when the offer lapsed or was withdrawn.
   */
  accept(scope, id, cryptoLayer, meta) {
    if (!this._validID(id)) return 'gone';
    const key = this._key(scope, id);
    const offer = this.offers.get(key);
    if (!offer) return 'gone';
    if (this.inbound.size >= MAX_ACTIVE_INBOUND
        || this._inboundBytes + offer.size > MAX_INBOUND_BYTES) {
      return 'busy';
    }
    clearTimeout(offer.timer);
    this.offers.delete(key);
    this._inboundBytes += offer.size;
    const transfer = {
      scope, id, size: offer.size, parts: offer.parts, meta,
      ttl: offer.ttl, burnAfterReading: offer.burnAfterReading,
      crypto: cryptoLayer, next: 0, received: 0,
      pending: [], pendingBytes: 0, blobs: [], timer: null,
    };
    this.inbound.set(key, transfer);
    this._armIdle(key, transfer);
    return 'ok';
  }

  /** Say no to an offer. Reports whether there was one. */
  decline(scope, id) {
    if (!this._validID(id)) return false;
    const key = this._key(scope, id);
    const offer = this.offers.get(key);
    if (!offer) return false;
    clearTimeout(offer.timer);
    this.offers.delete(key);
    return true;
  }

  _armIdle(key, transfer) {
    clearTimeout(transfer.timer);
    transfer.timer = setTimeout(() => {
      if (this.inbound.get(key) !== transfer) return;
      console.warn(`File transfer ${transfer.id} stopped arriving — dropped`);
      this._discardInbound(key);
      this.onLapse?.(transfer.scope, transfer.id, 'stalled');
    }, INBOUND_IDLE_TIMEOUT);
  }

  async _onPart(msg, key) {
    const transfer = this.inbound.get(key);
    // Parts still in flight when this side refused are dropped as they come.
    if (!transfer) return null;
    // The channel is ordered; a part out of place is a peer misbehaving.
    if (msg.index !== transfer.next
        || typeof msg.data !== 'string'
        || typeof msg.iv !== 'string' || msg.iv.length > 32
        || !Number.isSafeInteger(msg.epoch) || msg.epoch < 0) {
      return this._failInbound(key, 'Invalid file part');
    }
    const length = partLength(transfer.size, msg.index);
    if (msg.data.length !== 4 * Math.ceil((length + GCM_TAG) / 3)) {
      return this._failInbound(key, 'Invalid file part size');
    }
    let sealed;
    try {
      sealed = b64ToUint8(msg.data);
    } catch {
      return this._failInbound(key, 'Invalid file part encoding');
    }
    let plain;
    try {
      plain = await transfer.crypto.decryptPart(
        sealed, msg.iv, msg.epoch, transfer.id, msg.index, transfer.parts,
      );
    } catch {
      return this.inbound.get(key) === transfer ? this._failInbound(key, 'File part failed to decrypt') : null;
    }
    // Refused, withdrawn or wiped while this part was being opened.
    if (this.inbound.get(key) !== transfer) {
      plain.fill(0);
      return null;
    }
    if (plain.byteLength !== length) {
      plain.fill(0);
      return this._failInbound(key, 'Invalid file part size');
    }
    transfer.pending.push(plain);
    transfer.pendingBytes += length;
    transfer.received += length;
    transfer.next++;
    if (transfer.pendingBytes >= FLUSH_BYTES) this._flush(transfer);
    this._armIdle(key, transfer);
    return {
      event: 'progress', id: transfer.id, scope: transfer.scope,
      received: transfer.next, totalChunks: transfer.parts,
    };
  }

  _onDone(key) {
    const transfer = this.inbound.get(key);
    if (!transfer) return null;
    if (transfer.next !== transfer.parts || transfer.received !== transfer.size) {
      return this._failInbound(key, 'Incomplete file');
    }
    this._flush(transfer);
    const blob = new Blob(transfer.blobs, { type: transfer.meta?.fileType || 'application/octet-stream' });
    transfer.blobs = [];
    this._release(key, transfer);
    if (blob.size !== transfer.size) {
      return { event: 'error', id: transfer.id, scope: transfer.scope, error: 'File size mismatch' };
    }
    return {
      event: 'complete', id: transfer.id, scope: transfer.scope, blob, meta: transfer.meta,
      ttl: transfer.ttl, burnAfterReading: transfer.burnAfterReading,
    };
  }

  /** Hand what has been decrypted so far to the browser, out of script memory. */
  _flush(transfer) {
    if (!transfer.pending.length) return;
    transfer.blobs.push(new Blob(transfer.pending));
    for (const part of transfer.pending) part.fill(0);
    transfer.pending = [];
    transfer.pendingBytes = 0;
  }

  /** The sender withdrew a file, or this side refused one: drop what came
   *  of it, offered or arriving. Reports whether there was anything. */
  discardInbound(scope, id) {
    if (!this._validID(id)) return false;
    const key = this._key(scope, id);
    const declined = this.decline(scope, id);
    if (!this.inbound.has(key)) return declined;
    this._discardInbound(key);
    return true;
  }

  _discardInbound(key) {
    const transfer = this.inbound.get(key);
    if (!transfer) return;
    for (const part of transfer.pending) part.fill(0);
    transfer.pending = [];
    // A Blob cannot be overwritten; dropping the last reference to it lets the
    // browser free it, from memory or from the temporary file behind it.
    transfer.blobs = [];
    this._release(key, transfer);
  }

  _release(key, transfer) {
    clearTimeout(transfer.timer);
    transfer.crypto = null;
    this._inboundBytes -= transfer.size;
    this.inbound.delete(key);
  }

  _failInbound(key, error) {
    const transfer = this.inbound.get(key);
    if (!transfer) return null;
    const result = { event: 'error', id: transfer.id, scope: transfer.scope, error };
    this._discardInbound(key);
    return result;
  }

  /* ── Both ── */

  abortScope(scope) {
    const prefix = `${scope}\0`;
    for (const [key, transfer] of this.outbound) {
      if (key.startsWith(prefix)) this._abort(transfer);
    }
    for (const [key, offer] of [...this.offers]) {
      if (key.startsWith(prefix)) { clearTimeout(offer.timer); this.offers.delete(key); }
    }
    for (const key of [...this.inbound.keys()]) {
      if (key.startsWith(prefix)) this._discardInbound(key);
    }
    this._pace.delete(scope);
  }

  destroyAll() {
    for (const transfer of this.outbound.values()) this._abort(transfer);
    for (const offer of this.offers.values()) clearTimeout(offer.timer);
    this.offers.clear();
    for (const key of [...this.inbound.keys()]) this._discardInbound(key);
    this._pace.clear();
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
  for (let i = 0; i < bytes.length; i += 0x2000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x2000));
  }
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
