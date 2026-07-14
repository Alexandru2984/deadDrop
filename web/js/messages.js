/**
 * Dead Drop — Message Lifecycle Manager
 *
 * Handles TTL countdown, burn-after-reading, and cooperative bilateral removal.
 * This application does not persist message state; a peer/browser/OS can still
 * retain plaintext outside this manager.
 */

export class MessageManager {
  /**
   * @param {Function} onDestroyed – called with (wireId, peerId) so an inbound
   *                                  message notifies only the peer that sent it.
   */
  constructor(onDestroyed, { maxEntries = 500, maxBlobBytes = 100 * 1024 * 1024 } = {}) {
    this.messages = new Map();
    this.onDestroyed = onDestroyed;
    this.maxEntries = maxEntries;
    this.maxBlobBytes = maxBlobBytes;
    this.blobBytes = 0;
  }

  /**
   * Track a new message with cooperative removal rules.
   * @param {string}      id               – unique message id
   * @param {HTMLElement}  element          – DOM node to remove on destruction
   * @param {number}       ttl              – seconds until auto-destroy (0 = no TTL)
   * @param {boolean}      burnAfterReading – destroy once the remote peer reads it
   * @param {boolean}      isMine           – true if this client sent the message
   */
  add(id, element, ttl, burnAfterReading, isMine, blobUrl = null, routing = {}) {
    // A malicious peer must not leak the previous entry's timers or Blob URL by
    // reusing one of its own message IDs.
    if (this.messages.has(id)) this._remove(id, false);
    const entry = {
      id,
      element,
      ttl,
      burnAfterReading,
      isMine,
      timer: null,
      interval: null,
      burnTimer: null,
      blobUrl,
      wireId: routing.wireId || id,
      peerId: routing.peerId || null,
      blobBytes: Number.isSafeInteger(routing.blobBytes) && routing.blobBytes > 0
        ? routing.blobBytes
        : 0,
    };
    this.messages.set(id, entry);
    this.blobBytes += entry.blobBytes;

    if (ttl > 0) {
      entry.timer = setTimeout(() => this.destroy(id), ttl * 1000);
      this._startCountdown(entry);
    }

    this._enforceLimits();

    return entry;
  }

  /** Mark a message as read — triggers burn if burn-after-reading. */
  markRead(id) {
    const m = this.messages.get(id);
    if (!m) return;

    if (m.burnAfterReading && !m.isMine) {
      // Give the user a brief moment to read before burning
      m.burnTimer = setTimeout(() => this.destroy(id), 2000);
    }
  }

  /** Destroy a message: animate, remove from DOM, notify remote peer. */
  destroy(id) {
    this._remove(id, true);
  }

  /** Remote peer confirms destruction — destroy locally without re-notifying. */
  remoteDestroy(id) {
    this._remove(id, false);
  }

  has(id) {
    return this.messages.has(id);
  }

  removeElement(element) {
    for (const [id, message] of this.messages) {
      if (message.element === element) {
        this._remove(id, false, true);
        return true;
      }
    }
    return false;
  }

  _remove(id, notify, immediate = false) {
    const m = this.messages.get(id);
    if (!m) return;

    if (m.timer) clearTimeout(m.timer);
    if (m.interval) clearInterval(m.interval);
    if (m.burnTimer) clearTimeout(m.burnTimer);

    if (m.blobUrl) URL.revokeObjectURL(m.blobUrl);
    this.blobBytes -= m.blobBytes;

    if (m.element) {
      if (immediate) m.element.remove();
      else {
        m.element.classList.add('burning');
        setTimeout(() => m.element.remove(), 600);
      }
    }

    this.messages.delete(id);
    if (notify) this.onDestroyed(m.wireId, m.peerId);
  }

  /** Tear down all timers. */
  destroyAll() {
    for (const [, m] of this.messages) {
      if (m.timer) clearTimeout(m.timer);
      if (m.interval) clearInterval(m.interval);
      if (m.burnTimer) clearTimeout(m.burnTimer);
      if (m.blobUrl) URL.revokeObjectURL(m.blobUrl);
      m.element?.remove();
    }
    this.messages.clear();
    this.blobBytes = 0;
  }

  /* ── Private ── */

  _startCountdown(entry) {
    const el = entry.element?.querySelector('.countdown');
    if (!el) return;

    let remaining = entry.ttl;
    entry.interval = setInterval(() => {
      remaining--;
      if (remaining <= 0) {
        clearInterval(entry.interval);
        return;
      }
      el.textContent = `${remaining}s`;
    }, 1000);
  }

  _enforceLimits() {
    while (this.messages.size > this.maxEntries || this.blobBytes > this.maxBlobBytes) {
      const oldest = this.messages.keys().next().value;
      if (oldest === undefined) break;
      this._remove(oldest, false);
    }
  }
}
