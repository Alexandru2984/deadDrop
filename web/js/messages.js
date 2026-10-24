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
    // Reverse index for removeElement, which is called once per rendered message
    // when the transcript is trimmed. Scanning every tracked message to find the
    // one owning a node made that O(n) on the render path. Weak, so a node the
    // app drops elsewhere does not keep its entry alive.
    this.byElement = new WeakMap();
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
    if (element) this.byElement.set(element, id);
    this.blobBytes += entry.blobBytes;

    if (ttl > 0) {
      // The timer alone runs on a monotonic clock that stops while a phone
      // sleeps: a ten-second message was still on screen when it woke an hour
      // later. The deadline is wall-clock time, and sweep() holds to it.
      entry.deadline = Date.now() + ttl * 1000;
      entry.timer = setTimeout(() => this.destroy(id), ttl * 1000);
      this._startCountdown(entry);
    }

    this._enforceLimits();

    return entry;
  }

  /** Destroy every message whose time has run out, timer or not. Called
   *  when the page comes back from the background or from sleep. */
  sweep(now = Date.now()) {
    for (const [id, m] of [...this.messages]) {
      if (m.deadline && now >= m.deadline) this.destroy(id);
    }
  }

  /** Mark a message as read — triggers burn if burn-after-reading, once the
   *  reader has had `readMs` to read it. */
  markRead(id, readMs = 2000) {
    const m = this.messages.get(id);
    if (!m || m.burnTimer) return;

    if (m.burnAfterReading && !m.isMine) {
      m.burnTimer = setTimeout(() => this.destroy(id), readMs);
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

  /**
   * True when this is one of our own messages that was sent to burn once read.
   *
   * A read receipt destroys the sender's copy, so it must only be honoured for
   * a message that was actually sent with that promise. Otherwise a peer can
   * fabricate receipts for ordinary messages and erase the other side of the
   * conversation while keeping its own copy.
   */
  burnsOnRead(id) {
    const m = this.messages.get(id);
    return !!m && m.burnAfterReading === true && m.isMine === true;
  }

  removeElement(element) {
    const id = this.byElement.get(element);
    if (id === undefined || !this.messages.has(id)) return false;
    this._remove(id, false, true);
    return true;
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
    if (m.element) this.byElement.delete(m.element);
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

    // Counted from the deadline, not by ticks: a throttled background tab
    // fires fewer of them, and the count used to lag the real time left.
    entry.interval = setInterval(() => {
      const remaining = Math.ceil((entry.deadline - Date.now()) / 1000);
      if (remaining <= 0) {
        clearInterval(entry.interval);
        this.destroy(entry.id);
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
