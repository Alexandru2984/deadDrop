/**
 * Dead Drop — Message Lifecycle Manager
 *
 * Handles TTL countdown, burn-after-reading, and bilateral message destruction.
 * All message state is in-memory only — nothing is persisted.
 */

export class MessageManager {
  /**
   * @param {Function} onDestroyed – called with message id when a message is destroyed,
   *                                  so the app can notify the remote peer.
   */
  constructor(onDestroyed) {
    this.messages = new Map();
    this.onDestroyed = onDestroyed;
  }

  /**
   * Track a new message with self-destruct rules.
   * @param {string}      id               – unique message id
   * @param {HTMLElement}  element          – DOM node to remove on destruction
   * @param {number}       ttl              – seconds until auto-destroy (0 = no TTL)
   * @param {boolean}      burnAfterReading – destroy once the remote peer reads it
   * @param {boolean}      isMine           – true if this client sent the message
   */
  add(id, element, ttl, burnAfterReading, isMine, blobUrl = null) {
    const entry = { id, element, ttl, burnAfterReading, isMine, timer: null, interval: null, blobUrl };
    this.messages.set(id, entry);

    if (ttl > 0) {
      entry.timer = setTimeout(() => this.destroy(id), ttl * 1000);
      this._startCountdown(entry);
    }

    return entry;
  }

  /** Mark a message as read — triggers burn if burn-after-reading. */
  markRead(id) {
    const m = this.messages.get(id);
    if (!m) return;

    if (m.burnAfterReading && !m.isMine) {
      // Give the user a brief moment to read before burning
      setTimeout(() => this.destroy(id), 2000);
    }
  }

  /** Destroy a message: animate, remove from DOM, notify remote peer. */
  destroy(id) {
    const m = this.messages.get(id);
    if (!m) return;

    if (m.timer) clearTimeout(m.timer);
    if (m.interval) clearInterval(m.interval);

    if (m.blobUrl) URL.revokeObjectURL(m.blobUrl);

    if (m.element) {
      m.element.classList.add('burning');
      setTimeout(() => m.element.remove(), 600);
    }

    this.messages.delete(id);
    this.onDestroyed(id);
  }

  /** Remote peer confirms destruction — destroy locally without re-notifying. */
  remoteDestroy(id) {
    const m = this.messages.get(id);
    if (!m) return;

    if (m.timer) clearTimeout(m.timer);
    if (m.interval) clearInterval(m.interval);

    if (m.blobUrl) URL.revokeObjectURL(m.blobUrl);

    if (m.element) {
      m.element.classList.add('burning');
      setTimeout(() => m.element.remove(), 600);
    }

    this.messages.delete(id);
    // NOTE: do not call onDestroyed — avoids infinite ping-pong
  }

  /** Tear down all timers. */
  destroyAll() {
    for (const [, m] of this.messages) {
      if (m.timer) clearTimeout(m.timer);
      if (m.interval) clearInterval(m.interval);
      if (m.blobUrl) URL.revokeObjectURL(m.blobUrl);
    }
    this.messages.clear();
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
}
