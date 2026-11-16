/**
 * Dead Drop — messages left for an offline contact. Part of the app's one class, in a file of its
 * own: app.js adds these methods to it before the instance is made, and
 * they use `this` exactly as if written there.
 */

import { listContacts, loadDropRecord, saveDropRecord, listDropRecords, withDropRecords } from './identity.js';
import { mintInbox, acceptCapability, sealDrop, namesToCheck, openDrop, DROP_TTLS, MAX_DROP_TEXT } from './drops.js';
import { t } from './i18n.js';
import { DROP_READ_TTLS, DROP_POLL_MS, h } from './app-shared.js';

export class DropMethods {
  /* ── Messages left for an offline contact ──
   * Between saved contacts only: the keys to each other's inbox are handed
   * over in a verified session, and the server keeps sealed boxes it cannot
   * read or connect to anyone. See drops.js. */

  /** Give a saved contact the key to a fresh inbox for messages from them. */
  async _maybeOpenInbox(peerId) {
    const s = this.peers.get(peerId);
    if (!s || !this.identity || this.guest || !s.knownContact || !s.identityFp || !s.verified || s.inboxSent) return;
    s.inboxSent = true;
    const fp = s.identityFp;
    const current = () => !this._wiping && this.peers.get(peerId) === s && !!this.identity;
    try {
      // Stored before it is handed over: a key given out that this browser
      // does not hold would make every message left with it unreadable.
      const capability = await withDropRecords(async () => {
        const { record, capability: minted } = mintInbox(await loadDropRecord(fp));
        if (!current()) return null;
        await saveDropRecord(fp, record, { isCurrent: current });
        return minted;
      });
      if (!capability || !current()) return;
      await this._sendBestEffort(s.conn, { type: 'drop-inbox', ...capability });
    } catch {
      // Storage unavailable: no inbox this time, and no harm done.
    }
  }

  async _storeOutbox(peerId, s) {
    const capability = s.pendingInbox;
    s.pendingInbox = null;
    const fp = s.identityFp;
    const current = () => !this._wiping && this.peers.get(peerId) === s && !!this.identity;
    try {
      await withDropRecords(async () => {
        const record = acceptCapability(await loadDropRecord(fp), capability);
        if (!record || !current()) return;
        await saveDropRecord(fp, record, { isCurrent: current });
      });
    } catch { /* storage unavailable */ }
  }

  _stopDrops(clear) {
    clearTimeout(this._dropTimer);
    this._dropTimer = null;
    this._dropGeneration = (this._dropGeneration || 0) + 1;
    if (clear) {
      // Leaving for sign-in: what was opened here goes with the session.
      this.el.dropsInbox.replaceChildren();
      this.el.dropsInbox.classList.add('hidden');
      this.el.dropsCompose.classList.add('hidden');
      this.el.dropsText.value = '';
      this._dropsOpened?.clear();
    }
  }

  /**
   * Bring the drops section up to date: who messages can be left for, and
   * what is waiting here. Asked again every minute while the page is shown.
   */
  async _refreshDrops() {
    clearTimeout(this._dropTimer);
    const generation = this._dropGeneration = (this._dropGeneration || 0) + 1;
    const current = () => !this._wiping && this._dropGeneration === generation
      && !this.el.landing.classList.contains('hidden');
    if (!this.identity || this.guest || !this.username) {
      this._stopDrops(true);
      return;
    }
    const [contacts, records] = await Promise.all([
      listContacts().catch(() => []), listDropRecords().catch(() => []),
    ]);
    if (!current()) return;
    const labels = new Map(contacts.map((c) => [c.fingerprint, c.label || '—']));
    const pinned = records.filter(({ fp }) => labels.has(fp));

    // Who a message can be left for: contacts who handed us an inbox.
    const recipients = pinned.filter(({ record }) => record?.outbox);
    const chosen = this.el.dropsTo.value;
    this.el.dropsTo.replaceChildren(...recipients.map(({ fp }) => h('option', { value: fp, text: labels.get(fp) })));
    if (recipients.some(({ fp }) => fp === chosen)) this.el.dropsTo.value = chosen;
    this.el.dropsCompose.classList.toggle('hidden', recipients.length === 0);

    // What is waiting: the next few names of every inbox, asked in one go.
    const wanted = [];
    for (const { fp, record } of pinned) {
      for (const name of await namesToCheck(record).catch(() => [])) wanted.push({ fp, name });
    }
    if (!current()) return;
    let present = new Set();
    for (let i = 0; i < wanted.length; i += 128) {
      const batch = wanted.slice(i, i + 128);
      try {
        const res = await this._postJSON('/api/drop/check', { ids: batch.map((w) => w.name.id) });
        if (!res.ok) break;
        for (const id of res.data.present || []) present.add(id);
      } catch { break; }
      if (!current()) return;
    }
    if (!current()) return;
    this._renderWaitingDrops(wanted.filter((w) => present.has(w.name.id)), labels);
    if (!document.hidden) this._dropTimer = setTimeout(() => this._refreshDrops(), DROP_POLL_MS);
  }

  _renderWaitingDrops(waiting, labels) {
    const box = this.el.dropsInbox;
    // Messages already opened stay; notices are redrawn from what is waiting.
    for (const node of box.querySelectorAll('.drop-waiting')) node.remove();
    for (const { fp, name } of waiting) {
      if (this._dropsOpened?.has(name.id)) continue;
      const open = h('button', { class: 'btn btn-sm primary', type: 'button', 'data-i18n': 'drops.open', text: t('drops.open') });
      const row = h('div', { class: 'drop-waiting', 'data-drop': name.id },
        h('span', { class: 'drop-from', text: t('drops.waiting').replace('{name}', labels.get(fp)) }),
        open);
      open.addEventListener('click', () => this._collectDrop(fp, name, labels.get(fp), row));
      box.append(row);
    }
    box.classList.toggle('hidden', box.childElementCount === 0);
  }

  /** Collect a box — which removes it from the server — and show what it says. */
  async _collectDrop(fp, name, label, row) {
    row.querySelector('button').disabled = true;
    try {
      const res = await this._postJSON('/api/drop/collect', { id: name.id });
      if (!res.ok) {
        row.remove();
        if (res.status === 404) this._renderDropNote(t('drops.gone'));
        return;
      }
      const message = await withDropRecords(async () => {
        const opened = await openDrop(await loadDropRecord(fp), name, res.data.box, res.data.iv);
        await saveDropRecord(fp, opened.record);
        return opened.message;
      });
      (this._dropsOpened ||= new Set()).add(name.id);
      row.replaceWith(this._renderOpenedDrop(label, message));
    } catch {
      row.remove();
      this._renderDropNote(t('drops.unreadable'));
    }
    this.el.dropsInbox.classList.toggle('hidden', this.el.dropsInbox.childElementCount === 0);
  }

  _renderOpenedDrop(label, message) {
    const text = h('p', { class: 'drop-text', text: message.text });
    const close = h('button', { class: 'btn btn-sm', type: 'button', 'data-i18n': 'drops.close', text: t('drops.close') });
    const card = h('div', { class: 'drop-opened', role: 'article' },
      h('div', { class: 'drop-from', text: t('drops.from').replace('{name}', label) }),
      text);
    const remove = () => {
      clearInterval(card._timer);
      text.textContent = '';
      card.remove();
      this.el.dropsInbox.classList.toggle('hidden', this.el.dropsInbox.childElementCount === 0);
    };
    close.addEventListener('click', remove);
    const ttl = DROP_READ_TTLS.has(message.readTtl) ? message.readTtl : 0;
    if (ttl) {
      const left = h('span', { class: 'drop-countdown', text: `${ttl}s` });
      const until = Date.now() + ttl * 1000;
      card._timer = setInterval(() => {
        const secs = Math.ceil((until - Date.now()) / 1000);
        if (secs <= 0) remove();
        else left.textContent = `${secs}s`;
      }, 1000);
      card.append(h('div', { class: 'drop-actions' }, left, close));
    } else {
      card.append(h('div', { class: 'drop-actions' }, close));
    }
    return card;
  }

  _renderDropNote(text) {
    const note = h('p', { class: 'drop-note', role: 'status', text });
    this.el.dropsInbox.append(note);
    this.el.dropsInbox.classList.remove('hidden');
    setTimeout(() => {
      note.remove();
      this.el.dropsInbox.classList.toggle('hidden', this.el.dropsInbox.childElementCount === 0);
    }, 8000);
  }

  /** Leave a message in a saved contact's inbox. */
  async _leaveDrop() {
    const fp = this.el.dropsTo.value;
    const text = this.el.dropsText.value;
    const say = (key, ok = false, name = '') => this._accountMsg(this.el.dropsStatus, t(key).replace('{name}', name), ok);
    if (!fp || !text.trim() || this.guest) return;
    if (text.length > MAX_DROP_TEXT) { say('drops.tooLong'); return; }
    const ttl = Number.parseInt(this.el.dropsExpiry.value, 10);
    const readTtl = Number.parseInt(this.el.dropsRead.value, 10);
    if (!DROP_TTLS.includes(ttl) || !DROP_READ_TTLS.has(readTtl)) return;
    const name = this.el.dropsTo.selectedOptions[0]?.textContent || '';
    this.el.dropsSend.disabled = true;
    try {
      // Held until the name used is stored as used: two messages sent at once
      // would otherwise both be sealed under the same one.
      await withDropRecords(async () => {
        let record = await loadDropRecord(fp);
        for (let attempt = 0; attempt < 2; attempt++) {
          const sealed = await sealDrop(record, { text, readTtl });
          const res = await this._postJSON('/api/drop', { id: sealed.id, box: sealed.box, iv: sealed.iv, ttl });
          if (res.ok || res.status === 409) {
            // Taken, or a box already sits under that name: either way that
            // name is used, and the next message goes under the next one.
            record = sealed.advance();
            await saveDropRecord(fp, record);
            if (res.ok) {
              this.el.dropsText.value = '';
              say(`drops.left.${ttl}`, true, name);
              return;
            }
            continue;
          }
          say(res.status === 429 ? 'drops.full' : 'drops.failed');
          return;
        }
        say('drops.failed');
      });
    } catch {
      say('drops.failed');
    } finally {
      this.el.dropsSend.disabled = false;
    }
  }
}
