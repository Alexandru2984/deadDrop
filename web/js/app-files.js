/**
 * Dead Drop — files and voice messages. Part of the app's one class, in a file of its
 * own: app.js adds these methods to it before the instance is made, and
 * they use `this` exactly as if written there.
 */

import { MAX_FILE_SIZE } from './filetransfer.js';
import { t } from './i18n.js';
import { scrubber, MAX_FILES_AT_ONCE, h } from './app-shared.js';

export class FileMethods {
  /* ── File transfer ── */

  /** `recorded`: made here, by the voice recorder, with nothing to strip. */
  /**
   * Several files picked, dropped or pasted at once go one after another:
   * each transfer holds the whole file and its ciphertext in memory, and ten
   * of them at once would be most of a phone's tab. A room left part way
   * through stops the rest from going to whatever room comes next.
   */
  async _sendFiles(files) {
    if (!files.length || !this.encrypted) return;
    if (files.length > MAX_FILES_AT_ONCE) {
      this._renderSystem(t('file.tooMany').replace('{n}', String(MAX_FILES_AT_ONCE)));
      files = files.slice(0, MAX_FILES_AT_ONCE);
    }
    const room = this.roomCode;
    const generation = this._signalGeneration;
    for (const file of files) {
      if (!this.encrypted || this.roomCode !== room || this._signalGeneration !== generation) return;
      await this.sendFile(file);
    }
  }

  async sendFile(file, { recorded = false } = {}) {
    if (!this.encrypted || this._wiping) return;
    const room = this.roomCode;
    const generation = this._signalGeneration;
    const current = () => !this._wiping && this.encrypted && this.roomCode === room
      && this._signalGeneration === generation;
    // A later arrival must not become a recipient of a file selected earlier.
    const targets = [...this.peers].filter(([, s]) => s.verified && s.conn.userVerified);
    // Refused before it is read: a movie is scrubbed in memory, and a
    // two-gigabyte one would be read whole only to be turned away after.
    // A picture can come out of re-encoding smaller, so it is judged after.
    if (file.size > MAX_FILE_SIZE && !String(file.type).startsWith('image/')) {
      this._renderSystem(`${t('err.fileTooLarge')} — max ${this._fmtSize(MAX_FILE_SIZE)}`);
      return;
    }
    // What the sender is told under their own copy: that it left clean, or
    // that they chose to send it as it was. Nothing is claimed for a kind of
    // file this does not clean.
    let scrubNote = null;
    const original = file;
    // A file is never sent uncleaned because the code to clean it did not
    // arrive, or arrived altered and was refused.
    const scrub = this.el.scrubToggle.checked && !recorded ? await scrubber().catch(() => null) : undefined;
    if (!current()) return;
    if (scrub === null) {
      this._renderSystem(t('err.scrubFailed'));
      return;
    }
    if (scrub?.isScrubbable(file)) {
      const { scrubFile } = scrub;
      try {
        file = await scrubFile(file);
        if (!current()) return;
        scrubNote = 'file.cleaned';
      } catch (err) {
        if (!current()) return;
        console.warn('metadata removal failed:', err?.message);
        // A HEIC or TIFF photo this browser cannot read, or a document that
        // is password-protected: say what it means and let the person
        // choose, rather than refuse outright or, as before, send it with its
        // location as though it had been cleaned.
        if (!err?.undecodable || !window.confirm(t(err.prompt || 'scrub.cannotRead'))) {
          this._renderSystem(t('err.scrubFailed'));
          return;
        }
        scrubNote = 'file.sentAsIs';
      }
      // Comments, tracked changes and hidden parts are what the document
      // says, so they stay unless the person says otherwise; but they are easy
      // to forget, and carry names.
      if (file.kept) {
        const choice = await this._askKept(file.kept);
        if (!current()) return;
        if (choice === 'remove') {
          try {
            file = await scrubFile(original, { removeKept: true });
            if (!current()) return;
          } catch (err) {
            if (!current()) return;
            console.warn('removing comments failed:', err?.message);
            file = null;
          }
          if (!file || file.kept) {
            this._renderSystem(t('err.scrubFailed'));
            return;
          }
          scrubNote = 'file.cleanedAll';
        } else if (choice !== 'asIs') {
          this._renderSystem(t('file.notSent'));
          return;
        }
        if (!current()) return;
      }
    }
    if (file.size > MAX_FILE_SIZE) {
      this._renderSystem(`${t('err.fileTooLarge')} — max ${this._fmtSize(MAX_FILE_SIZE)}`);
      return;
    }

    const burn = this.el.burnToggle.checked;
    const ttl  = this._normalizeTTL(this.el.ttlSelect.value);
    const id   = crypto.randomUUID();
    const meta = {
      fileName: file.name,
      fileType: file.type || 'application/octet-stream',
      fileSize: file.size,
    };

    // Show preview immediately (sender has the file locally)
    const blobUrl = URL.createObjectURL(file);
    this._renderFileMsg(id, blobUrl, meta, true, ttl, burn);

    // Fan out to every peer at once, each copy encrypted with that pair's own
    // keys. A file is read from disk a part at a time for each of them, so a
    // group no longer multiplies it in memory; and one person slow to accept
    // a large file does not hold it back from the rest.
    //
    // The sender's copy appears at once, but a large file takes a while to
    // leave; closing the tab before then loses it. Say how far it got.
    const own = document.getElementById(this._domMessageId(this._messageKey(null, id)));
    if (own && scrubNote) {
      own.querySelector('.file-details')?.after(h('div', {
        class: `file-note${scrubNote === 'file.sentAsIs' ? ' warn' : ''}`, 'data-i18n': scrubNote, text: t(scrubNote),
      }));
    }
    // A large file takes minutes; one sent by mistake can be stopped.
    // Cancelling withdraws it as a delete for everyone does, which also tells
    // each peer to drop the part that already arrived.
    let cancelled = false;
    const progress = h('span', { text: t('file.sending').replace('{pct}', '0') });
    const cancel = h('button', {
      class: 'file-cancel', type: 'button', text: '✕',
      'aria-label': t('file.cancel'), title: t('file.cancel'), 'data-i18n-aria': 'file.cancel',
    });
    cancel.addEventListener('click', (e) => {
      e.stopPropagation();
      cancelled = true;
      this.fileMgr.abortOutbound(id);
      this.msgMgr.destroy(this._messageKey(null, id));
    });
    const sending = own && targets.length
      ? h('div', { class: 'file-sending' }, progress, cancel)
      : null;
    if (sending) own.append(sending);
    this._awaitDelivery(id, targets.map(([peerId]) => peerId));
    this._sendingFiles = (this._sendingFiles || 0) + 1;
    this._syncWakeLock();
    // How far each copy has gone, as a fraction; the note shows the average.
    const done = new Map(targets.map(([peerId]) => [peerId, 0]));
    const waiting = new Set();
    const showProgress = () => {
      if (!sending) return;
      if (waiting.size && [...done.values()].every((f) => f === 0)) {
        progress.dataset.i18n = 'file.waiting';
        progress.textContent = t('file.waiting');
        return;
      }
      delete progress.dataset.i18n;
      const pct = Math.min(100, Math.floor(([...done.values()].reduce((a, b) => a + b, 0) / done.size) * 100));
      progress.textContent = t('file.sending').replace('{pct}', String(pct));
    };
    const failures = [];
    await Promise.all(targets.map(async ([peerId, s]) => {
      if (cancelled || !current() || this.peers.get(peerId) !== s || !s.conn.userVerified) {
        this._undeliverable(id, peerId);
        return;
      }
      const onProgress = (sent, total) => {
        waiting.delete(peerId);
        done.set(peerId, sent / total);
        showProgress();
      };
      const onWaiting = () => { waiting.add(peerId); showProgress(); };
      try {
        await this.fileMgr.send(file, id, s.crypto, s.conn, ttl, burn, onProgress, peerId, onWaiting);
      } catch (reason) {
        this._undeliverable(id, peerId);
        if (!current() || cancelled) return;
        failures.push({ peerId, s, reason });
      } finally {
        waiting.delete(peerId);
      }
    }));
    if (this._signalGeneration === generation) this._sendingFiles = Math.max(0, this._sendingFiles - 1);
    this._syncWakeLock();
    sending?.remove();
    if (!current()) return;
    for (const { s, reason } of failures) {
      if (reason?.code === 'unanswered') this._renderSystem(t('file.unanswered').replace('{peer}', s.label));
    }
    const other = failures.find(({ reason }) => reason?.code !== 'unanswered');
    if (other) {
      console.error('File send failed:', other.reason);
      this._renderSystem(t('err.fileFailed'));
    }
  }

  /* ── Voice messages ── */

  async _toggleRecord() {
    if (this._recorder && this._recorder.state === 'recording') { this._stopRecording(); return; }
    // A second tap while the permission prompt is up used to open a second
    // microphone stream; the first was then orphaned, live, with no button
    // left that could stop it.
    if (!this.encrypted || this._recStarting) return;
    this._recStarting = true;
    const room = this.roomCode;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      // Granted after the room was left, or after nobody verified was left
      // in it: there is nothing to record for.
      if (!this.encrypted || this.roomCode !== room) {
        for (const track of stream.getTracks()) track.stop();
        return;
      }
      this._recordStream = stream;
      const rec = new MediaRecorder(stream);
      this._recorder = rec;
      this._recChunks = [];
      rec.ondataavailable = (e) => { if (e.data && e.data.size) this._recChunks.push(e.data); };
      rec.onstop = () => this._finishRecording();
      rec.start();
      this.el.recordBtn.classList.add('recording');
      this.el.recordBtn.textContent = '⏹️';
      this.el.recCancelBtn.classList.remove('hidden');
      this._recTimer = setTimeout(() => this._stopRecording(), 120000); // 2 min cap
      // The microphone is live: say so where the eye already is, with the time.
      const started = Date.now();
      const tick = () => {
        const secs = Math.floor((Date.now() - started) / 1000);
        this.el.msgInput.placeholder = t('rec.active')
          .replace('{time}', `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, '0')}`);
      };
      tick();
      this._recClock = setInterval(tick, 1000);
      this.el.chatFooter?.classList.add('recording');
    } catch {
      this._renderSystem(t('err.micDenied'));
    } finally {
      this._recStarting = false;
    }
  }

  _stopRecording() {
    clearTimeout(this._recTimer);
    if (this._recorder && this._recorder.state === 'recording') this._recorder.stop();
  }

  /**
   * Stop without sending. Used by the discard button, by Escape, and by every
   * way out of the room — leaving used to keep the microphone live until the
   * two-minute cap, recording into a room that no longer existed.
   */
  _discardRecording({ quiet = false } = {}) {
    if (!this._recorder) return;
    this._recDiscard = true;
    // The last chunk arrives after stop(); with nothing listening it is never
    // kept, rather than sitting in memory until the next recording.
    this._recorder.ondataavailable = null;
    if (this._recordStream) for (const track of this._recordStream.getTracks()) track.stop();
    this._stopRecording();
    if (this._recorder?.state !== 'recording') this._finishRecording();
    if (!quiet) this._renderSystem(t('rec.discarded'));
  }

  _finishRecording() {
    clearInterval(this._recClock);
    clearTimeout(this._recTimer);
    this.el.chatFooter?.classList.remove('recording');
    this._updateComposerHint();
    this.el.recordBtn.classList.remove('recording');
    this.el.recordBtn.textContent = '🎙️';
    this.el.recCancelBtn.classList.add('hidden');
    if (this._recordStream) {
      for (const t of this._recordStream.getTracks()) t.stop();
      this._recordStream = null;
    }
    const type = (this._recorder && this._recorder.mimeType) || 'audio/webm';
    const blob = new Blob(this._recChunks, { type });
    this._recChunks = [];
    if (this._recorder) this._recorder.onstop = null;
    this._recorder = null;
    const discarded = this._recDiscard;
    this._recDiscard = false;
    if (discarded || !blob.size || !this.encrypted) return;
    // Safari records MP4/AAC; naming that .webm made a file nothing would open.
    const ext = type.includes('ogg') ? 'ogg' : type.includes('mp4') ? 'm4a' : 'webm';
    // A fixed name: a timestamp here told the other side the exact
    // millisecond of the sender's clock. The type says it is audio; the
    // receiver labels it as a voice message.
    this.sendFile(new File([blob], `voice.${ext}`, { type }), { recorded: true });
  }
}
