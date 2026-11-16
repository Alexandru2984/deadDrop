/**
 * Dead Drop — comparing safety codes. Part of the app's one class, in a file of its
 * own: app.js adds these methods to it before the instance is made, and
 * they use `this` exactly as if written there.
 */

import { pinContact, findContact } from './identity.js';
import { t } from './i18n.js';
import { h, keptQuestion } from './app-shared.js';

export class VerifyMethods {
  /* ── Per-peer verification bar ──
   * One row per encrypted pairwise session: label, its SAS, QR verify, and a
   * manual verify button. The bar turns green once every peer is verified. */

  _renderVerifyBar() {
    const enc = this._encryptedSessions();
    this.el.verifyRows.replaceChildren();
    if (enc.length === 0) {
      this.el.verifyBar.classList.add('hidden');
      return;
    }
    this.el.verifyBar.classList.remove('hidden');
    this.el.verifyBar.classList.toggle('verified', enc.every((s) => s.verified));
    this.el.verifyBar.classList.toggle('expanded', this._verifyExpanded);
    this.el.verifyBar.classList.toggle('multi', enc.length > 1);
    for (const [peerId, s] of this.peers) {
      if (!s.encrypted) continue;
      const row = document.createElement('div');
      row.className = 'verify-row';
      const label = document.createElement('span');
      label.className = 'verify-label peer-tag';
      label.textContent = s.label;
      label.style.color = s.color;
      const sas = document.createElement('span');
      sas.className = 'verify-sas';
      sas.setAttribute('aria-live', 'polite');
      sas.textContent = s.sas ?? '';
      const qrBtn = document.createElement('button');
      qrBtn.className = 'btn btn-sm';
      qrBtn.textContent = t('verify.qr');
      qrBtn.addEventListener('click', () => this._openQrVerify(peerId));
      const okBtn = document.createElement('button');
      okBtn.className = 'btn btn-sm verify-btn';
      okBtn.textContent = s.verified
        ? t('verify.verified')
        : (s.localVerified ? t('verify.waitingPeer') : t('verify.btn'));
      okBtn.disabled = s.localVerified;
      okBtn.addEventListener('click', () => this._markVerified(peerId, false, 'emoji'));
      // The two actions travel together: when the row is too narrow they
      // wrap below the code as a pair, not one above and one below.
      row.append(label, sas, h('div', { class: 'verify-actions' }, qrBtn, okBtn));
      // Route and method each lead with an icon. Once everyone is verified
      // the bar folds to one line and only the icons show; the sentence stays
      // for screen readers and as a tooltip, and one tap unfolds it.
      const notice = (cls, text) => {
        const [, icon = '', rest = text] = text.match(/^(\S+)\s+(.*)$/su) || [];
        return h('span', { class: cls, title: text },
          h('span', { class: 'notice-icon', 'aria-hidden': 'true', text: icon }),
          h('span', { class: 'notice-text', text: ' ' + rest }));
      };
      if (s.route) {
        row.append(notice(`verify-route verify-route-${s.route}`,
          t(s.route === 'relay' ? 'route.relay' : 'route.direct')));
      }
      if (s.verifiedBy) {
        // How this side checked, kept in view. Six emoji are 36 bits: enough
        // against a guess, thin against someone who can try many sessions. The
        // QR compares all 128, and saying so is how people learn to use it.
        row.append(notice(`verify-method verify-method-${s.verifiedBy}`,
          t({ qr: 'verify.byQr', emoji: 'verify.byEmoji', contact: 'verify.byContact' }[s.verifiedBy])));
      } else if (s.peerConfirmed && !s.localVerified) {
        row.append(h('span', { class: 'verify-peer-confirmed',
          text: t('verify.peerConfirmed').replace('{peer}', s.label) }));
      }
      if (s.verified) {
        const more = h('button', {
          class: 'btn-icon verify-more',
          'aria-expanded': String(this._verifyExpanded),
          'aria-label': t('verify.details'),
          title: t('verify.details'),
          text: this._verifyExpanded ? '▴' : '▾',
        });
        more.addEventListener('click', () => {
          this._verifyExpanded = !this._verifyExpanded;
          this._renderVerifyBar();
        });
        row.insertBefore(more, row.querySelector('.verify-actions'));
      }
      this.el.verifyRows.appendChild(row);
    }
  }

  /**
   * The peer proved possession of a long-term identity.
   *
   * A pin is only ever created after a human compared the safety code, and the
   * proof is bound to this session, so recognising the fingerprint is enough to
   * skip the comparison — that is the entire point of saving a contact. An
   * unknown fingerprint changes nothing: the session stays locked until the
   * codes are compared, exactly as before.
   */
  async _onIdentityProved(peerId, fp) {
    const s = this.peers.get(peerId);
    if (!s || !fp) return;
    s.identityFp = fp;
    const known = await findContact(fp);
    if (this._wiping || this.peers.get(peerId) !== s) return;
    if (!known) {
      this._maybeSaveContact(peerId); // the user may have already confirmed
      this._refreshRoomState();
      return;
    }
    s.knownContact = known;
    s.label = known.label || s.label;
    this._renderSystem(`🔖 ${s.label} ${t('contact.recognised')}`);
    if (s.pendingInbox) this._storeOutbox(peerId, s);
    // Unlock without a fresh comparison. The peer does the same on its side, so
    // two saved contacts connect straight through.
    this._markVerified(peerId, true, 'contact');
  }

  /**
   * Keep the row's route line true. ICE can move a session between a direct
   * pair and a relayed one after it starts, so this re-reads the selected pair
   * every fifteen seconds for as long as the peer is in the room.
   */
  _watchRoute(peerId) {
    const tick = async () => {
      const s = this.peers.get(peerId);
      if (!s) return;
      const route = await s.conn.routeKind().catch(() => null);
      if (this.peers.get(peerId) !== s) return;
      if (route !== s.route) {
        s.route = route;
        this._renderVerifyBar();
      }
      s.routeTimer = setTimeout(tick, 15_000);
    };
    clearTimeout(this.peers.get(peerId)?.routeTimer);
    tick();
  }

  _markVerified(peerId, verifiedByQR = false, method = verifiedByQR ? 'qr' : 'emoji') {
    const s = this.peers.get(peerId);
    if (!s || !s.encrypted) return;
    if (!verifiedByQR && !window.confirm(t('verify.confirm'))) return;
    s.localVerified = true;
    // The strongest check wins: scanning the QR after confirming the emoji
    // upgrades what the row reports, never the reverse.
    const strength = { emoji: 1, contact: 2, qr: 3 };
    if (!s.verifiedBy || strength[method] > strength[s.verifiedBy]) s.verifiedBy = method;
    try {
      s.conn.markVerified().catch(() => s.conn.rejectVerification('verification sync failed'));
    } catch {
      s.localVerified = false;
      return;
    }
    if (!s.verified) {
      this._renderSystem(`✓ ${s.label} ${t('sys.waitPeerVerify')}`);
      this._refreshRoomState();
    }
    if (!verifiedByQR) {
      s.manuallyVerified = true;
      this._maybeSaveContact(peerId);
    }
    this._renderVerifyBar();
  }

  /**
   * Offer to remember a peer once both halves are in place: the human compared
   * the safety code, and the peer proved possession of an identity to attach
   * that trust to. Either can land first — the proof arrives over the encrypted
   * channel just after the handshake, which may be before or after the click —
   * so both paths call this.
   */
  _maybeSaveContact(peerId) {
    const s = this.peers.get(peerId);
    if (!s || !this.identity) return;
    if (!s.identityFp || s.knownContact || s.saveOffered) return;
    if (!s.manuallyVerified) return;
    s.saveOffered = true;
    this._offerToSaveContact(peerId, s);
  }

  _offerToSaveContact(peerId, s) {
    const label = window.prompt(t('contact.savePrompt'), s.label);
    if (label === null) return;
    const current = () => !this._wiping && this.peers.get(peerId) === s;
    pinContact(s.identityFp, label.trim() || s.label, { isCurrent: current })
      .then(() => {
        if (!current()) return;
        s.knownContact = { fingerprint: s.identityFp, label };
        s.label = label.trim() || s.label;
        this._renderSystem(`🔖 ${s.label} ${t('contact.saved')}`);
        this._refreshRoomState();
        if (s.pendingInbox) this._storeOutbox(peerId, s);
        this._maybeOpenInbox(peerId);
      })
      .catch(() => { if (current()) this._renderSystem(t('contact.saveFailed')); });
  }

  /* ── QR safety-code verification ──
   * The QR encodes the full 128-bit verification token (the visual SAS shows
   * only 2^36 of it), so a scan compares the entire handshake secret: a MitM
   * that survived the emoji comparison odds cannot survive this one. */

  async _openQrVerify(peerId) {
    const s = this.peers.get(peerId);
    if (!s) return;
    let token;
    try { token = 'dd-sas:' + s.crypto.computeSASToken(); } catch { return; }
    this._qrPeerId = peerId;
    const qr = await this._qrDataURL(token);
    if (qr) this.el.qrVerifyImg.src = qr;
    this.el.qrVerifyStatus.textContent = `${s.label} — ${t('qr.scanning')}`;
    this.el.qrVerifyStatus.classList.remove('match', 'mismatch');
    this.el.qrVerify.classList.remove('hidden');
    this._makeModal(this.el.qrVerify);
    this._captureFocus(this.el.qrVerify);
    await this._startQrScan(token);
  }

  async _startQrScan(expected) {
    // The permission prompt can outlast the dialog. A camera granted after
    // the dialog was closed must be stopped, not kept scanning out of sight.
    const scan = (this._qrScanGen = (this._qrScanGen || 0) + 1);
    let stream;
    try {
      // The 250KB decoder is only ever loaded (same-origin) when scanning starts.
      await import('./vendor/jsqr.js');
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' }, audio: false,
      });
    } catch {
      if (scan === this._qrScanGen) this.el.qrVerifyStatus.textContent = t('qr.cameraFail');
      return;
    }
    if (scan !== this._qrScanGen) {
      for (const track of stream.getTracks()) track.stop();
      return;
    }
    this._qrStream = stream;
    const video = this.el.qrVerifyVideo;
    video.srcObject = this._qrStream;
    await video.play().catch(() => {});
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    const tick = () => {
      if (!this._qrStream) return; // scan was stopped
      if (video.readyState >= 2 && video.videoWidth) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0);
        const frame = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const hit = self.jsQR(frame.data, frame.width, frame.height, { inversionAttempts: 'dontInvert' });
        if (hit && typeof hit.data === 'string' && hit.data.startsWith('dd-sas:')) {
          this._onQrScanned(hit.data === expected);
          return;
        }
      }
      this._qrRaf = requestAnimationFrame(tick);
    };
    this._qrRaf = requestAnimationFrame(tick);
  }

  _onQrScanned(match) {
    this._stopQrScan();
    if (match) {
      this.el.qrVerifyStatus.textContent = t('qr.match');
      this.el.qrVerifyStatus.classList.add('match');
      this._markVerified(this._qrPeerId, true, 'qr');
    } else {
      this.el.qrVerifyStatus.textContent = t('qr.mismatch');
      this.el.qrVerifyStatus.classList.add('mismatch');
      this.el.verifyBar.classList.remove('verified');
      this.el.verifyBar.classList.add('insecure');
      const s = this.peers.get(this._qrPeerId);
      if (s) s.conn.rejectVerification('safety code mismatch');
    }
  }

  _stopQrScan() {
    this._qrScanGen = (this._qrScanGen || 0) + 1;
    if (this._qrRaf) { cancelAnimationFrame(this._qrRaf); this._qrRaf = null; }
    if (this._qrStream) {
      for (const track of this._qrStream.getTracks()) track.stop();
      this._qrStream = null;
    }
    this.el.qrVerifyVideo.srcObject = null;
  }

  /**
   * Ask what to do with a document that still has comments, changes or hidden
   * parts: take them out and send, send as it is, or not send. Resolves to
   * 'remove', 'asIs' or null.
   */
  _askKept(kept) {
    this._answerKept(null);
    this.el.keptText.textContent = keptQuestion(kept);
    this.el.keptRemove.classList.toggle('hidden', !kept.removable);
    this.el.keptNote.classList.toggle('hidden', !!kept.removable);
    this.el.keptAsk.classList.remove('hidden');
    this._makeModal(this.el.keptAsk);
    this._captureFocus(this.el.keptAsk);
    return new Promise((resolve) => { this._keptAnswer = resolve; });
  }

  _answerKept(choice) {
    const resolve = this._keptAnswer;
    if (!resolve) return;
    this._keptAnswer = null;
    this.el.keptAsk.classList.add('hidden');
    this._makeModal(null);
    this._restoreFocus();
    resolve(choice);
  }

  _closeQrVerify() {
    this._stopQrScan();
    this.el.qrVerify.classList.add('hidden');
    this._makeModal(null);
    this._restoreFocus();
  }
}
