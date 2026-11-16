/**
 * Dead Drop — voice and video calls. Part of the app's one class, in a file of its
 * own: app.js adds these methods to it before the instance is made, and
 * they use `this` exactly as if written there.
 */

import { t } from './i18n.js';
import { callSignalAllowed } from './callsignal.js';
import { CallGone, MAX_RENDERED_NODES, CALL_RING_MS, CALL_MISSED_MS, appendPresent, h, linkify } from './app-shared.js';

export class CallMethods {
  /* ── Calls ── */

  /** The session that owns the active (or requested) call. */
  _callConn() {
    return this.peers.get(this._callPeerId)?.conn ?? null;
  }

  _onCallBtnClick() {
    if (this.callState === 'active') {
      this._toggleCallOverlay(true);
      return;
    }
    // Calls are strictly 1:1 — only when the room has exactly one encrypted peer
    // whose media path is bound to the verified SAS channel.
    if (!this._canCall()) return;
    this._showCallMenu(this.el.callMenu.classList.contains('hidden'));
  }

  _canCall() {
    const enc = this._verifiedSessions();
    return this.callState === 'idle' && enc.length === 1 && this.peers.size === 1
      && enc[0].conn.mediaVerified;
  }

  _showCallMenu(on) {
    this.el.callMenu.classList.toggle('hidden', !on);
    this.el.callBtn.setAttribute('aria-expanded', String(on));
    if (on) this.el.callVoice.focus();
  }

  _placeCall(video) {
    this._showCallMenu(false);
    if (!this._canCall()) return;
    this._callPeerId = [...this.peers.keys()][0];
    this._callRole = 'caller';
    this._startCall(video);
  }

  async _startCall(video) {
    this.callState = 'requesting';
    this._syncWakeLock();
    this._callVideo = video;
    this._ringFor(CALL_RING_MS, 'requesting', () => {
      this._endCall();
      this._renderSystem(t('call.noAnswer'));
    });
    await this._sendBestEffort(this._callConn(), { type: 'call-req', video });
    this._showCallStatus(`📞 ${t('call.calling')}`);
    this._showPlaceholder(video ? 'call.waitingVideo' : 'call.voice');
    this._toggleCallOverlay(true);
  }

  /**
   * Answer, with the camera only if asked to. A video call used to switch
   * the callee's camera on at Accept; now there is a voice-only answer
   * beside it, and a voice call never asks for the camera at all.
   */
  async _acceptCall(video = true) {
    this._showRinging(false);
    this.callState = 'connecting';
    this._syncWakeLock();

    try {
      this.localStream = await this._getMedia(this._callVideo && video);
    } catch (err) {
      if (err instanceof CallGone) return;
      console.error('getUserMedia failed:', err);
      await this._sendBestEffort(this._callConn(), { type: 'call-reject', reason: 'media-error' });
      this._endCallCleanup();
      this._renderSystem(t('err.media'));
      return;
    }

    this.el.localVideo.srcObject = this.localStream;
    this._syncCamButton();
    this._showPlaceholder(this._callVideo ? 'call.waitingVideo' : 'call.voice');
    this._toggleCallOverlay(true);
    this._showCallStatus(`🔄 ${t('call.connecting')}`);
    await this._sendBestEffort(this._callConn(), { type: 'call-accept' });
  }

  _rejectCall() {
    // Send first: the cleanup drops the reference to the peer being declined.
    // Leaving that reference behind is what let a declined caller keep going.
    this._sendBestEffort(this._callConn(), { type: 'call-reject' });
    this._endCallCleanup();
  }

  _handleCallSignal(peerId, msg) {
    // A frame from the right peer is not the same as a frame at the right
    // moment. Verification tells us who is on the other end; it does not stop
    // them from running a patched client that offers media while our phone is
    // merely ringing, or straight after the user pressed decline.
    if (!callSignalAllowed(msg.type, {
      state: this.callState,
      role: this._callRole,
      fromCallPeer: peerId === this._callPeerId,
    })) return;
    if (msg.type === 'call-req' && typeof msg.video !== 'boolean') return;
    if ((msg.type === 'call-offer' || msg.type === 'call-answer')
        && (typeof msg.sdp !== 'string' || msg.sdp.length > 64 * 1024)) return;
    if (msg.type === 'call-mute'
        && msg.audio !== undefined && typeof msg.audio !== 'boolean') return;
    if (msg.type === 'call-mute'
        && msg.video !== undefined && typeof msg.video !== 'boolean') return;
    if (msg.type === 'call-mute'
        && msg.screen !== undefined && typeof msg.screen !== 'boolean') return;
    switch (msg.type) {
      case 'call-req':    this._onCallReq(peerId, msg); break;
      case 'call-accept': this._onCallAccept();     break;
      case 'call-reject': this._onCallReject(msg);  break;
      case 'call-offer':  this._onCallOffer(msg);   break;
      case 'call-answer': this._onCallAnswer(msg);  break;
      case 'call-end':    this._onCallEnd();        break;
      case 'call-mute':   this._onCallMute(msg);    break;
    }
  }

  _onCallReq(peerId, msg) {
    // Busy, a group room (calls stay 1:1), or a media path not bound to the
    // verified SAS channel — decline rather than risk an intercepted call.
    const session = this.peers.get(peerId);
    if (this.callState !== 'idle'
        || this.peers.size > 1
        || !session?.verified
        || !session.conn.userVerified
        || !session.conn.mediaVerified) {
      this._sendBestEffort(this.peers.get(peerId)?.conn, { type: 'call-reject', reason: 'busy' });
      return;
    }
    this._callPeerId = peerId;
    this._callRole = 'callee';
    this.callState = 'incoming';
    this._callVideo = msg.video;
    // The QR dialog is modal and would leave the ring unanswerable behind it.
    if (!this.el.qrVerify.classList.contains('hidden')) this._closeQrVerify();
    // Name the caller: in a room you have verified, the label is who it is.
    this.el.incomingText.textContent = t(msg.video ? 'call.incomingVideo' : 'call.incomingFrom')
      .replace('{peer}', session.label);
    this._showRinging(true);
    if (!this._pageOnScreen()) this._markTitle();
    this._ringFor(CALL_MISSED_MS, 'incoming', () => {
      this._sendBestEffort(this._callConn(), { type: 'call-reject', reason: 'no-answer' });
      this._missedCall();
    });
  }

  /**
   * Give up on a call nobody answered. It used to ring for as long as both
   * tabs stayed open — on a phone left on a table, all night.
   */
  _ringFor(ms, state, giveUp) {
    clearTimeout(this._ringLimit);
    const gen = this._callGen;
    this._ringLimit = setTimeout(() => {
      if (this._callGen === gen && this.callState === state) giveUp();
    }, ms);
  }

  _missedCall() {
    const label = this.peers.get(this._callPeerId)?.label ?? '';
    this._endCallCleanup();
    this._renderSystem(t('call.missed').replace('{peer}', label));
  }

  /**
   * The ring sat under the privacy screen, so someone coming back to the tab
   * was told only that it was hidden while the call went unanswered. The
   * screen now says that someone is calling — not who, since it is there to
   * hide the conversation from whoever else can see the display.
   */
  _showRinging(on) {
    this.el.acceptAudio.classList.toggle('hidden', !(on && this._callVideo));
    this.el.incomingCall.classList.toggle('hidden', !on);
    this.el.privacyRinging.classList.toggle('hidden', !on);
    this._ring(on);
  }

  /**
   * Ring and vibrate while a call waits to be answered.
   *
   * A call used to arrive in silence, so one to a tab in the background, or a
   * phone on the table, went unanswered. The tone is made here rather than
   * fetched, and is quiet. Someone who cannot have their phone make a sound
   * turns it off in the privacy options; the call still shows on screen.
   */
  _ring(on) {
    clearInterval(this._ringTimer);
    this._ringTimer = null;
    const ctx = this._ringCtx;
    this._ringCtx = null;
    ctx?.close().catch(() => {});
    try { navigator.vibrate?.(0); } catch { /* not on this device */ }
    if (!on || !this.el.ringToggle.checked) return;
    let tone = null;
    try {
      tone = new AudioContext();
      tone.resume().catch(() => {});
    } catch { /* no audio output: vibrate only */ }
    this._ringCtx = tone;
    const burst = () => {
      try { navigator.vibrate?.([400, 200, 400]); } catch { /* not on this device */ }
      if (!tone || tone.state === 'closed') return;
      const t0 = tone.currentTime;
      for (const [freq, at] of [[880, 0], [660, 0.4]]) {
        const osc = tone.createOscillator();
        const gain = tone.createGain();
        osc.frequency.value = freq;
        gain.gain.setValueAtTime(0, t0 + at);
        gain.gain.linearRampToValueAtTime(0.08, t0 + at + 0.02);
        gain.gain.linearRampToValueAtTime(0, t0 + at + 0.35);
        osc.connect(gain).connect(tone.destination);
        osc.start(t0 + at);
        osc.stop(t0 + at + 0.36);
      }
    };
    burst();
    this._ringTimer = setInterval(burst, 3000);
  }

  async _onCallAccept() {
    if (this.callState !== 'requesting') return;
    this.callState = 'connecting';
    this._syncWakeLock();

    try {
      this.localStream = await this._getMedia(this._callVideo);
    } catch (err) {
      if (err instanceof CallGone) return;
      console.error('getUserMedia failed:', err);
      await this._sendBestEffort(this._callConn(), { type: 'call-end' });
      this._endCallCleanup();
      this._renderSystem(t('err.media'));
      return;
    }

    this.el.localVideo.srcObject = this.localStream;
    this._syncCamButton();
    this._showCallStatus(`🔄 ${t('call.connectingMedia')}`);

    try {
      const offer = await this._callConn().startMedia(this.localStream);
      await this._sendBestEffort(
        this._callConn(), { type: 'call-offer', sdp: JSON.stringify(offer) },
      );
    } catch (err) {
      console.error('Media offer failed:', err);
      this._endCall();
    }
  }

  _onCallReject(msg) {
    this._endCallCleanup();
    this._renderSystem(t(msg.reason === 'no-answer' ? 'call.noAnswer' : 'call.declined'));
  }

  async _onCallOffer(msg) {
    try {
      const offer = JSON.parse(msg.sdp);
      const answer = await this._callConn().acceptMedia(offer, this.localStream);
      await this._sendBestEffort(
        this._callConn(), { type: 'call-answer', sdp: JSON.stringify(answer) },
      );
      this.callState = 'active';
      this._startCallClock();
      this._updateCallBtn(true);
      this._onCallActive();
    } catch (err) {
      console.error('Call offer handling failed:', err);
      this._endCall();
    }
  }

  async _onCallAnswer(msg) {
    try {
      const answer = JSON.parse(msg.sdp);
      await this._callConn().completeMedia(answer);
      this.callState = 'active';
      this._startCallClock();
      this._updateCallBtn(true);
      this._onCallActive();
    } catch (err) {
      console.error('Call answer handling failed:', err);
      this._endCall();
    }
  }

  _onCallEnd() {
    if (this.callState === 'incoming') { this._missedCall(); return; }
    this._endCallCleanup();
    this._renderSystem(t('call.ended'));
  }

  _onCallMute(msg) {
    if (msg.video === undefined) return;
    this._remotePictureOff = !msg.video;
    this._remoteScreen = msg.video && msg.screen === true;
    this._syncRemotePicture();
  }

  /** Media is negotiated: what each side can now do is known. */
  _onCallActive() {
    this._syncShareButton();
    // A video call answered without a camera says so, but not in the first
    // moments, when the picture is simply still on its way.
    const call = this._callGen;
    clearTimeout(this._pictureGrace);
    this._pictureGrace = setTimeout(() => {
      if (call !== this._callGen) return;
      this._pictureGraceOver = true;
      this._syncRemotePicture();
    }, 2500);
  }

  /** What stands in for the other side's picture, in words that fit the call:
   *  a voice call used to say "Waiting for video…" for as long as it lasted. */
  _showPlaceholder(key) {
    this.el.placeholderText.dataset.i18n = key;
    this.el.placeholderText.textContent = t(key);
  }

  _endCall() {
    if (this.callState === 'idle') return;
    this._sendBestEffort(this._callConn(), { type: 'call-end' });
    this._endCallCleanup();
  }

  _endCallCleanup() {
    // Media still being granted belongs to the call that asked for it; once
    // that call is over, whatever arrives is stopped instead of adopted.
    this._callGen = (this._callGen || 0) + 1;
    const hadCall = this._callInProgress();
    this.callState = 'idle';
    clearTimeout(this._ringLimit);
    if (hadCall && this._idleDeadline) this._armIdleLock();
    this._syncWakeLock();
    clearInterval(this._callClock);
    this._callClock = null;
    this._callConn()?.stopMedia();
    this._callPeerId = null;
    this._callRole = null;
    if (this.localStream) {
      for (const track of this.localStream.getTracks()) track.stop();
      this.localStream = null;
    }
    this.remoteStream = null;
    if (this._screenTrack) {
      // Not part of localStream, so nothing above stopped it.
      this._screenTrack.stop();
      this._screenTrack = null;
    }
    this._camBeforeShare = null;
    this._screenBusy = false;
    this._remoteVideoTrack = null;
    this._remotePictureOff = false;
    this._remoteScreen = false;
    this._remoteLastPicture = null;
    clearTimeout(this._pictureGrace);
    this._pictureGraceOver = false;
    this.el.remoteVideo.classList.remove('screen');
    this.el.screenNote.classList.add('hidden');
    this.el.screenNote.textContent = '';
    this.el.shareScreen.classList.add('hidden');
    this.el.shareScreen.classList.remove('sharing');
    this.el.shareScreen.setAttribute('aria-pressed', 'false');
    this.el.localVideo.srcObject = null;
    this.el.remoteVideo.srcObject = null;
    // A call that fails mid-negotiation gets torn down here, and left the last
    // status behind: the user was told "connecting" forever with nothing to
    // connect to.
    this._showCallStatus('');
    this._toggleCallOverlay(false);
    this._showRinging(false);
    this.el.remotePlaceholder.classList.remove('hidden');
    this._showPlaceholder('call.waitingVideo');
    this.el.localVideo.classList.remove('hidden');
    this._updateCallBtn(false);
    this._showCallMenu(false);
    this._resetMuteButtons();
    this._refreshRoomState();
  }

  _onRemoteTrack(track) {
    if (!this._callInProgress()) return;
    if (!this.remoteStream) {
      this.remoteStream = new MediaStream();
      this.el.remoteVideo.srcObject = this.remoteStream;
    }
    if (track.kind !== 'video') {
      if (!this.remoteStream.getTracks().includes(track)) this.remoteStream.addTrack(track);
      return;
    }
    // Every call has a picture channel, so that a screen can be shown without
    // negotiating again; in a voice call nothing travels on it. The track is
    // therefore only put on screen while pictures are actually arriving.
    this._remoteVideoTrack = track;
    const sync = () => { if (this._remoteVideoTrack === track) this._syncRemotePicture(); };
    track.addEventListener('unmute', sync);
    track.addEventListener('mute', sync);
    track.addEventListener('ended', sync);
    this._syncRemotePicture();
  }

  /** Show the other side's picture while there is one, and say why when not. */
  _syncRemotePicture() {
    if (!this._callInProgress()) return;
    const track = this._remoteVideoTrack;
    const live = !!track && track.readyState === 'live' && !track.muted && !this._remotePictureOff;
    if (track && this.remoteStream) {
      const shown = this.remoteStream.getVideoTracks().includes(track);
      if (live && !shown) this.remoteStream.addTrack(track);
      else if (!live && shown) this.remoteStream.removeTrack(track);
    }
    if (live) this._remoteLastPicture = this._remoteScreen ? 'screen' : 'camera';
    this.el.remotePlaceholder.classList.toggle('hidden', live);
    this.el.remoteVideo.classList.toggle('screen', live && this._remoteScreen);
    if (!live) {
      if (this._remotePictureOff && this._remoteLastPicture === 'camera') {
        this._showPlaceholder('call.cameraOff');
      } else if (!this._callVideo) {
        this._showPlaceholder('call.voice');
      } else {
        this._showPlaceholder(this._pictureGraceOver ? 'call.voiceOnly' : 'call.waitingVideo');
      }
    }
    this._syncScreenNote();
  }

  /** Offered only where the browser can capture a screen and this call has a
   *  picture channel to put it on. Phones have no such capture. */
  _syncShareButton() {
    const can = this.callState === 'active'
      && typeof navigator.mediaDevices?.getDisplayMedia === 'function'
      && !!this._callConn()?.canSendVideo();
    const sharing = !!this._screenTrack;
    this.el.shareScreen.classList.toggle('hidden', !can);
    this.el.shareScreen.classList.toggle('sharing', sharing);
    this.el.shareScreen.setAttribute('aria-pressed', String(sharing));
    const label = t(sharing ? 'aria.stopShare' : 'aria.shareScreen');
    this.el.shareScreen.dataset.i18nAria = sharing ? 'aria.stopShare' : 'aria.shareScreen';
    this.el.shareScreen.setAttribute('aria-label', label);
    this.el.shareScreen.title = label;
  }

  /** Whose screen is on show, in words — above all when it is one's own. */
  _syncScreenNote() {
    const peer = this.peers.get(this._callPeerId)?.label ?? '';
    let text = '';
    if (this._screenTrack) {
      text = t('call.youShare').replace('{peer}', peer);
    } else if (this._remoteScreen && this.el.remoteVideo.classList.contains('screen')) {
      text = t('call.peerShares').replace('{peer}', peer);
    }
    this.el.screenNote.textContent = text;
    this.el.screenNote.classList.toggle('hidden', !text);
    this.el.screenNote.classList.toggle('mine', !!this._screenTrack);
  }

  /** Tell the other side what this one is sending, so its screen can say so. */
  _announceMedia() {
    const mic = this.localStream?.getAudioTracks()[0];
    const cam = this.localStream?.getVideoTracks()[0];
    const screen = !!this._screenTrack;
    this._sendBestEffort(this._callConn(), {
      type: 'call-mute',
      audio: mic?.enabled ?? true,
      video: screen || (cam?.enabled ?? false),
      screen,
    });
  }

  /**
   * Show this screen in place of the camera, or stop.
   *
   * The screen goes out on the call's existing picture channel — the one
   * bound to the verified safety code — by swapping the track on it, so
   * nothing is negotiated and the other side cannot ask for it: only this
   * button, and then the browser's own picker, start a capture. The camera
   * is switched off while the screen is shown rather than left running
   * unseen, and comes back afterwards if it was on.
   */
  async _toggleScreenShare() {
    if (this._screenBusy) return;
    if (this._screenTrack) { await this._stopScreenShare(); return; }
    const conn = this._callConn();
    if (this.callState !== 'active' || !conn?.canSendVideo()) return;
    this._screenBusy = true;
    const call = this._callGen;
    let track = null;
    try {
      const display = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
      track = display.getVideoTracks()[0] ?? null;
      for (const extra of display.getTracks()) if (extra !== track) extra.stop();
      if (!track || call !== this._callGen || this.callState !== 'active') throw new CallGone();
      try { track.contentHint = 'detail'; } catch { /* only a hint */ }
      await conn.replaceVideoTrack(track);
      if (call !== this._callGen) throw new CallGone();
      const cam = this.localStream?.getVideoTracks()[0];
      this._camBeforeShare = cam ? { enabled: cam.enabled } : null;
      if (cam) { this.localStream.removeTrack(cam); cam.stop(); }
      const shared = track;
      track = null;
      this._screenTrack = shared;
      // The browser's own "stop sharing" control ends the track from outside.
      shared.addEventListener('ended', () => {
        if (this._screenTrack === shared) this._stopScreenShare();
      });
      this._syncCamButton();
      this._syncShareButton();
      this._syncScreenNote();
      this._announceMedia();
    } catch (err) {
      const declined = err instanceof CallGone
        || err?.name === 'NotAllowedError' || err?.name === 'AbortError';
      if (!declined) {
        console.warn('Screen sharing failed:', err);
        this.el.screenNote.textContent = t('call.screenFailed');
        this.el.screenNote.classList.remove('hidden', 'mine');
      }
    } finally {
      track?.stop();
      this._screenBusy = false;
    }
  }

  async _stopScreenShare() {
    const shared = this._screenTrack;
    if (!shared) return;
    this._screenTrack = null;
    shared.stop();
    const call = this._callGen;
    const conn = this._callConn();
    const before = this._camBeforeShare;
    this._camBeforeShare = null;
    let cam = null;
    try {
      if (before && this.callState === 'active') {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: { ideal: this._facing || 'user' } },
        });
        cam = stream.getVideoTracks()[0] ?? null;
        if (call !== this._callGen || !this.localStream) throw new CallGone();
        if (cam) cam.enabled = before.enabled;
      }
      if (call !== this._callGen) throw new CallGone();
      await conn?.replaceVideoTrack(cam);
      if (cam && this.localStream) {
        this.localStream.addTrack(cam);
        cam = null;
      }
    } catch (err) {
      if (!(err instanceof CallGone)) {
        console.warn('Could not return to the camera:', err);
        // Whatever happens, the screen must not stay on the channel.
        if (call === this._callGen) await conn?.replaceVideoTrack(null).catch(() => {});
      }
    } finally {
      cam?.stop();
    }
    if (call !== this._callGen) return;
    this._syncCamButton();
    const restored = this.localStream?.getVideoTracks()[0];
    if (restored) {
      this.el.toggleCam.classList.toggle('muted', !restored.enabled);
      this.el.toggleCam.textContent = restored.enabled ? '📹' : '🚫';
    }
    this._syncShareButton();
    this._syncScreenNote();
    this._announceMedia();
  }

  /** No camera in this call: the camera button has nothing to switch. */
  _syncCamButton() {
    const cam = this.localStream?.getVideoTracks()[0];
    this.el.toggleCam.disabled = !cam;
    this.el.flipCam.classList.add('hidden');
    // Nor a preview: an empty frame sat in the corner of every voice call.
    this.el.localVideo.classList.toggle('hidden', !cam);
    if (!cam) {
      this.el.toggleCam.classList.add('muted');
      this.el.toggleCam.textContent = '🚫';
      return;
    }
    this._facing = cam.getSettings?.().facingMode || 'user';
    // Offered only where there is another camera to switch to.
    const call = this._callGen;
    navigator.mediaDevices.enumerateDevices?.().then((devices) => {
      if (call !== this._callGen) return;
      const cameras = devices.filter((d) => d.kind === 'videoinput').length;
      this.el.flipCam.classList.toggle('hidden', cameras < 2);
    }).catch(() => {});
  }

  /**
   * Front camera to back and back again, mid-call. The new picture replaces
   * the old on the same sender, so nothing is renegotiated; the old camera is
   * released as soon as the new one is live, and a camera that was switched
   * off stays off.
   */
  async _flipCam() {
    const old = this.localStream?.getVideoTracks()[0];
    if (!old || this._flipping) return;
    this._flipping = true;
    const call = this._callGen;
    const facing = this._facing === 'environment' ? 'user' : 'environment';
    let fresh = null;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: facing } } });
      fresh = stream.getVideoTracks()[0];
      if (call !== this._callGen || !this.localStream) throw new CallGone();
      fresh.enabled = old.enabled;
      await this._callConn().replaceVideoTrack(fresh);
      this.localStream.removeTrack(old);
      this.localStream.addTrack(fresh);
      old.stop();
      this._facing = fresh.getSettings?.().facingMode || facing;
      this.el.localVideo.classList.toggle('rear', this._facing === 'environment');
      fresh = null;
    } catch (err) {
      if (!(err instanceof CallGone)) console.warn('Camera switch failed:', err);
    } finally {
      fresh?.stop();
      this._flipping = false;
    }
  }

  /** Media is being set up or flowing: someone is on the call. */
  _callInProgress() {
    return this.callState === 'connecting' || this.callState === 'active';
  }

  /**
   * Keep the screen on through a call or a file transfer.
   *
   * A phone that dims and locks suspends the tab with it: video freezes for
   * the other side, and a transfer stalls until it fails. The lock lapses by
   * itself whenever the page is hidden, so it is asked for again when the
   * page comes back, and let go as soon as nothing needs it.
   */
  _syncWakeLock() {
    const want = this.callState !== 'idle' && this.callState !== 'incoming'
      || this._sendingFiles > 0
      || this.fileMgr.inbound.size > 0;
    if (!want) {
      const lock = this._wakeLock;
      this._wakeLock = null;
      lock?.release().catch(() => {});
      return;
    }
    if (this._wakeLock || this._wakeLockAsking || document.hidden || !navigator.wakeLock) return;
    this._wakeLockAsking = true;
    navigator.wakeLock.request('screen').then((lock) => {
      this._wakeLockAsking = false;
      this._wakeLock = lock;
      lock.addEventListener('release', () => {
        if (this._wakeLock === lock) this._wakeLock = null;
      });
      // Whatever needed it may have finished while the browser was asked.
      this._syncWakeLock();
    }, () => { this._wakeLockAsking = false; });
  }

  _toggleCallOverlay(show) {
    const wasOpen = !this.el.callOverlay.classList.contains('hidden');
    this.el.callOverlay.classList.toggle('hidden', !show);
    if (show && !wasOpen) {
      this._makeModal(this.el.callOverlay);
      this._captureFocus(this.el.callOverlay);
    } else if (!show && wasOpen) {
      this._makeModal(null);
      this._restoreFocus();
    }
  }

  /** Who the call is with and how long it has run — and that it is encrypted. */
  _startCallClock() {
    clearInterval(this._callClock);
    const started = Date.now();
    const label = this.peers.get(this._callPeerId)?.label ?? '';
    const tick = () => {
      const secs = Math.floor((Date.now() - started) / 1000);
      const h = Math.floor(secs / 3600);
      const mm = String(Math.floor(secs / 60) % 60).padStart(2, '0');
      const ss = String(secs % 60).padStart(2, '0');
      this._showCallStatus(t('call.active')
        .replace('{peer}', label)
        .replace('{time}', h ? `${h}:${mm}:${ss}` : `${mm}:${ss}`));
    };
    tick();
    this._callClock = setInterval(tick, 1000);
  }

  _showCallStatus(text) {
    this.el.callStatusBar.textContent = text;
    this.el.callStatusBar.classList.toggle('hidden', !text);
  }

  _updateCallBtn(inCall) {
    this.el.callBtn.textContent = inCall ? '🟢' : '📞';
    this.el.callBtn.title = t(inCall ? 'call.show' : 'aria.call');
  }

  _toggleMic() {
    if (!this.localStream) return;
    const track = this.localStream.getAudioTracks()[0];
    if (!track) return;
    track.enabled = !track.enabled;
    this.el.toggleMic.classList.toggle('muted', !track.enabled);
    this.el.toggleMic.textContent = track.enabled ? '🎤' : '🔇';
    this._announceMedia();
  }

  _toggleCam() {
    if (!this.localStream) return;
    const track = this.localStream.getVideoTracks()[0];
    if (!track) return;
    track.enabled = !track.enabled;
    this.el.toggleCam.classList.toggle('muted', !track.enabled);
    this.el.toggleCam.textContent = track.enabled ? '📹' : '🚫';
    this._announceMedia();
  }

  _resetMuteButtons() {
    this.el.toggleCam.disabled = false;
    this.el.flipCam.classList.add('hidden');
    this.el.localVideo.classList.remove('rear');
    this.el.toggleMic.classList.remove('muted');
    this.el.toggleMic.textContent = '🎤';
    this.el.toggleCam.classList.remove('muted');
    this.el.toggleCam.textContent = '📹';
  }

  /**
   * Camera and microphone for the current call. The permission prompt can be
   * answered after the call has ended — the other side hung up, or left — and
   * a stream granted then would be live with no call to belong to, so it is
   * stopped and the caller learns the call is gone (CallGone).
   */
  async _getMedia(withVideo) {
    const call = this._callGen;
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: withVideo });
    } catch (err) {
      if (!withVideo || call !== this._callGen) throw err;
      // Fallback to audio-only if camera unavailable
      stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
    }
    if (call !== this._callGen) {
      for (const track of stream.getTracks()) track.stop();
      throw new CallGone();
    }
    return stream;
  }

  _renderMsg(id, text, mine, ttl, burn, sender = null, peerId = null, quoteKey = null) {
    ttl = this._normalizeTTL(ttl);
    burn = burn === true;
    const el = document.createElement('div');
    el.className = `msg ${mine ? 'mine' : 'theirs'}`;
    if (burn) el.classList.add('burn');

    const key = this._messageKey(mine ? null : peerId, id);
    appendPresent(el,
      this._senderTag(mine, sender),
      quoteKey && this._quoteEl(el, quoteKey),
      h('div', { class: 'msg-text' }, ...linkify(String(text))),
      this._metaRow(burn, ttl),
      this._msgActions(el, key, mine, true),
    );
    this._applySenderColor(el, sender);

    this._appendToLog(el, mine);

    this.msgMgr.add(key, el, ttl, burn, mine, null, { wireId: id, peerId, deferTtl: !mine && !this._onScreen() });
    // Two seconds was the same for a word as for a paragraph; this is about
    // the pace of careful reading, within limits.
    if (!mine) {
      this._markSeen(key, Math.min(30_000, 2000 + String(text).length * 60),
        burn ? { peerId, id } : null);
    }
  }

  /**
   * Start a received message's burn-after-reading clock — once someone can
   * actually see it. It used to start on arrival, so a message that came in
   * while the tab was in the background, or behind the privacy screen, burned
   * two seconds later in front of nobody. The read receipt that burns the
   * sender's copy went out on arrival too, and now waits for the same moment.
   */
  _markSeen(key, readMs, receipt = null) {
    if (!this._onScreen()) {
      const unseen = (this._unseen ||= new Map());
      unseen.set(key, { readMs, receipt });
      // The transcript keeps at most so many messages; a peer sending more
      // while the tab is away must not grow this list without end.
      while (unseen.size > MAX_RENDERED_NODES) unseen.delete(unseen.keys().next().value);
      if (!this._pageOnScreen()) this._markTitle();
      return;
    }
    if (!this.msgMgr.has(key)) return;
    this.msgMgr.startTtl(key);
    this.msgMgr.markRead(key, readMs);
    if (receipt) {
      const s = this.peers.get(receipt.peerId);
      if (s?.verified) this._sendBestEffort(s.conn, { type: 'read', id: receipt.id });
    }
  }

  _onScreen() {
    return this._pageOnScreen() && !this._scrolledAway;
  }

  _pageOnScreen() {
    return !document.hidden && this.el.privacyScreen.classList.contains('hidden');
  }

  /**
   * A tab in the background gave no sign that a message or a call had come
   * in, so a reply could wait unseen for as long as the tab stayed hidden.
   * The title gets a dot: no count and no name, since the tab strip is on show
   * to anyone who can see the screen.
   */
  _markTitle() {
    if (this._plainTitle == null) this._plainTitle = document.title;
    document.title = '● ' + this._plainTitle;
  }

  _clearTitle() {
    if (this._plainTitle == null) return;
    document.title = this._plainTitle;
    this._plainTitle = null;
  }

  _flushUnseen() {
    if (!this._pageOnScreen()) return;
    this._clearTitle();
    if (this._scrolledAway) return;
    if (!this._unseen) return;
    const due = [...this._unseen];
    this._unseen.clear();
    for (const [key, { readMs, receipt }] of due) this._markSeen(key, readMs, receipt);
  }
}
