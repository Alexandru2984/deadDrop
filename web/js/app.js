/**
 * Dead Drop — Main Application
 *
 * Orchestrates auth, signaling, P2P connection, encryption, and message lifecycle.
 */

import { CryptoLayer } from './crypto.js';
import { PeerConnection } from './peer.js';
import { MessageManager } from './messages.js';
import { FileTransferManager, MAX_FILE_SIZE } from './filetransfer.js';

class DeadDrop {
  constructor() {
    this.username = null;
    this.peerId = null;
    this.roomCode = null;
    this.ws = null;
    this.crypto = new CryptoLayer();
    this.peer = null;
    this.msgMgr = null;
    this.fileMgr = new FileTransferManager();
    this.encrypted = false;

    // Call state
    this.callState = 'idle'; // idle | requesting | incoming | connecting | active
    this.localStream = null;
    this.remoteStream = null;
    this._callVideo = false;

    this._bindDOM();
    this._bindEvents();
    this._initMsgManager();
    this._checkAuth();
  }

  /* ── DOM ── */

  _bindDOM() {
    const $ = (s) => document.querySelector(s);
    this.el = {
      // Auth
      auth:        $('#auth'),
      authForm:    $('#auth-form'),
      authUser:    $('#auth-user'),
      authPass:    $('#auth-pass'),
      authError:   $('#auth-error'),
      loginBtn:    $('#login-btn'),
      registerBtn: $('#register-btn'),
      // Landing
      landing:     $('#landing'),
      userDisplay: $('#user-display'),
      logoutBtn:   $('#logout-btn'),
      createBtn:   $('#create-room'),
      joinBtn:     $('#join-room'),
      roomInput:   $('#room-code-input'),
      // Chat
      chatWrap:    $('#chat-wrap'),
      roomInfo:    $('#room-info'),
      roomCode:    $('#room-code'),
      copyBtn:     $('#copy-code'),
      messages:    $('#messages'),
      msgInput:    $('#msg-input'),
      sendBtn:     $('#send-btn'),
      attachBtn:   $('#attach-btn'),
      fileInput:   $('#file-input'),
      burnToggle:  $('#burn-toggle'),
      ttlSelect:   $('#ttl-select'),
      status:      $('#status'),
      // Call
      callBtn:       $('#call-btn'),
      incomingCall:  $('#incoming-call'),
      acceptCall:    $('#accept-call'),
      rejectCall:    $('#reject-call'),
      callOverlay:   $('#call-overlay'),
      callStatusBar: $('#call-status-bar'),
      remoteVideo:   $('#remote-video'),
      localVideo:    $('#local-video'),
      remotePlaceholder: $('#remote-placeholder'),
      toggleMic:     $('#toggle-mic'),
      toggleCam:     $('#toggle-cam'),
      backToChat:    $('#back-to-chat'),
      endCall:       $('#end-call'),
    };
  }

  _bindEvents() {
    // Auth
    this.el.authForm.addEventListener('submit', (e) => { e.preventDefault(); this._login(); });
    this.el.registerBtn.addEventListener('click', () => this._register());
    this.el.logoutBtn.addEventListener('click', () => this._logout());
    // Room
    this.el.createBtn.addEventListener('click', () => this.createRoom());
    this.el.joinBtn.addEventListener('click', () => this.joinRoom());
    this.el.copyBtn.addEventListener('click', () => this._copyCode());
    // Chat
    this.el.sendBtn.addEventListener('click', () => this.sendMessage());
    this.el.msgInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.sendMessage(); }
    });
    // File attach
    this.el.attachBtn.addEventListener('click', () => {
      if (this.encrypted) this.el.fileInput.click();
    });
    this.el.fileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) this.sendFile(file);
      e.target.value = '';
    });
    // Drag-and-drop on messages area
    const drop = this.el.messages;
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(ev =>
      drop.addEventListener(ev, (e) => { e.preventDefault(); e.stopPropagation(); })
    );
    drop.addEventListener('dragenter', () => drop.classList.add('drag-over'));
    drop.addEventListener('dragleave', (e) => {
      if (!drop.contains(e.relatedTarget)) drop.classList.remove('drag-over');
    });
    drop.addEventListener('drop', (e) => {
      drop.classList.remove('drag-over');
      const file = e.dataTransfer.files[0];
      if (file && this.encrypted) this.sendFile(file);
    });

    // Call controls
    this.el.callBtn.addEventListener('click', () => this._onCallBtnClick());
    this.el.acceptCall.addEventListener('click', () => this._acceptCall());
    this.el.rejectCall.addEventListener('click', () => this._rejectCall());
    this.el.toggleMic.addEventListener('click', () => this._toggleMic());
    this.el.toggleCam.addEventListener('click', () => this._toggleCam());
    this.el.backToChat.addEventListener('click', () => this._toggleCallOverlay(false));
    this.el.endCall.addEventListener('click', () => this._endCall());

    window.addEventListener('beforeunload', () => this._cleanup());
  }

  _initMsgManager() {
    this.msgMgr = new MessageManager((id) => {
      if (this.peer?.connected) this.peer.send({ type: 'delete', id });
    });
  }

  /* ── Auth ── */

  async _checkAuth() {
    try {
      const res = await fetch('/api/me');
      if (res.ok) {
        const data = await res.json();
        this.username = data.username;
        this._showPage('landing');
      } else {
        this._showPage('auth');
      }
    } catch {
      this._showPage('auth');
    }
  }

  async _login() {
    const username = this.el.authUser.value.trim();
    const password = this.el.authPass.value;
    if (!username || !password) return;

    this._hideAuthError();
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (res.ok) {
        this.username = data.username;
        this._showPage('landing');
      } else {
        this._showAuthError(data.error);
      }
    } catch {
      this._showAuthError('Connection failed');
    }
  }

  async _register() {
    const username = this.el.authUser.value.trim();
    const password = this.el.authPass.value;
    if (!username || !password) return;

    this._hideAuthError();
    try {
      const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (res.ok) {
        this.username = data.username;
        this._showPage('landing');
      } else {
        this._showAuthError(data.error);
      }
    } catch {
      this._showAuthError('Connection failed');
    }
  }

  async _logout() {
    this._cleanup();
    await fetch('/api/logout', { method: 'POST' });
    this.username = null;
    this.el.authUser.value = '';
    this.el.authPass.value = '';
    this._showPage('auth');
  }

  _showAuthError(msg) {
    this.el.authError.textContent = msg;
    this.el.authError.classList.remove('hidden');
  }

  _hideAuthError() {
    this.el.authError.classList.add('hidden');
  }

  /* ── Page navigation ── */

  _showPage(name) {
    this.el.auth.classList.add('hidden');
    this.el.landing.classList.add('hidden');
    this.el.chatWrap.classList.add('hidden');

    switch (name) {
      case 'auth':
        this.el.auth.classList.remove('hidden');
        this.el.authUser.focus();
        break;
      case 'landing':
        this.el.landing.classList.remove('hidden');
        this.el.userDisplay.textContent = this.username;
        break;
      case 'chat':
        this.el.chatWrap.classList.remove('hidden');
        break;
    }
  }

  /* ── Room management ── */

  async createRoom() {
    // Request a server-generated room code (stronger entropy)
    try {
      const res = await fetch('/api/room', { method: 'POST' });
      const data = await res.json();
      if (!data.code) {
        this._renderSystem(data.error || 'Failed to create room');
        return;
      }
      this.roomCode = data.code;
    } catch {
      this._renderSystem('Failed to create room');
      return;
    }
    await this._connectSignaling();
    this.ws.send(JSON.stringify({ type: 'join', room: this.roomCode }));
    this._enterChat(this.roomCode);
    this._setStatus('waiting', '⏳ Waiting for peer…');
  }

  async joinRoom() {
    const code = this.el.roomInput.value.trim().toLowerCase();
    if (!code) return;
    await this._connectSignaling();
    this.roomCode = code;
    this.ws.send(JSON.stringify({ type: 'join', room: code }));
    this._enterChat(code);
    this._setStatus('connecting', '🔄 Joining room…');
  }

  _enterChat(code) {
    this._showPage('chat');
    this.el.roomCode.textContent = code;
    this.el.roomInfo.classList.remove('hidden');
  }

  /* ── Signaling (WebSocket → signaling server) ── */

  _connectSignaling() {
    return new Promise((resolve, reject) => {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      this.ws = new WebSocket(`${proto}//${location.host}/ws`);

      this.ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === 'welcome' && !this.peerId) {
          this.peerId = msg.peerId;
          resolve();
        }
        this._onSignal(msg);
      };

      this.ws.onclose = () => this._setStatus('disconnected', '❌ Server disconnected');
      this.ws.onerror = () => {
        // Could be auth failure — recheck
        this._checkAuth();
        reject(new Error('WebSocket error'));
      };
    });
  }

  _onSignal(msg) {
    switch (msg.type) {
      case 'peer-joined':
        this._setStatus('connecting', '🔗 Peer found — connecting P2P…');
        // Deterministic initiator: lower peerId creates the offer
        if (this.peerId < msg.peerId) {
          this._createPeerConn();
          this.peer.createOffer(msg.peerId);
        }
        break;

      case 'peer-left':
        this._setStatus('disconnected', '👋 Peer disconnected');
        this.peer?.close();
        this.peer = null;
        this.encrypted = false;
        this.crypto.destroy();
        break;

      case 'error':
        this._setStatus('disconnected', `❌ ${msg.peerId || 'Unknown error'}`);
        break;

      case 'offer':
        this._createPeerConn();
        try { this.peer.handleOffer(msg.from, JSON.parse(msg.payload)); } catch {}
        break;

      case 'answer':
        try { this.peer?.handleAnswer(JSON.parse(msg.payload)); } catch {}
        break;

      case 'ice-candidate':
        try { this.peer?.handleIceCandidate(JSON.parse(msg.payload)); } catch {}
        break;
    }
  }

  _createPeerConn() {
    this.peer = new PeerConnection(
      { send: (o) => this.ws.send(JSON.stringify(o)) },
      this.crypto,
      (msg) => this._onPeerMessage(msg),
      (state, sas) => this._onConnState(state, sas),
    );
    this.peer.onRemoteTrack = (stream) => this._onRemoteTrack(stream);
  }

  /* ── P2P connection state ── */

  _onConnState(state, sas) {
    switch (state) {
      case 'connected':
        this._setStatus('connected', '🔗 P2P connected — exchanging keys…');
        break;
      case 'encrypted':
        this.encrypted = true;
        this._setStatus('encrypted', `🔒 E2E Encrypted`);
        if (sas) {
          this._renderSystem(`🔐 Security code: ${sas} — Verify this matches your peer's code to confirm no one is intercepting.`);
        }
        this.el.msgInput.focus();
        this.el.callBtn.style.display = '';
        break;
      case 'disconnected':
        this.encrypted = false;
        this._setStatus('disconnected', '❌ Peer disconnected');
        this.el.callBtn.style.display = 'none';
        this._endCallCleanup();
        break;
    }
  }

  /* ── File transfer ── */

  async sendFile(file) {
    if (!this.encrypted) return;
    if (file.size > MAX_FILE_SIZE) {
      this._renderSystem(`File too large — max ${MAX_FILE_SIZE / 1024 / 1024} MB`);
      return;
    }

    const burn = this.el.burnToggle.checked;
    const ttl  = parseInt(this.el.ttlSelect.value, 10);
    const id   = crypto.randomUUID();
    const meta = {
      fileName: file.name,
      fileType: file.type || 'application/octet-stream',
      fileSize: file.size,
    };

    // Show preview immediately (sender has the file locally)
    const blobUrl = URL.createObjectURL(file);
    this._renderFileMsg(id, blobUrl, meta, true, ttl, burn);

    try {
      await this.fileMgr.send(file, id, this.crypto, this.peer, ttl, burn);
    } catch (err) {
      console.error('File send failed:', err);
      this._renderSystem('File transfer failed');
    }
  }

  /* ── Messaging ── */

  async sendMessage() {
    const text = this.el.msgInput.value.trim();
    if (!text || !this.encrypted) return;

    const burn = this.el.burnToggle.checked;
    const ttl = parseInt(this.el.ttlSelect.value, 10);
    const id = crypto.randomUUID();

    const { ciphertext, iv } = await this.crypto.encrypt(text);
    this.peer.send({ type: 'chat', id, ciphertext, iv, ttl, burnAfterReading: burn });

    this._renderMsg(id, text, true, ttl, burn);
    this.el.msgInput.value = '';
  }

  async _onPeerMessage(msg) {
    switch (msg.type) {
      case 'chat': {
        try {
          const text = await this.crypto.decrypt(msg.ciphertext, msg.iv);
          this._renderMsg(msg.id, text, false, msg.ttl, msg.burnAfterReading);
          if (msg.burnAfterReading) {
            this.peer.send({ type: 'read', id: msg.id });
          }
        } catch (err) {
          console.error('Decryption failed:', err.message);
        }
        break;
      }
      case 'read':
        this.msgMgr.remoteDestroy(msg.id);
        break;
      case 'delete':
        this.msgMgr.remoteDestroy(msg.id);
        break;

      // ── File transfer messages ──
      case 'file':
      case 'file-chunk':
      case 'file-end': {
        const result = this.fileMgr.handleMessage(msg);
        if (!result) break;
        switch (result.event) {
          case 'start':
            this._renderFileProgress(result.id, 0, result.totalChunks);
            break;
          case 'progress':
            this._updateFileProgress(result.id, result.received, result.totalChunks);
            break;
          case 'complete':
            await this._onFileComplete(result);
            break;
          case 'error':
            this._renderSystem(`⚠️ File transfer failed: ${result.error}`);
            break;
        }
        break;
      }

      // ── Call signaling (over encrypted data channel) ──
      case 'call-req':
      case 'call-accept':
      case 'call-reject':
      case 'call-offer':
      case 'call-answer':
      case 'call-end':
      case 'call-mute':
        this._handleCallSignal(msg);
        break;
    }
  }

  async _onFileComplete(result) {
    try {
      // Decrypt metadata
      const metaJson = await this.crypto.decrypt(result.meta.ciphertext, result.meta.iv);
      const meta = JSON.parse(metaJson);

      // Decrypt file data
      const fileData = await this.crypto.decryptBinary(result.ciphertext, result.fileIv);
      const fileType = typeof meta.fileType === 'string' ? meta.fileType : 'application/octet-stream';
      const blob    = new Blob([fileData], { type: fileType });
      const blobUrl = URL.createObjectURL(blob);

      // Replace progress placeholder with actual preview
      meta.fileType = fileType; // ensure validated type for rendering
      this._renderFileComplete(result.id, blobUrl, meta, result.ttl, result.burnAfterReading);
    } catch (err) {
      console.error('File decryption failed:', err.message);
      this._renderSystem('Failed to decrypt file');
    }
  }

  /* ── Calls ── */

  _onCallBtnClick() {
    if (this.callState === 'active') {
      this._toggleCallOverlay(true);
      return;
    }
    if (this.callState !== 'idle' || !this.encrypted) return;
    this._startCall(true);
  }

  async _startCall(video) {
    this.callState = 'requesting';
    this._callVideo = video;
    this.peer.send({ type: 'call-req', video });
    this._showCallStatus('📞 Calling…');
    this._toggleCallOverlay(true);
  }

  async _acceptCall() {
    this.el.incomingCall.classList.add('hidden');
    this.callState = 'connecting';

    try {
      this.localStream = await this._getMedia(this._callVideo);
    } catch (err) {
      console.error('getUserMedia failed:', err);
      this.peer.send({ type: 'call-reject', reason: 'media-error' });
      this.callState = 'idle';
      this._renderSystem('Failed to access camera/microphone');
      return;
    }

    this.el.localVideo.srcObject = this.localStream;
    this._toggleCallOverlay(true);
    this._showCallStatus('🔄 Connecting…');
    this.peer.send({ type: 'call-accept' });
  }

  _rejectCall() {
    this.el.incomingCall.classList.add('hidden');
    this.callState = 'idle';
    this.peer.send({ type: 'call-reject' });
  }

  _handleCallSignal(msg) {
    switch (msg.type) {
      case 'call-req':    this._onCallReq(msg);    break;
      case 'call-accept': this._onCallAccept();     break;
      case 'call-reject': this._onCallReject();     break;
      case 'call-offer':  this._onCallOffer(msg);   break;
      case 'call-answer': this._onCallAnswer(msg);  break;
      case 'call-end':    this._onCallEnd();        break;
      case 'call-mute':   this._onCallMute(msg);    break;
    }
  }

  _onCallReq(msg) {
    if (this.callState !== 'idle') {
      this.peer.send({ type: 'call-reject', reason: 'busy' });
      return;
    }
    this.callState = 'incoming';
    this._callVideo = msg.video;
    this.el.incomingCall.classList.remove('hidden');
  }

  async _onCallAccept() {
    if (this.callState !== 'requesting') return;
    this.callState = 'connecting';

    try {
      this.localStream = await this._getMedia(this._callVideo);
    } catch (err) {
      console.error('getUserMedia failed:', err);
      this.peer.send({ type: 'call-end' });
      this._endCallCleanup();
      this._renderSystem('Failed to access camera/microphone');
      return;
    }

    this.el.localVideo.srcObject = this.localStream;
    this._showCallStatus('🔄 Connecting media…');

    try {
      const offer = await this.peer.startMedia(this.localStream);
      this.peer.send({ type: 'call-offer', sdp: JSON.stringify(offer) });
    } catch (err) {
      console.error('Media offer failed:', err);
      this._endCall();
    }
  }

  _onCallReject() {
    this._endCallCleanup();
    this._renderSystem('Call declined');
  }

  async _onCallOffer(msg) {
    try {
      const offer = JSON.parse(msg.sdp);
      const answer = await this.peer.acceptMedia(offer, this.localStream);
      this.peer.send({ type: 'call-answer', sdp: JSON.stringify(answer) });
      this.callState = 'active';
      this._showCallStatus('');
      this._updateCallBtn(true);
    } catch (err) {
      console.error('Call offer handling failed:', err);
      this._endCall();
    }
  }

  async _onCallAnswer(msg) {
    try {
      const answer = JSON.parse(msg.sdp);
      await this.peer.completeMedia(answer);
      this.callState = 'active';
      this._showCallStatus('');
      this._updateCallBtn(true);
    } catch (err) {
      console.error('Call answer handling failed:', err);
      this._endCall();
    }
  }

  _onCallEnd() {
    this._endCallCleanup();
    this._renderSystem('Call ended');
  }

  _onCallMute(msg) {
    if (msg.video !== undefined) {
      this.el.remotePlaceholder.classList.toggle('hidden', msg.video);
    }
  }

  _endCall() {
    if (this.callState === 'idle') return;
    this.peer?.send({ type: 'call-end' });
    this._endCallCleanup();
  }

  _endCallCleanup() {
    this.callState = 'idle';
    this.peer?.stopMedia();
    if (this.localStream) {
      for (const track of this.localStream.getTracks()) track.stop();
      this.localStream = null;
    }
    this.remoteStream = null;
    this.el.localVideo.srcObject = null;
    this.el.remoteVideo.srcObject = null;
    this._toggleCallOverlay(false);
    this.el.incomingCall.classList.add('hidden');
    this.el.remotePlaceholder.classList.remove('hidden');
    this._updateCallBtn(false);
    this._resetMuteButtons();
  }

  _onRemoteTrack(stream) {
    this.remoteStream = stream;
    this.el.remoteVideo.srcObject = stream;
    this.el.remotePlaceholder.classList.add('hidden');
  }

  _toggleCallOverlay(show) {
    this.el.callOverlay.classList.toggle('hidden', !show);
  }

  _showCallStatus(text) {
    this.el.callStatusBar.textContent = text;
    this.el.callStatusBar.classList.toggle('hidden', !text);
  }

  _updateCallBtn(inCall) {
    this.el.callBtn.textContent = inCall ? '🟢' : '📞';
    this.el.callBtn.title = inCall ? 'Show call' : 'Start call';
  }

  _toggleMic() {
    if (!this.localStream) return;
    const track = this.localStream.getAudioTracks()[0];
    if (!track) return;
    track.enabled = !track.enabled;
    this.el.toggleMic.classList.toggle('muted', !track.enabled);
    this.el.toggleMic.textContent = track.enabled ? '🎤' : '🔇';
    this.peer?.send({
      type: 'call-mute',
      audio: track.enabled,
      video: this.localStream.getVideoTracks()[0]?.enabled ?? false,
    });
  }

  _toggleCam() {
    if (!this.localStream) return;
    const track = this.localStream.getVideoTracks()[0];
    if (!track) return;
    track.enabled = !track.enabled;
    this.el.toggleCam.classList.toggle('muted', !track.enabled);
    this.el.toggleCam.textContent = track.enabled ? '📹' : '🚫';
    this.peer?.send({
      type: 'call-mute',
      audio: this.localStream.getAudioTracks()[0]?.enabled ?? true,
      video: track.enabled,
    });
  }

  _resetMuteButtons() {
    this.el.toggleMic.classList.remove('muted');
    this.el.toggleMic.textContent = '🎤';
    this.el.toggleCam.classList.remove('muted');
    this.el.toggleCam.textContent = '📹';
  }

  async _getMedia(withVideo) {
    try {
      return await navigator.mediaDevices.getUserMedia({ audio: true, video: withVideo });
    } catch (err) {
      if (withVideo) {
        // Fallback to audio-only if camera unavailable
        return await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
      }
      throw err;
    }
  }

  _renderMsg(id, text, mine, ttl, burn) {
    const el = document.createElement('div');
    el.className = `msg ${mine ? 'mine' : 'theirs'}`;
    if (burn) el.classList.add('burn');

    let meta = '';
    if (burn) meta += '<span class="burn-badge">🔥 BURN</span> ';
    if (ttl > 0) meta += `<span class="countdown">${ttl}s</span>`;

    el.innerHTML = `
      <div class="msg-text">${this._esc(text)}</div>
      ${meta ? `<div class="msg-meta">${meta}</div>` : ''}
    `;

    this.el.messages.appendChild(el);
    this.el.messages.scrollTop = this.el.messages.scrollHeight;

    this.msgMgr.add(id, el, ttl, burn, mine);
    if (!mine) this.msgMgr.markRead(id);
  }

  /* ── UI helpers ── */

  _renderFileMsg(id, blobUrl, meta, mine, ttl, burn) {
    const el = document.createElement('div');
    el.className = `msg ${mine ? 'mine' : 'theirs'} file-msg`;
    if (burn) el.classList.add('burn');
    el.id = `msg-${id}`;

    let preview = '';
    const escaped = this._esc(meta.fileName);
    if (meta.fileType.startsWith('image/')) {
      preview = `<img src="${blobUrl}" alt="${escaped}" class="file-preview-img" loading="lazy" />`;
    } else if (meta.fileType.startsWith('video/')) {
      preview = `<video src="${blobUrl}" controls playsinline class="file-preview-video"></video>`;
    } else if (meta.fileType.startsWith('audio/')) {
      preview = `<audio src="${blobUrl}" controls class="file-preview-audio"></audio>`;
    } else {
      preview = `<div class="file-generic"><span class="file-icon-lg">📄</span></div>`;
    }

    let badges = '';
    if (burn) badges += '<span class="burn-badge">🔥 BURN</span> ';
    if (ttl > 0) badges += `<span class="countdown">${ttl}s</span>`;

    el.innerHTML = `
      <div class="file-content">${preview}</div>
      <div class="file-details">
        <span class="file-name">${escaped}</span>
        <span class="file-size">${this._fmtSize(meta.fileSize)}</span>
        <a href="${blobUrl}" download="${escaped}" class="file-download" title="Download">💾</a>
      </div>
      ${badges ? `<div class="msg-meta">${badges}</div>` : ''}
    `;

    this.el.messages.appendChild(el);
    this.el.messages.scrollTop = this.el.messages.scrollHeight;

    this.msgMgr.add(id, el, ttl, burn, mine, blobUrl);
    if (!mine) this.msgMgr.markRead(id);
  }

  _renderFileProgress(id, received, total) {
    const el = document.createElement('div');
    el.className = 'msg theirs file-msg';
    el.id = `msg-${id}`;
    el.innerHTML = `
      <div class="file-receiving">
        <span>📦 Receiving file…</span>
        <div class="progress-bar"><div class="progress-fill" style="width: 0%"></div></div>
        <span class="progress-text">0 / ${total}</span>
      </div>
    `;
    this.el.messages.appendChild(el);
    this.el.messages.scrollTop = this.el.messages.scrollHeight;
  }

  _updateFileProgress(id, received, total) {
    const el = document.getElementById(`msg-${id}`);
    if (!el) return;
    const fill = el.querySelector('.progress-fill');
    const text = el.querySelector('.progress-text');
    const pct  = Math.round((received / total) * 100);
    if (fill) fill.style.width = `${pct}%`;
    if (text) text.textContent = `${received} / ${total}`;
  }

  _renderFileComplete(id, blobUrl, meta, ttl, burn) {
    const old = document.getElementById(`msg-${id}`);
    if (old) old.remove();
    this._renderFileMsg(id, blobUrl, meta, false, ttl, burn);
  }

  _renderSystem(text) {
    const el = document.createElement('div');
    el.className = 'msg system';
    el.textContent = text;
    this.el.messages.appendChild(el);
    this.el.messages.scrollTop = this.el.messages.scrollHeight;
  }

  _setStatus(cls, text) {
    this.el.status.className = `status ${cls}`;
    this.el.status.textContent = text;
  }

  _copyCode() {
    navigator.clipboard.writeText(this.roomCode).then(() => {
      this.el.copyBtn.textContent = '✓';
      setTimeout(() => (this.el.copyBtn.textContent = '📋'), 1500);
    });
  }

  _esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    // innerHTML escapes <, >, & but NOT quotes — add those for attribute safety
    return d.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  _fmtSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  _cleanup() {
    this._endCallCleanup();
    this.msgMgr?.destroyAll();
    this.peer?.close();
    this.crypto?.destroy();
    this.ws?.close();
    this.peer = null;
    this.encrypted = false;
  }
}

new DeadDrop();
