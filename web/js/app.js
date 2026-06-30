/**
 * Dead Drop — Main Application
 *
 * Orchestrates auth, signaling, P2P connection, encryption, and message lifecycle.
 */

import { CryptoLayer } from './crypto.js';
import { PeerConnection } from './peer.js';
import { MessageManager } from './messages.js';
import { FileTransferManager, MAX_FILE_SIZE } from './filetransfer.js';
import { register as srpRegister, ClientLogin } from './srp.js';

const ROOM_CODE_RE = /^[0-9a-f]{6,12}$/;
const MAX_MESSAGE_ID_LEN = 80;
const MAX_TEXT_LEN = 16 * 1024;
const ALLOWED_TTLS = new Set([0, 10, 30, 60, 300]);

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
    this.iceConfig = { iceServers: [] };
    this._relayOnly = false;

    // Call state
    this.callState = 'idle'; // idle | requesting | incoming | connecting | active
    this.localStream = null;
    this.remoteStream = null;
    this._callVideo = false;

    this._bindDOM();
    this._bindEvents();
    this._initMsgManager();
    this._readJoinHash();
    this._checkAuth();
  }

  // Parse a shared join link (#join=<code>) and remember the room to pre-fill.
  _readJoinHash() {
    const m = location.hash.match(/^#join=([0-9a-f]{6,12})$/i);
    if (m) {
      this._pendingJoin = m[1].toLowerCase();
      history.replaceState(null, '', location.pathname); // drop the code from the URL bar
    }
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
      authInvite:  $('#auth-invite'),
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
      relayToggle: $('#relay-toggle'),
      // Chat
      chatWrap:    $('#chat-wrap'),
      roomInfo:    $('#room-info'),
      roomCode:    $('#room-code'),
      copyBtn:     $('#copy-code'),
      messages:    $('#messages'),
      msgInput:    $('#msg-input'),
      sendBtn:     $('#send-btn'),
      attachBtn:   $('#attach-btn'),
      recordBtn:   $('#record-btn'),
      fileInput:   $('#file-input'),
      burnToggle:  $('#burn-toggle'),
      ttlSelect:   $('#ttl-select'),
      status:      $('#status'),
      panicBtn:    $('#panic-btn'),
      typingIndicator: $('#typing-indicator'),
      privacyScreen:   $('#privacy-screen'),
      verifyBar:   $('#verify-bar'),
      verifySas:   $('#verify-sas'),
      verifyBtn:   $('#verify-btn'),
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
    this.el.verifyBtn.addEventListener('click', () => this._markVerified());
    this.el.relayToggle.addEventListener('change', (e) => { this._relayOnly = e.target.checked; });
    // Chat
    this.el.sendBtn.addEventListener('click', () => this.sendMessage());
    this.el.msgInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); this.sendMessage(); }
    });
    this.el.msgInput.addEventListener('input', () => this._sendTyping());
    // Panic wipe: button or three Escapes within a second.
    this.el.panicBtn.addEventListener('click', () => this._panicWipe());
    window.addEventListener('keydown', (e) => this._onGlobalKey(e));
    // Privacy screen: blur messages whenever the tab is backgrounded.
    document.addEventListener('visibilitychange', () => this._onVisibilityChange());
    this.el.privacyScreen.addEventListener('click', () => this._hidePrivacyScreen());
    // File attach
    this.el.attachBtn.addEventListener('click', () => {
      if (this.encrypted) this.el.fileInput.click();
    });
    this.el.fileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) this.sendFile(file);
      e.target.value = '';
    });
    this.el.recordBtn.addEventListener('click', () => this._toggleRecord());
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
    this._setAuthBusy(true);
    try {
      const client = new ClientLogin(username, password);
      const ch = await this._postJSON('/api/srp/challenge', { username, A: client.start().A });
      if (ch.data.legacy) { await this._legacyLogin(username, password); return; }
      if (!ch.ok) { this._showAuthError(ch.data.error || 'Login failed'); return; }

      const { M1 } = await client.finish(ch.data.salt, ch.data.B);
      const auth = await this._postJSON('/api/srp/authenticate', { token: ch.data.token, M1 });
      if (!auth.ok) { this._showAuthError(auth.data.error || 'Invalid credentials'); return; }
      // Authenticate the SERVER too — proves it knows our verifier, not just us.
      if (!client.verifyServer(auth.data.M2)) {
        this._showAuthError('Server authentication failed — do not trust this connection.');
        return;
      }
      this.username = auth.data.username;
      this._afterAuth();
    } catch {
      this._showAuthError('Connection failed');
    } finally {
      this._setAuthBusy(false);
    }
  }

  // Legacy bcrypt accounts: log in the old way, then transparently upgrade to SRP
  // (the verifier is computed locally; the password is not resent).
  async _legacyLogin(username, password) {
    const res = await this._postJSON('/api/login', { username, password });
    if (!res.ok) { this._showAuthError(res.data.error || 'Invalid credentials'); return; }
    try {
      const { salt, verifier } = await srpRegister(username, password);
      await this._postJSON('/api/account/verifier', { salt, verifier });
    } catch { /* upgrade is best-effort; legacy login already succeeded */ }
    this.username = res.data.username;
    this._afterAuth();
  }

  async _register() {
    const username = this.el.authUser.value.trim();
    const password = this.el.authPass.value;
    const invite = this.el.authInvite.value.trim();
    if (!username || !password) return;
    if (password.length < 8) { this._showAuthError('Password must be at least 8 characters'); return; }
    if (!invite) { this._showAuthError('An invite code is required to register'); return; }

    this._hideAuthError();
    this._setAuthBusy(true);
    try {
      const { salt, verifier } = await srpRegister(username, password);
      const res = await this._postJSON('/api/srp/register', { username, salt, verifier, invite });
      if (res.ok) {
        this.username = res.data.username;
        this._afterAuth();
      } else {
        this._showAuthError(res.data.error || 'Registration failed');
      }
    } catch {
      this._showAuthError('Connection failed');
    } finally {
      this._setAuthBusy(false);
    }
  }

  _afterAuth() {
    this.el.authPass.value = '';
    this.el.authInvite.value = '';
    this._showPage('landing');
  }

  async _postJSON(path, body) {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    let data = {};
    try { data = await res.json(); } catch { /* empty body */ }
    return { ok: res.ok, status: res.status, data };
  }

  _setAuthBusy(busy) {
    this.el.loginBtn.disabled = busy;
    this.el.registerBtn.disabled = busy;
    this.el.loginBtn.textContent = busy ? '…' : 'Login';
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
        if (this._pendingJoin) {
          this.el.roomInput.value = this._pendingJoin;
          this._pendingJoin = null;
          this.el.joinBtn.focus();
        }
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
    await this._loadIceServers();
    try {
      await this._connectSignaling();
      this.ws.send(JSON.stringify({ type: 'join', room: this.roomCode }));
    } catch {
      this._renderSystem('Failed to connect to signaling server');
      return;
    }
    this._enterChat(this.roomCode);
    this._renderShareLink(this.roomCode);
    this._setStatus('waiting', '⏳ Waiting for peer…');
  }

  _renderShareLink(code) {
    const link = `${location.origin}/#join=${code}`;
    const el = document.createElement('div');
    el.className = 'msg system share-link';
    el.innerHTML = 'Send your peer this link (or the code above):<br>' +
      '<span class="share-url"></span> <button class="btn btn-sm copy-link-btn">Copy link</button>';
    el.querySelector('.share-url').textContent = link;
    const btn = el.querySelector('.copy-link-btn');
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(link).then(() => {
        btn.textContent = '✓ Copied';
        setTimeout(() => (btn.textContent = 'Copy link'), 1500);
      });
    });
    this.el.messages.appendChild(el);
    this.el.messages.scrollTop = this.el.messages.scrollHeight;
  }

  async joinRoom() {
    const code = this.el.roomInput.value.trim().toLowerCase();
    if (!code) return;
    if (!ROOM_CODE_RE.test(code)) {
      this._renderSystem('Invalid room code');
      return;
    }
    await this._loadIceServers();
    try {
      await this._connectSignaling();
    } catch {
      this._renderSystem('Failed to connect to signaling server');
      return;
    }
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
        let msg;
        try {
          msg = JSON.parse(e.data);
        } catch {
          console.warn('[ws] Ignoring malformed signaling message');
          return;
        }
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
      { iceServers: this.iceConfig.iceServers, relayOnly: this._relayOnly },
    );
    this.peer.onRemoteTrack = (stream) => this._onRemoteTrack(stream);
  }

  /** Fetch self-hosted STUN/TURN ICE servers (with an ephemeral credential). */
  async _loadIceServers() {
    try {
      const res = await fetch('/api/turn');
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.iceServers)) this.iceConfig.iceServers = data.iceServers;
      }
    } catch { /* keep host candidates only */ }
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
        if (sas) this._showVerify(sas);
        this.el.msgInput.focus();
        this.el.callBtn.style.display = '';
        break;
      case 'insecure':
        // Commit-reveal handshake (or rekey) failed — the channel may be tampered with.
        this.encrypted = false;
        this._setStatus('disconnected', '⛔ Insecure — handshake failed');
        this.el.verifyBar.classList.remove('hidden', 'verified');
        this.el.verifyBar.classList.add('insecure');
        this.el.verifySas.textContent = '⚠️ MITM?';
        this._renderSystem('⛔ Secure handshake failed — someone may be intercepting the connection. The session was closed. Do not trust this channel.');
        this.el.callBtn.style.display = 'none';
        this._endCallCleanup();
        break;
      case 'disconnected':
        this.encrypted = false;
        this._setStatus('disconnected', '❌ Peer disconnected');
        this._hideVerify();
        this._hideTyping();
        this.el.callBtn.style.display = 'none';
        this._endCallCleanup();
        break;
    }
  }

  _showVerify(sas) {
    this.el.verifyBar.classList.remove('hidden', 'verified', 'insecure');
    this.el.verifySas.textContent = sas;
    this.el.verifyBtn.textContent = 'Mark verified';
  }

  _markVerified() {
    this.el.verifyBar.classList.add('verified');
    this.el.verifyBtn.textContent = '✓ Verified';
  }

  _hideVerify() {
    this.el.verifyBar.classList.add('hidden');
    this.el.verifyBar.classList.remove('verified', 'insecure');
  }

  /* ── File transfer ── */

  async sendFile(file) {
    if (!this.encrypted) return;
    if (file.size > MAX_FILE_SIZE) {
      this._renderSystem(`File too large — max ${MAX_FILE_SIZE / 1024 / 1024} MB`);
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

    try {
      await this.fileMgr.send(file, id, this.crypto, this.peer, ttl, burn);
    } catch (err) {
      console.error('File send failed:', err);
      this._renderSystem('File transfer failed');
    }
  }

  /* ── Voice messages ── */

  async _toggleRecord() {
    if (this._recorder && this._recorder.state === 'recording') { this._stopRecording(); return; }
    if (!this.encrypted) return;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      this._recordStream = stream;
      const rec = new MediaRecorder(stream);
      this._recorder = rec;
      this._recChunks = [];
      rec.ondataavailable = (e) => { if (e.data && e.data.size) this._recChunks.push(e.data); };
      rec.onstop = () => this._finishRecording();
      rec.start();
      this.el.recordBtn.classList.add('recording');
      this.el.recordBtn.textContent = '⏹️';
      this._recTimer = setTimeout(() => this._stopRecording(), 120000); // 2 min cap
    } catch {
      this._renderSystem('Microphone access denied');
    }
  }

  _stopRecording() {
    clearTimeout(this._recTimer);
    if (this._recorder && this._recorder.state === 'recording') this._recorder.stop();
  }

  _finishRecording() {
    this.el.recordBtn.classList.remove('recording');
    this.el.recordBtn.textContent = '🎙️';
    if (this._recordStream) {
      for (const t of this._recordStream.getTracks()) t.stop();
      this._recordStream = null;
    }
    const type = (this._recorder && this._recorder.mimeType) || 'audio/webm';
    const blob = new Blob(this._recChunks, { type });
    this._recChunks = [];
    this._recorder = null;
    if (!blob.size || !this.encrypted) return;
    const ext = type.includes('ogg') ? 'ogg' : 'webm';
    this.sendFile(new File([blob], `voice-${Date.now()}.${ext}`, { type }));
  }

  /* ── Messaging ── */

  async sendMessage() {
    const text = this.el.msgInput.value.trim();
    if (!text || !this.encrypted) return;
    if (text.length > MAX_TEXT_LEN) {
      this._renderSystem('Message too large');
      return;
    }

    const burn = this.el.burnToggle.checked;
    const ttl = this._normalizeTTL(this.el.ttlSelect.value);
    const id = crypto.randomUUID();

    const { ciphertext, iv, epoch } = await this.crypto.encrypt(text);
    this.peer.send({ type: 'chat', id, ciphertext, iv, epoch, ttl, burnAfterReading: burn });

    this._renderMsg(id, text, true, ttl, burn);
    this.el.msgInput.value = '';
  }

  async _onPeerMessage(msg) {
    if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;
    switch (msg.type) {
      case 'typing':
        this._showTyping();
        break;

      case 'chat': {
        if (!this._validMessageID(msg.id) || !this._validEncryptedPayload(msg)) return;
        this._hideTyping();
        try {
          const text = await this.crypto.decrypt(msg.ciphertext, msg.iv, msg.epoch);
          if (typeof text !== 'string' || text.length > MAX_TEXT_LEN) return;
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
        if (!this._validMessageID(msg.id)) return;
        this.msgMgr.remoteDestroy(msg.id);
        break;
      case 'delete':
        if (!this._validMessageID(msg.id)) return;
        this.msgMgr.remoteDestroy(msg.id);
        break;

      // ── File transfer messages ──
      case 'file':
      case 'file-chunk':
      case 'file-end': {
        let result;
        try {
          result = this.fileMgr.handleMessage(msg);
        } catch (err) {
          console.warn('File transfer message rejected:', err);
          break;
        }
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
      const metaJson = await this.crypto.decrypt(result.meta.ciphertext, result.meta.iv, result.meta.epoch);
      const meta = this._sanitizeFileMeta(JSON.parse(metaJson));
      if (!meta) throw new Error('Invalid file metadata');

      // Decrypt file data
      const fileData = await this.crypto.decryptBinary(result.ciphertext, result.fileIv, result.fileEpoch);
      const blob    = new Blob([fileData], { type: meta.fileType });
      const blobUrl = URL.createObjectURL(blob);

      // Replace progress placeholder with actual preview
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
    ttl = this._normalizeTTL(ttl);
    burn = burn === true;
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
    ttl = this._normalizeTTL(ttl);
    burn = burn === true;
    meta = this._sanitizeFileMeta(meta);
    if (!meta) return;
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
    if (!this._validMessageID(id) || !Number.isSafeInteger(total) || total < 1) return;
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
    if (!this._validMessageID(id) || !Number.isSafeInteger(received) || !Number.isSafeInteger(total) || total < 1) return;
    const el = document.getElementById(`msg-${id}`);
    if (!el) return;
    const fill = el.querySelector('.progress-fill');
    const text = el.querySelector('.progress-text');
    const pct  = Math.round((received / total) * 100);
    if (fill) fill.style.width = `${pct}%`;
    if (text) text.textContent = `${received} / ${total}`;
  }

  _renderFileComplete(id, blobUrl, meta, ttl, burn) {
    if (!this._validMessageID(id)) return;
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
    if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
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

  /* ── Panic wipe ── */

  _onGlobalKey(e) {
    if (e.key !== 'Escape') return;
    const now = Date.now();
    this._escTimes = (this._escTimes || []).filter((t) => now - t < 1000);
    this._escTimes.push(now);
    if (this._escTimes.length >= 3) { this._escTimes = []; this._panicWipe(); }
  }

  async _panicWipe() {
    // Tear down every trace locally, end the session, and reload to a clean screen.
    this._cleanup();
    if (this.el.messages) this.el.messages.innerHTML = '';
    if (this.el.msgInput) this.el.msgInput.value = '';
    this.roomCode = null;
    this.username = null;
    try { await fetch('/api/logout', { method: 'POST' }); } catch { /* best effort */ }
    location.replace(location.origin + '/');
  }

  /* ── Typing indicator ── */

  _sendTyping() {
    if (!this.encrypted || !this.peer?.connected) return;
    const now = Date.now();
    if (this._lastTypingSent && now - this._lastTypingSent < 1500) return;
    this._lastTypingSent = now;
    try { this.peer.send({ type: 'typing' }); } catch { /* channel closed */ }
  }

  _showTyping() {
    this.el.typingIndicator.classList.remove('hidden');
    clearTimeout(this._typingHideTimer);
    this._typingHideTimer = setTimeout(() => this.el.typingIndicator.classList.add('hidden'), 3000);
  }

  _hideTyping() {
    clearTimeout(this._typingHideTimer);
    this.el.typingIndicator.classList.add('hidden');
  }

  /* ── Privacy screen ── */

  _onVisibilityChange() {
    if (document.hidden && !this.el.chatWrap.classList.contains('hidden')) {
      this.el.privacyScreen.classList.remove('hidden');
    }
  }

  _hidePrivacyScreen() {
    this.el.privacyScreen.classList.add('hidden');
  }

  _normalizeTTL(value) {
    const ttl = Number.parseInt(value, 10);
    return ALLOWED_TTLS.has(ttl) ? ttl : 0;
  }

  _validMessageID(id) {
    return typeof id === 'string' && id.length > 0 && id.length <= MAX_MESSAGE_ID_LEN;
  }

  _validEncryptedPayload(msg) {
    return typeof msg.ciphertext === 'string' && typeof msg.iv === 'string';
  }

  _sanitizeFileMeta(meta) {
    if (!meta || typeof meta !== 'object') return null;
    const fileName = typeof meta.fileName === 'string' && meta.fileName.trim()
      ? meta.fileName.slice(0, 180)
      : 'file';
    const fileType = typeof meta.fileType === 'string' && /^[\w.+-]+\/[\w.+-]+$/.test(meta.fileType)
      ? meta.fileType.slice(0, 100)
      : 'application/octet-stream';
    const fileSize = Number.isFinite(meta.fileSize) && meta.fileSize >= 0 && meta.fileSize <= MAX_FILE_SIZE
      ? meta.fileSize
      : 0;
    return { fileName, fileType, fileSize };
  }
}

new DeadDrop();

// Register the service worker (installable PWA + offline shell). Best-effort.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  });
}
