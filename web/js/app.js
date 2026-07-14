/**
 * Dead Drop — Main Application
 *
 * Orchestrates auth, signaling, P2P connection, encryption, and message lifecycle.
 */

import { CryptoLayer } from './crypto.js';
import { PeerConnection } from './peer.js';
import { MessageManager } from './messages.js';
import { FileTransferManager, MAX_FILE_SIZE } from './filetransfer.js';
import { register as srpRegister, ClientLogin, DEFAULT_KDF } from './srp.js';
import qrcode from './vendor/qrcode.js';
import { t, applyI18n, setLang, getLang } from './i18n.js';

const ROOM_CODE_RE = /^[0-9a-f]{12}$/;
const MESSAGE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PEER_ID_RE = /^[0-9a-f]{16}$/;
const MAX_TEXT_LEN = 16 * 1024;
const MAX_RENDERED_NODES = 600;
const ALLOWED_TTLS = new Set([0, 10, 30, 60, 300]);
const CURRENT_KDF_ITERATIONS = Number(DEFAULT_KDF.split(':')[1]);

function needsKdfUpgrade(kdf) {
  const match = /^pbkdf2:(\d+)$/.exec(kdf || '');
  return !match || Number(match[1]) < CURRENT_KDF_ITERATIONS;
}

class DeadDrop {
  constructor() {
    this.username = null;
    this.peerId = null;
    this.roomCode = null;
    this.ws = null;
    // Mesh: one pairwise session per remote peer — its own WebRTC connection AND
    // its own CryptoLayer (hybrid handshake, SAS, epochs). There is no group key;
    // every message is encrypted separately for each peer.
    this.peers = new Map(); // peerId → { conn, crypto, encrypted, sas, verified, label, color }
    this.msgMgr = null;
    this.fileMgr = new FileTransferManager();
    this.encrypted = false; // true when ≥1 pairwise session is encrypted and SAS-verified
    this.iceConfig = { iceServers: [] };
    this._relayOnly = false;
    this._coverEnabled = false; // decoy traffic to mask when real chatting happens
    this._coverTimer = null;

    // Call state (calls stay 1:1 — only available when exactly one peer is in the room)
    this.callState = 'idle'; // idle | requesting | incoming | connecting | active
    this._callPeerId = null;
    this.localStream = null;
    this.remoteStream = null;
    this._callVideo = false;

    this._bindDOM();
    this._bindEvents();
    this._initMsgManager();
    applyI18n();
    this._loadConfig();
    this._readJoinHash();
    this._checkAuth();
  }

  // Fetch public client config (e.g. whether registration is open).
  async _loadConfig() {
    try {
      const res = await fetch('/api/config');
      if (!res.ok) return;
      const cfg = await res.json();
      if (cfg.openRegistration) {
        this.el.authInvite.classList.add('hidden');
        const hint = this.el.authForm.querySelector('.auth-hint');
        if (hint) { hint.dataset.i18n = 'auth.hintOpen'; hint.textContent = t('auth.hintOpen'); }
      }
    } catch { /* default: invite required */ }
  }

  // Parse a shared join link (#join=<code>) and remember the room to pre-fill.
  _readJoinHash() {
    const m = location.hash.match(/^#join=([0-9a-f]{12})$/i);
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
      langBtn:     $('#lang-btn'),
      // Landing
      landing:     $('#landing'),
      userDisplay: $('#user-display'),
      logoutBtn:   $('#logout-btn'),
      settingsBtn:  $('#settings-btn'),
      accountPanel: $('#account-panel'),
      duressPass:   $('#duress-pass'),
      setDuressBtn: $('#set-duress-btn'),
      delAccountBtn:$('#del-account-btn'),
      createBtn:   $('#create-room'),
      joinBtn:     $('#join-room'),
      roomInput:   $('#room-code-input'),
      relayToggle: $('#relay-toggle'),
      coverToggle: $('#cover-toggle'),
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
      verifyRows:  $('#verify-rows'),
      qrVerify:       $('#qr-verify'),
      qrVerifyImg:    $('#qr-verify-img'),
      qrVerifyVideo:  $('#qr-verify-video'),
      qrVerifyStatus: $('#qr-verify-status'),
      qrVerifyClose:  $('#qr-verify-close'),
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
    // Hidden until the data channel is up. Done here (CSSOM) rather than with an
    // inline style attribute so the CSP needs no style-src 'unsafe-inline'.
    this.el.callBtn.style.display = 'none';
    for (const control of [this.el.msgInput, this.el.sendBtn, this.el.attachBtn, this.el.recordBtn]) {
      control.disabled = true;
    }
  }

  _bindEvents() {
    // Auth
    this.el.authForm.addEventListener('submit', (e) => { e.preventDefault(); this._login(); });
    this.el.registerBtn.addEventListener('click', () => this._register());
    this.el.langBtn.addEventListener('click', () => setLang(getLang() === 'ro' ? 'en' : 'ro'));
    this.el.logoutBtn.addEventListener('click', () => this._logout());
    this.el.settingsBtn.addEventListener('click', () => this.el.accountPanel.classList.toggle('hidden'));
    this.el.setDuressBtn.addEventListener('click', () => this._setDuress());
    this.el.delAccountBtn.addEventListener('click', () => this._deleteAccount());
    // Room
    this.el.createBtn.addEventListener('click', () => this.createRoom());
    this.el.joinBtn.addEventListener('click', () => this.joinRoom());
    this.el.copyBtn.addEventListener('click', () => this._copyCode());
    this.el.qrVerifyClose.addEventListener('click', () => this._closeQrVerify());
    this.el.relayToggle.addEventListener('change', (e) => { this._relayOnly = e.target.checked; });
    this.el.coverToggle.addEventListener('change', (e) => {
      this._coverEnabled = e.target.checked;
      if (this._coverEnabled) this._startCoverTraffic(); else this._stopCoverTraffic();
    });
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
    this.msgMgr = new MessageManager((wireId, peerId) => {
      if (peerId) {
        const s = this.peers.get(peerId);
        if (s?.verified) {
          this._sendBestEffort(s.conn, { type: 'delete', id: wireId });
        }
        return;
      }
      for (const s of this._verifiedSessions()) {
        this._sendBestEffort(s.conn, { type: 'delete', id: wireId });
      }
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

      // The challenge advertises each credential's password-stretch KDF
      // ('' = legacy account from before the PBKDF2 hardening).
      const { M1 } = await client.finish(ch.data.salt, ch.data.B, ch.data.kdf);
      // Second proof against the duress challenge, reusing the same ephemeral `a`.
      // Exactly one of the two proofs matches server-side (real vs duress password).
      let clientD = null, M1d = '';
      if (ch.data.salt2 && ch.data.B2) {
        clientD = new ClientLogin(username, password, client.a);
        clientD.start();
        M1d = (await clientD.finish(ch.data.salt2, ch.data.B2, ch.data.kdf2)).M1;
      }
      const auth = await this._postJSON('/api/srp/authenticate', { token: ch.data.token, M1, M1d });
      if (!auth.ok) { this._showAuthError(auth.data.error || 'Invalid credentials'); return; }
      // Authenticate the server too. Which locally-computed M2 matches tells this
      // browser which credential won; the server response remains identical for
      // primary and duress sessions, so it carries no observable decoy marker.
      const primaryOK = client.verifyServer(auth.data.M2);
      const duressOK = !!clientD && clientD.verifyServer(auth.data.M2);
      if (!primaryOK && !duressOK) {
        this._showAuthError('Server authentication failed — do not trust this connection.');
        return;
      }
      const usedDuress = !primaryOK && duressOK;
      this.username = auth.data.username;
      // Transparent hardening upgrade: if the credential that just logged in
      // predates the PBKDF2 stretch, re-derive it stretched and store the new
      // verifier. The server routes this to the right slot (real vs duress).
      const usedKdf = usedDuress ? ch.data.kdf2 : ch.data.kdf;
      if (needsKdfUpgrade(usedKdf)) {
        try {
          const up = await srpRegister(username, password);
          await this._postJSON('/api/account/verifier', up);
        } catch { /* best-effort; login already succeeded */ }
      }
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
      const { salt, verifier, kdf } = await srpRegister(username, password);
      await this._postJSON('/api/account/verifier', { salt, verifier, kdf });
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
    // Invite requirement is enforced by the server; the field is hidden when
    // registration is open, so don't block on it here.

    this._hideAuthError();
    this._setAuthBusy(true);
    try {
      const { salt, verifier, kdf } = await srpRegister(username, password);
      const res = await this._postJSON('/api/srp/register', { username, salt, verifier, kdf, invite });
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
    this.el.accountPanel.classList.add('hidden');
    this._showPage('landing');
  }

  // Set (or update) the duress password. Computed locally — never sent in the clear.
  async _setDuress() {
    const pw = this.el.duressPass.value;
    if (pw.length < 8) {
      this.el.setDuressBtn.textContent = t('duress.set');
      this.el.duressPass.focus();
      return;
    }
    const { salt, verifier, kdf } = await srpRegister(this.username, pw);
    const res = await this._postJSON('/api/account/duress', { salt, verifier, kdf });
    this.el.duressPass.value = '';
    this.el.setDuressBtn.textContent = res.ok ? t('duress.saved') : (res.data.error || t('duress.set'));
    setTimeout(() => (this.el.setDuressBtn.textContent = t('duress.set')), 1800);
  }

  async _deleteAccount() {
    if (!confirm(t('account.confirmDelete'))) return;
    try { await this._postJSON('/api/account/delete', {}); } catch { /* */ }
    this._cleanup();
    location.replace(location.origin + '/');
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
    this.el.loginBtn.textContent = busy ? '…' : t('auth.login');
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
        this.el.settingsBtn.style.display = '';
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
    this._setStatus('waiting', t('st.waiting'));
  }

  _renderShareLink(code) {
    const link = `${location.origin}/#join=${code}`;
    const el = document.createElement('div');
    el.className = 'msg system share-link';
    el.innerHTML = '<span class="share-intro"></span><br>' +
      '<span class="share-url"></span> <button class="btn btn-sm copy-link-btn"></button>';
    el.querySelector('.share-intro').textContent = t('share.intro');
    el.querySelector('.share-url').textContent = link;
    const btn = el.querySelector('.copy-link-btn');
    btn.textContent = t('share.copy');
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(link).then(() => {
        btn.textContent = t('share.copied');
        setTimeout(() => (btn.textContent = t('share.copy')), 1500);
      });
    });
    const qr = this._qrDataURL(link);
    if (qr) {
      const img = document.createElement('img');
      img.className = 'share-qr';
      img.src = qr;
      img.alt = 'QR code — scan to join';
      el.appendChild(img);
    }
    this.el.messages.appendChild(el);
    this._pruneRenderedNodes();
    this.el.messages.scrollTop = this.el.messages.scrollHeight;
  }

  _qrDataURL(text) {
    try {
      const qr = qrcode(0, 'M');
      qr.addData(text);
      qr.make();
      return qr.createDataURL(5, 2);
    } catch { return null; }
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
      let settled = false;
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const socket = new WebSocket(`${proto}//${location.host}/ws`);
      this.ws = socket;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        socket.close();
        reject(new Error('WebSocket welcome timeout'));
      }, 15000);

      socket.onmessage = (e) => {
        let msg;
        try {
          msg = JSON.parse(e.data);
        } catch {
          console.warn('[ws] Ignoring malformed signaling message');
          return;
        }
        if (msg.type === 'welcome' && !this.peerId && this._validPeerID(msg.peerId)) {
          this.peerId = msg.peerId;
          settled = true;
          clearTimeout(timer);
          resolve();
        }
        this._onSignal(msg).catch((err) => console.warn('[ws] signaling message failed', err));
      };

      socket.onclose = () => {
        clearTimeout(timer);
        this._setStatus('disconnected', '❌ Server disconnected');
        if (!settled) {
          settled = true;
          reject(new Error('WebSocket closed before welcome'));
        }
      };
      socket.onerror = () => {
        clearTimeout(timer);
        // Could be auth failure — recheck
        this._checkAuth();
        if (!settled) {
          settled = true;
          reject(new Error('WebSocket error'));
        }
      };
    });
  }

  async _onSignal(msg) {
    switch (msg.type) {
      case 'peer-joined':
        if (!this._validPeerID(msg.peerId) || msg.peerId === this.peerId) return;
        if (!this.peers.has(msg.peerId)) {
          this._setStatus('connecting', '🔗 Peer found — connecting P2P…');
        }
        // Deterministic initiator per pair: the lower peerId creates the offer.
        if (this.peerId < msg.peerId) {
          await this._ensureSession(msg.peerId).conn.createOffer(msg.peerId);
        }
        break;

      case 'peer-left':
        if (!this._validPeerID(msg.peerId)) return;
        this._dropSession(msg.peerId, t('st.peerLeft'));
        break;

      case 'error':
        this._setStatus('disconnected', `❌ ${msg.peerId || 'Unknown error'}`);
        break;

      case 'offer': {
        if (!this._validSignal(msg)) return;
        const s = this._ensureSession(msg.from);
        await s.conn.handleOffer(msg.from, JSON.parse(msg.payload));
        break;
      }

      case 'answer':
        if (!this._validSignal(msg)) return;
        await this.peers.get(msg.from)?.conn.handleAnswer(JSON.parse(msg.payload));
        break;

      case 'ice-candidate':
        if (!this._validSignal(msg)) return;
        await this.peers.get(msg.from)?.conn.handleIceCandidate(JSON.parse(msg.payload));
        break;
    }
  }

  /* ── Pairwise session registry (mesh) ── */

  _ensureSession(peerId) {
    if (!this._validPeerID(peerId) || peerId === this.peerId) {
      throw new Error('Invalid remote peer id');
    }
    let s = this.peers.get(peerId);
    if (s) return s;
    const cryptoLayer = new CryptoLayer();
    const conn = new PeerConnection(
      { send: (o) => this.ws.send(JSON.stringify(o)) },
      cryptoLayer,
      (m) => this._onPeerMessage(peerId, m),
      (state, sas) => this._onConnState(peerId, state, sas),
      { iceServers: this.iceConfig.iceServers, relayOnly: this._relayOnly },
    );
    conn.onRemoteTrack = (stream) => this._onRemoteTrack(stream);
    s = {
      conn,
      crypto: cryptoLayer,
      encrypted: false,
      sas: null,
      localVerified: false,
      verified: false,
      label: 'Peer ' + peerId.slice(0, 4).toUpperCase(),
      color: this._peerColor(peerId),
    };
    this.peers.set(peerId, s);
    return s;
  }

  /** Remove one pairwise session (peer left / channel closed / handshake failed). */
  _dropSession(peerId, sysMsg) {
    const s = this.peers.get(peerId);
    if (!s) return;
    this.peers.delete(peerId); // delete first — close() re-enters _onConnState
    this.fileMgr.abortScope(peerId);
    if (this._callPeerId === peerId) this._endCallCleanup();
    try { s.conn.close(); } catch { /* already closed */ }
    s.crypto.destroy();
    if (sysMsg) this._renderSystem(`${sysMsg} (${s.label})`);
    this._refreshRoomState();
  }

  _encryptedSessions() {
    return [...this.peers.values()].filter((s) => s.encrypted);
  }

  _verifiedSessions() {
    return [...this.peers.values()].filter(
      (s) => s.encrypted && s.verified && s.conn.userVerified,
    );
  }

  /** Deterministic per-peer color for sender labels. */
  _peerColor(peerId) {
    let h = 0;
    for (const c of peerId) h = (h * 31 + c.charCodeAt(0)) % 360;
    return `hsl(${h}, 65%, 62%)`;
  }

  /** Recompute the aggregate room state: status bar, call button, verify bar. */
  _refreshRoomState() {
    const enc = this._encryptedSessions();
    const verified = this._verifiedSessions();
    this.encrypted = verified.length > 0;
    if (verified.length > 0) {
      const extra = this.peers.size > verified.length ? ' ⏳' : '';
      this._setStatus('encrypted',
        (verified.length === 1
          ? t('st.verified')
          : t('st.verifiedN').replace('{n}', String(verified.length))) + extra);
    } else if (enc.length > 0) {
      this._setStatus('connecting', t('st.unverified'));
    } else if (this.peers.size > 0) {
      this._setStatus('connecting', '🔗 P2P connected — exchanging keys…');
    } else {
      this.encrypted = false;
      this._setStatus('waiting', t('st.waiting'));
      this._hideTyping();
    }
    // Calls stay strictly 1:1 and require both human identity verification and
    // exact binding of the DTLS certificate to the verified crypto session.
    const callable = verified.length === 1
      && this.peers.size === 1
      && verified[0].conn.mediaVerified;
    this.el.callBtn.style.display = (callable || this.callState !== 'idle') ? '' : 'none';
    // Cover traffic runs whenever it's enabled and there's someone to cover for.
    if (this._coverEnabled && verified.length > 0 && !this._coverTimer) this._startCoverTraffic();
    else if (verified.length === 0) this._stopCoverTraffic();
    for (const control of [this.el.msgInput, this.el.sendBtn, this.el.attachBtn, this.el.recordBtn]) {
      control.disabled = !this.encrypted;
    }
    this._renderVerifyBar();
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

  _onConnState(peerId, state, sas) {
    const s = this.peers.get(peerId);
    switch (state) {
      case 'connected':
        if (!this.encrypted) this._setStatus('connected', '🔗 P2P connected — exchanging keys…');
        break;
      case 'encrypted':
        if (!s) return;
        s.encrypted = true;
        s.sas = sas;
        s.verified = false;
        this._renderSystem(`⚠️ ${s.label} ${t('sys.awaitVerify')}`);
        this._refreshRoomState();
        break;
      case 'media-verified':
        // Transport binding alone is insufficient; the human SAS gate remains.
        this._refreshRoomState();
        break;
      case 'verified-ready':
        if (!s) return;
        s.localVerified = true;
        s.verified = true;
        this._renderSystem(`✅ ${s.label} ${t('sys.verified')}`);
        this._refreshRoomState();
        this.el.msgInput.focus();
        break;
      case 'insecure':
        // Commit-reveal handshake (or rekey) with THIS peer failed. Drop only that
        // pair — other verified sessions in the room are unaffected.
        this._renderSystem(`⛔ ${t('sys.insecure').replace('{peer}', s?.label ?? 'peer')}`);
        this.el.verifyBar.classList.remove('hidden');
        this.el.verifyBar.classList.add('insecure');
        setTimeout(() => this.el.verifyBar.classList.remove('insecure'), 5000);
        this._dropSession(peerId);
        break;
      case 'disconnected':
        this._dropSession(peerId, `👋 ${t('sys.left')}`);
        break;
    }
  }

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
      okBtn.addEventListener('click', () => this._markVerified(peerId, false));
      row.append(label, sas, qrBtn, okBtn);
      this.el.verifyRows.appendChild(row);
    }
  }

  _markVerified(peerId, verifiedByQR = false) {
    const s = this.peers.get(peerId);
    if (!s || !s.encrypted) return;
    if (!verifiedByQR && !window.confirm(t('verify.confirm'))) return;
    s.localVerified = true;
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
    const qr = this._qrDataURL(token);
    if (qr) this.el.qrVerifyImg.src = qr;
    this.el.qrVerifyStatus.textContent = `${s.label} — ${t('qr.scanning')}`;
    this.el.qrVerifyStatus.classList.remove('match', 'mismatch');
    this.el.qrVerify.classList.remove('hidden');
    await this._startQrScan(token);
  }

  async _startQrScan(expected) {
    try {
      // The 250KB decoder is only ever loaded (same-origin) when scanning starts.
      await import('./vendor/jsqr.js');
      this._qrStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' }, audio: false,
      });
    } catch {
      this.el.qrVerifyStatus.textContent = t('qr.cameraFail');
      return;
    }
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
      this._markVerified(this._qrPeerId, true);
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
    if (this._qrRaf) { cancelAnimationFrame(this._qrRaf); this._qrRaf = null; }
    if (this._qrStream) {
      for (const track of this._qrStream.getTracks()) track.stop();
      this._qrStream = null;
    }
    this.el.qrVerifyVideo.srcObject = null;
  }

  _closeQrVerify() {
    this._stopQrScan();
    this.el.qrVerify.classList.add('hidden');
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

    // Fan out to every peer, each copy encrypted with that pair's own keys.
    // Send sequentially so a group cannot multiply the 25 MB plaintext and
    // ciphertext buffers in memory for every peer at once.
    const results = [];
    for (const [peerId, s] of this.peers) {
      if (!s.verified || !s.conn.userVerified) continue;
      try {
        await this.fileMgr.send(file, id, s.crypto, s.conn, ttl, burn, null, peerId);
        results.push({ status: 'fulfilled' });
      } catch (reason) {
        results.push({ status: 'rejected', reason });
      }
    }
    if (results.some((r) => r.status === 'rejected')) {
      console.error('File send failed:', results.find((r) => r.status === 'rejected')?.reason);
      this._renderSystem('File transfer failed for at least one peer');
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

    // Pairwise E2E: encrypt separately for every peer with that pair's own keys.
    for (const s of this._verifiedSessions()) {
      try {
        const { ciphertext, iv, epoch } = await s.crypto.encrypt(text);
        await s.conn.send({ type: 'chat', id, ciphertext, iv, epoch, ttl, burnAfterReading: burn });
      } catch (err) {
        console.warn('Send failed for one peer:', err);
      }
    }

    this._renderMsg(id, text, true, ttl, burn);
    this.el.msgInput.value = '';
  }

  async _onPeerMessage(peerId, msg) {
    if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;
    const s = this.peers.get(peerId);
    if (!s || !s.verified || !s.conn.userVerified) return;
    switch (msg.type) {
      case 'cover':
        // Decoy packet from the peer's cover-traffic generator — sealed and
        // padded exactly like a real message, so it's indistinguishable on the
        // wire. Silently discarded; never shown, never acknowledged.
        break;

      case 'typing':
        this._showTyping(s.label);
        break;

      case 'chat': {
        if (!this._validMessageID(msg.id) || !this._validEncryptedPayload(msg)) return;
        this._hideTyping();
        try {
          const text = await s.crypto.decrypt(msg.ciphertext, msg.iv, msg.epoch);
          if (typeof text !== 'string' || text.length > MAX_TEXT_LEN) return;
          this._renderMsg(msg.id, text, false, msg.ttl, msg.burnAfterReading, s, peerId);
          if (msg.burnAfterReading) {
            await this._sendBestEffort(s.conn, { type: 'read', id: msg.id });
          }
        } catch (err) {
          console.error('Decryption failed:', err.message);
        }
        break;
      }
      case 'read':
        if (!this._validMessageID(msg.id)) return;
        this.msgMgr.remoteDestroy(this._messageKey(null, msg.id));
        break;
      case 'delete':
        if (!this._validMessageID(msg.id)) return;
        if (this.msgMgr.has(this._messageKey(null, msg.id))) {
          this.msgMgr.remoteDestroy(this._messageKey(null, msg.id));
        } else {
          this.msgMgr.remoteDestroy(this._messageKey(peerId, msg.id));
        }
        break;

      // ── File transfer messages ──
      case 'file':
      case 'file-chunk':
      case 'file-end': {
        let result;
        try {
          result = this.fileMgr.handleMessage(msg, peerId);
        } catch (err) {
          console.warn('File transfer message rejected:', err);
          break;
        }
        if (!result) break;
        switch (result.event) {
          case 'start':
            this._renderFileProgress(result.id, 0, result.totalChunks, peerId);
            break;
          case 'progress':
            this._updateFileProgress(result.id, result.received, result.totalChunks, peerId);
            break;
          case 'complete':
            await this._onFileComplete(result, s, peerId);
            break;
          case 'error':
            document.getElementById(
              this._domMessageId(this._messageKey(result.scope || peerId, result.id)),
            )?.remove();
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
        this._handleCallSignal(peerId, msg);
        break;
    }
  }

  async _onFileComplete(result, s, peerId) {
    let fileData;
    try {
      // Decrypt metadata
      const metaJson = await s.crypto.decrypt(result.meta.ciphertext, result.meta.iv, result.meta.epoch);
      const meta = this._sanitizeFileMeta(JSON.parse(metaJson));
      if (!meta) throw new Error('Invalid file metadata');

      // Decrypt file data
      fileData = await s.crypto.decryptBinary(result.ciphertext, result.fileIv, result.fileEpoch);
      const blob    = new Blob([fileData], { type: meta.fileType });
      const blobUrl = URL.createObjectURL(blob);

      // Replace progress placeholder with actual preview
      this._renderFileComplete(
        result.id, blobUrl, meta, result.ttl, result.burnAfterReading, s, peerId,
      );
    } catch (err) {
      console.error('File decryption failed:', err.message);
      this._renderSystem('Failed to decrypt file');
    } finally {
      new Uint8Array(result.ciphertext).fill(0);
      if (fileData) new Uint8Array(fileData).fill(0);
    }
  }

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
    const enc = this._verifiedSessions();
    if (this.callState !== 'idle' || enc.length !== 1 || this.peers.size !== 1) return;
    if (!enc[0].conn.mediaVerified) return;
    this._callPeerId = [...this.peers.keys()][0];
    this._startCall(true);
  }

  async _startCall(video) {
    this.callState = 'requesting';
    this._callVideo = video;
    await this._sendBestEffort(this._callConn(), { type: 'call-req', video });
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
      await this._sendBestEffort(this._callConn(), { type: 'call-reject', reason: 'media-error' });
      this.callState = 'idle';
      this._renderSystem('Failed to access camera/microphone');
      return;
    }

    this.el.localVideo.srcObject = this.localStream;
    this._toggleCallOverlay(true);
    this._showCallStatus('🔄 Connecting…');
    await this._sendBestEffort(this._callConn(), { type: 'call-accept' });
  }

  _rejectCall() {
    this.el.incomingCall.classList.add('hidden');
    this.callState = 'idle';
    this._sendBestEffort(this._callConn(), { type: 'call-reject' });
  }

  _handleCallSignal(peerId, msg) {
    // Everything after call-req must come from the peer the call is with.
    if (msg.type !== 'call-req' && peerId !== this._callPeerId) return;
    if (msg.type === 'call-req' && typeof msg.video !== 'boolean') return;
    if ((msg.type === 'call-offer' || msg.type === 'call-answer')
        && (typeof msg.sdp !== 'string' || msg.sdp.length > 64 * 1024)) return;
    if (msg.type === 'call-mute'
        && msg.audio !== undefined && typeof msg.audio !== 'boolean') return;
    if (msg.type === 'call-mute'
        && msg.video !== undefined && typeof msg.video !== 'boolean') return;
    switch (msg.type) {
      case 'call-req':    this._onCallReq(peerId, msg); break;
      case 'call-accept': this._onCallAccept();     break;
      case 'call-reject': this._onCallReject();     break;
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
      await this._sendBestEffort(this._callConn(), { type: 'call-end' });
      this._endCallCleanup();
      this._renderSystem('Failed to access camera/microphone');
      return;
    }

    this.el.localVideo.srcObject = this.localStream;
    this._showCallStatus('🔄 Connecting media…');

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

  _onCallReject() {
    this._endCallCleanup();
    this._renderSystem('Call declined');
  }

  async _onCallOffer(msg) {
    try {
      const offer = JSON.parse(msg.sdp);
      const answer = await this._callConn().acceptMedia(offer, this.localStream);
      await this._sendBestEffort(
        this._callConn(), { type: 'call-answer', sdp: JSON.stringify(answer) },
      );
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
      await this._callConn().completeMedia(answer);
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
    this._sendBestEffort(this._callConn(), { type: 'call-end' });
    this._endCallCleanup();
  }

  _endCallCleanup() {
    this.callState = 'idle';
    this._callConn()?.stopMedia();
    this._callPeerId = null;
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
    this._refreshRoomState();
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
    this._sendBestEffort(this._callConn(), {
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
    this._sendBestEffort(this._callConn(), {
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

  _renderMsg(id, text, mine, ttl, burn, sender = null, peerId = null) {
    ttl = this._normalizeTTL(ttl);
    burn = burn === true;
    const el = document.createElement('div');
    el.className = `msg ${mine ? 'mine' : 'theirs'}`;
    if (burn) el.classList.add('burn');

    let meta = '';
    if (burn) meta += '<span class="burn-badge">🔥 BURN</span> ';
    if (ttl > 0) meta += `<span class="countdown">${ttl}s</span>`;

    el.innerHTML = `
      ${this._senderTag(mine, sender)}
      <div class="msg-text">${this._esc(text)}</div>
      ${meta ? `<div class="msg-meta">${meta}</div>` : ''}
    `;
    this._applySenderColor(el, sender);

    this.el.messages.appendChild(el);
    this._pruneRenderedNodes();
    this.el.messages.scrollTop = this.el.messages.scrollHeight;

    const key = this._messageKey(mine ? null : peerId, id);
    this.msgMgr.add(key, el, ttl, burn, mine, null, { wireId: id, peerId });
    if (!mine) this.msgMgr.markRead(key);
  }

  /* ── UI helpers ── */

  _renderFileMsg(id, blobUrl, meta, mine, ttl, burn, sender = null, peerId = null) {
    ttl = this._normalizeTTL(ttl);
    burn = burn === true;
    meta = this._sanitizeFileMeta(meta);
    if (!meta) return;
    const el = document.createElement('div');
    el.className = `msg ${mine ? 'mine' : 'theirs'} file-msg`;
    if (burn) el.classList.add('burn');
    const key = this._messageKey(mine ? null : peerId, id);
    el.id = this._domMessageId(key);

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
      ${this._senderTag(mine, sender)}
      <div class="file-content">${preview}</div>
      <div class="file-details">
        <span class="file-name">${escaped}</span>
        <span class="file-size">${this._fmtSize(meta.fileSize)}</span>
        <a href="${blobUrl}" download="${escaped}" class="file-download" title="Download">💾</a>
      </div>
      ${badges ? `<div class="msg-meta">${badges}</div>` : ''}
    `;
    this._applySenderColor(el, sender);

    this.el.messages.appendChild(el);
    this._pruneRenderedNodes();
    this.el.messages.scrollTop = this.el.messages.scrollHeight;

    this.msgMgr.add(key, el, ttl, burn, mine, blobUrl, {
      wireId: id,
      peerId,
      blobBytes: meta.fileSize,
    });
    if (!mine) this.msgMgr.markRead(key);
  }

  _renderFileProgress(id, received, total, peerId) {
    if (!this._validMessageID(id) || !Number.isSafeInteger(total) || total < 1) return;
    const key = this._messageKey(peerId, id);
    const el = document.createElement('div');
    el.className = 'msg theirs file-msg';
    el.id = this._domMessageId(key);
    el.innerHTML = `
      <div class="file-receiving">
        <span>📦 Receiving file…</span>
        <div class="progress-bar"><div class="progress-fill"></div></div>
        <span class="progress-text">0 / ${total}</span>
      </div>
    `;
    this.el.messages.appendChild(el);
    this._pruneRenderedNodes();
    this.el.messages.scrollTop = this.el.messages.scrollHeight;
  }

  _updateFileProgress(id, received, total, peerId) {
    if (!this._validMessageID(id) || !Number.isSafeInteger(received) || !Number.isSafeInteger(total) || total < 1) return;
    const el = document.getElementById(this._domMessageId(this._messageKey(peerId, id)));
    if (!el) return;
    const fill = el.querySelector('.progress-fill');
    const text = el.querySelector('.progress-text');
    const pct  = Math.round((received / total) * 100);
    if (fill) fill.style.width = `${pct}%`;
    if (text) text.textContent = `${received} / ${total}`;
  }

  _renderFileComplete(id, blobUrl, meta, ttl, burn, sender = null, peerId = null) {
    if (!this._validMessageID(id)) return;
    const key = this._messageKey(peerId, id);
    const old = document.getElementById(this._domMessageId(key));
    if (old) old.remove();
    this._renderFileMsg(id, blobUrl, meta, false, ttl, burn, sender, peerId);
  }

  /** Sender attribution tag — only on peers' messages, only in group rooms.
   * The color is applied afterwards via _applySenderColor (CSSOM), because an
   * inline style attribute would violate the strict CSP. */
  _senderTag(mine, sender) {
    if (mine || !sender || this.peers.size < 2) return '';
    return `<div class="msg-sender">${this._esc(sender.label)}</div>`;
  }

  _applySenderColor(el, sender) {
    const tag = el.querySelector('.msg-sender');
    if (tag && sender) tag.style.color = sender.color;
  }

  _renderSystem(text) {
    const el = document.createElement('div');
    el.className = 'msg system';
    el.textContent = text;
    this.el.messages.appendChild(el);
    this._pruneRenderedNodes();
    this.el.messages.scrollTop = this.el.messages.scrollHeight;
  }

  _setStatus(cls, text) {
    this.el.status.className = `status ${cls}`;
    this.el.status.textContent = text;
  }

  _pruneRenderedNodes() {
    while (this.el.messages.childElementCount > MAX_RENDERED_NODES) {
      const oldest = this.el.messages.firstElementChild;
      if (!oldest) break;
      if (!this.msgMgr.removeElement(oldest)) oldest.remove();
    }
  }

  _sendBestEffort(conn, msg) {
    if (!conn) return Promise.resolve(false);
    try {
      return Promise.resolve(conn.send(msg))
        .then(() => true)
        .catch((err) => {
          console.warn('[peer] best-effort send failed', err);
          return false;
        });
    } catch (err) {
      console.warn('[peer] best-effort send failed', err);
      return Promise.resolve(false);
    }
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

  /* ── Cover traffic ──
   * Occasional padded decoys make isolated small control packets less obvious.
   * This is not constant-rate traffic shaping: timing, volume, large messages,
   * files and calls remain visible to a network observer. */

  _startCoverTraffic() {
    this._stopCoverTraffic();
    if (!this._coverEnabled) return;
    const tick = () => {
      if (!this._coverEnabled) { this._coverTimer = null; return; }
      for (const s of this._verifiedSessions()) {
        this._sendBestEffort(s.conn, { type: 'cover' });
      }
      // Randomized 4–16 s cadence so there's no fixed heartbeat fingerprint.
      this._coverTimer = setTimeout(tick, 4000 + Math.random() * 12000);
    };
    this._coverTimer = setTimeout(tick, 2000 + Math.random() * 4000);
  }

  _stopCoverTraffic() {
    if (this._coverTimer) { clearTimeout(this._coverTimer); this._coverTimer = null; }
  }

  _cleanup() {
    this._closeQrVerify();
    this._stopCoverTraffic();
    this._endCallCleanup();
    this.msgMgr?.destroyAll();
    // Tear down every pairwise session; clear the map first so the close
    // callbacks find nothing to re-process.
    const sessions = [...this.peers.values()];
    this.peers.clear();
    this.fileMgr.destroyAll();
    for (const s of sessions) {
      try { s.conn.close(); } catch { /* already closed */ }
      s.crypto.destroy();
    }
    const ws = this.ws;
    this.ws = null;
    if (ws) {
      ws.onmessage = null;
      ws.onclose = null;
      ws.onerror = null;
      ws.close();
    }
    this.peerId = null;
    this.roomCode = null;
    this.el.messages.replaceChildren();
    this.encrypted = false;
    for (const control of [this.el.msgInput, this.el.sendBtn, this.el.attachBtn, this.el.recordBtn]) {
      control.disabled = true;
    }
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
    if (!this.encrypted) return;
    const now = Date.now();
    if (this._lastTypingSent && now - this._lastTypingSent < 1500) return;
    this._lastTypingSent = now;
    for (const s of this._verifiedSessions()) {
      this._sendBestEffort(s.conn, { type: 'typing' });
    }
  }

  _showTyping(label) {
    const text = this.el.typingIndicator.querySelector('[data-i18n="typing"]');
    if (text) {
      text.textContent = this.peers.size > 1 && label ? `${label} — ${t('typing')}` : t('typing');
    }
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
    return typeof id === 'string' && MESSAGE_ID_RE.test(id);
  }

  _validPeerID(id) {
    return typeof id === 'string' && PEER_ID_RE.test(id);
  }

  _validSignal(msg) {
    return this._validPeerID(msg.from)
      && msg.from !== this.peerId
      && typeof msg.payload === 'string'
      && msg.payload.length > 0
      && msg.payload.length <= 64 * 1024;
  }

  _messageKey(peerId, wireId) {
    return `${peerId || 'self'}:${wireId}`;
  }

  _domMessageId(key) {
    return `msg-${encodeURIComponent(key)}`;
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
