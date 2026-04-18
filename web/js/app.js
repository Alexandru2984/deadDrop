/**
 * Dead Drop — Main Application
 *
 * Orchestrates auth, signaling, P2P connection, encryption, and message lifecycle.
 */

import { CryptoLayer } from './crypto.js';
import { PeerConnection } from './peer.js';
import { MessageManager } from './messages.js';

class DeadDrop {
  constructor() {
    this.username = null;
    this.peerId = null;
    this.roomCode = null;
    this.ws = null;
    this.crypto = new CryptoLayer();
    this.peer = null;
    this.msgMgr = null;
    this.encrypted = false;

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
      burnToggle:  $('#burn-toggle'),
      ttlSelect:   $('#ttl-select'),
      status:      $('#status'),
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
    await this._connectSignaling();
    const code = this._genRoomCode();
    this.roomCode = code;
    this.ws.send(JSON.stringify({ type: 'join', room: code }));
    this._enterChat(code);
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

      case 'offer':
        this._createPeerConn();
        this.peer.handleOffer(msg.from, JSON.parse(msg.payload));
        break;

      case 'answer':
        this.peer?.handleAnswer(JSON.parse(msg.payload));
        break;

      case 'ice-candidate':
        this.peer?.handleIceCandidate(JSON.parse(msg.payload));
        break;
    }
  }

  _createPeerConn() {
    this.peer = new PeerConnection(
      { send: (o) => this.ws.send(JSON.stringify(o)) },
      this.crypto,
      (msg) => this._onPeerMessage(msg),
      (state) => this._onConnState(state),
    );
  }

  /* ── P2P connection state ── */

  _onConnState(state) {
    switch (state) {
      case 'connected':
        this._setStatus('connected', '🔗 P2P connected — exchanging keys…');
        break;
      case 'encrypted':
        this.encrypted = true;
        this._setStatus('encrypted', '🔒 End-to-end encrypted');
        this.el.msgInput.focus();
        break;
      case 'disconnected':
        this.encrypted = false;
        this._setStatus('disconnected', '❌ Peer disconnected');
        break;
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
    return d.innerHTML;
  }

  _genRoomCode() {
    const hex = '0123456789abcdef';
    const arr = crypto.getRandomValues(new Uint8Array(3));
    return Array.from(arr, (b) => hex[b >> 4] + hex[b & 0xf]).join('');
  }

  _cleanup() {
    this.msgMgr?.destroyAll();
    this.peer?.close();
    this.crypto?.destroy();
    this.ws?.close();
    this.peer = null;
    this.encrypted = false;
  }
}

new DeadDrop();
