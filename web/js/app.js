/**
 * Dead Drop — Main Application
 *
 * Orchestrates auth, signaling, P2P connection, encryption, and message lifecycle.
 */

import { CryptoLayer } from './crypto.js';
import { PeerConnection } from './peer.js';
import { MessageManager } from './messages.js';
import { FileTransferManager, MAX_FILE_SIZE, AUTO_ACCEPT_SIZE, assertFileSizeBinding, safeFileMeta } from './filetransfer.js';
import { loadIdentity, ensureIdentity, clearIdentity, forgetContact, listContacts } from './identity.js';
import { t, applyI18n, setLang, getLang } from './i18n.js';
import { sanitizeIceConfig } from './util.js';
import { checkSupport } from './support.js';
import { getPref, setPref, clearPrefs, applyTheme } from './prefs.js';
import { scrubber, ROOM_CODE_RE, MESSAGE_ID_RE, PEER_ID_RE, MAX_TEXT_LEN, MAX_RENDERED_NODES, MAX_REMOTE_PEERS, SIGNAL_WINDOW_MS, MAX_SIGNAL_MESSAGES_PER_WINDOW, MAX_SIGNAL_BYTES_PER_WINDOW, ALLOWED_TTLS, appendPresent, h, serverMessage, roomCodeFrom, signOutOwed, setSignOutOwed } from './app-shared.js';
import { AuthMethods } from './app-auth.js';
import { VerifyMethods } from './app-verify.js';
import { FileMethods } from './app-files.js';
import { CallMethods } from './app-calls.js';
import { DropMethods } from './app-drops.js';

class DeadDrop {
  constructor() {
    this.username = null;
    this.peerId = null;
    this.roomCode = null;
    this._announced = new Set();
    this._verifyExpanded = false;
    this.ws = null;
    // Mesh: one pairwise session per remote peer — its own WebRTC connection AND
    // its own CryptoLayer (hybrid handshake, SAS, epochs). There is no group key;
    // every message is encrypted separately for each peer.
    this.peers = new Map(); // peerId → { conn, crypto, encrypted, sas, verified, label, color }
    // Opt-in saved contacts. Null until the user turns the feature on; while it
    // is null nothing long-lived is generated or presented to any peer.
    this.identity = null;
    this.msgMgr = null;
    this.fileMgr = new FileTransferManager();
    this.fileMgr.onLapse = (peerId, id, why) => this._onFileLapse(peerId, id, why);
    this.encrypted = false; // true when ≥1 pairwise session is encrypted and SAS-verified
    this.iceConfig = { iceServers: [] };
    this._iceExpiresAt = 0;
    // On by default: a direct connection hands the other person your IP
    // address. A missing relay blocks connection until the user chooses direct.
    this._relayOnly = getPref('relayOnly');
    this._coverEnabled = getPref('coverTraffic'); // decoy traffic to mask when real chatting happens
    this._coverTimer = null;
    this._signalWindowAt = Date.now();
    this._signalMessages = 0;
    this._signalBytes = 0;
    this._signalQ = Promise.resolve();
    this._signalGeneration = 0;
    this._workController = new AbortController();

    // Call state (calls stay 1:1 — only available when exactly one peer is in the room)
    this.callState = 'idle'; // idle | requesting | incoming | connecting | active
    this._callPeerId = null;
    // Which side of the call setup this is. An offer is only ever legitimate
    // for a callee waiting on one, an answer only for a caller that sent one.
    this._callRole = null;   // 'caller' | 'callee'
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

  // Parse a shared join link (#join=<code>, with &guest=<pass> for someone
  // without an account) and remember the room to pre-fill.
  _readJoinHash() {
    const m = location.hash.match(/^#join=([0-9a-f]{24})(?:&guest=([0-9a-f]{32}))?$/i);
    if (m) {
      this._pendingJoin = m[1].toLowerCase();
      this._pendingGuest = m[2] ? m[2].toLowerCase() : null;
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
      currentPass:  $('#current-pass'),
      contactsToggle: $('#contacts-toggle'),
      contactsList: $('#contacts-list'),
      duressPass:   $('#duress-pass'),
      setDuressBtn: $('#set-duress-btn'),
      newPass: $('#new-pass'),
      genPassBtn: $('#gen-pass-btn'),
      genPassNote: $('#gen-pass-note'),
      genNewPassBtn: $('#gen-new-pass-btn'),
      changePassBtn: $('#change-pass-btn'),
      delAccountBtn:$('#del-account-btn'),
      passMsg:      $('#pass-msg'),
      duressMsg:    $('#duress-msg'),
      signOutOthersBtn: $('#signout-others-btn'),
      sessionsMsg:  $('#sessions-msg'),
      deleteMsg:    $('#delete-msg'),
      createBtn:   $('#create-room'),
      joinBtn:     $('#join-room'),
      roomInput:   $('#room-code-input'),
      relayToggle: $('#relay-toggle'),
      coverToggle: $('#cover-toggle'),
      scrubToggle: $('#scrub-toggle'),
      typingToggle: $('#typing-toggle'),
      ringToggle: $('#ring-toggle'),
      replyBar: $('#reply-bar'),
      jumpNew: $('#jump-new'),
      imageViewer: $('#image-viewer'),
      imageViewerImg: $('#image-viewer-img'),
      imageViewerClose: $('#image-viewer-close'),
      callMenu: $('#call-menu'),
      callVoice: $('#call-voice'),
      callVideo: $('#call-video'),
      acceptAudio: $('#accept-audio'),
      replyBarText: $('#reply-bar-text'),
      replyCancel: $('#reply-cancel'),
      idleSelect: $('#idle-select'),
      themeSelect: $('#theme-select'),
      // Chat
      chatWrap:    $('#chat-wrap'),
      roomInfo:    $('#room-info'),
      roomCode:    $('#room-code'),
      copyBtn:     $('#copy-code'),
      messages:    $('#messages'),
      msgInput:    $('#msg-input'),
      landingError: $('#landing-error'),
      authInvited: $('#auth-invited'),
      dropsInbox: $('#drops-inbox'),
      dropsCompose: $('#drops-compose'),
      dropsTo: $('#drops-to'),
      dropsText: $('#drops-text'),
      dropsExpiry: $('#drops-expiry'),
      dropsRead: $('#drops-read'),
      dropsSend: $('#drops-send'),
      dropsStatus: $('#drops-status'),
      authGuest: $('#auth-guest'),
      guestJoinBtn: $('#guest-join-btn'),
      landingInvited: $('#landing-invited'),
      sendBtn:     $('#send-btn'),
      attachBtn:   $('#attach-btn'),
      recordBtn:   $('#record-btn'),
      recCancelBtn: $('#rec-cancel-btn'),
      chatFooter:  $('.chat-footer'),
      fileInput:   $('#file-input'),
      burnToggle:  $('#burn-toggle'),
      ttlSelect:   $('#ttl-select'),
      status:      $('#status'),
      panicBtn:    $('#panic-btn'),
      typingIndicator: $('#typing-indicator'),
      privacyScreen:   $('#privacy-screen'),
      privacyRinging:  $('#privacy-ringing'),
      verifyBar:   $('#verify-bar'),
      verifyRows:  $('#verify-rows'),
      qrVerify:       $('#qr-verify'),
      qrVerifyImg:    $('#qr-verify-img'),
      qrVerifyVideo:  $('#qr-verify-video'),
      qrVerifyStatus: $('#qr-verify-status'),
      qrVerifyClose:  $('#qr-verify-close'),
      keptAsk:        $('#kept-ask'),
      keptText:       $('#kept-ask-text'),
      keptNote:       $('#kept-ask-note'),
      keptRemove:     $('#kept-remove'),
      keptAsIs:       $('#kept-asis'),
      keptCancel:     $('#kept-cancel'),
      // Call
      callBtn:       $('#call-btn'),
      incomingCall:  $('#incoming-call'),
      incomingText:  $('#incoming-call-text'),
      acceptCall:    $('#accept-call'),
      rejectCall:    $('#reject-call'),
      callOverlay:   $('#call-overlay'),
      callStatusBar: $('#call-status-bar'),
      remoteVideo:   $('#remote-video'),
      localVideo:    $('#local-video'),
      remotePlaceholder: $('#remote-placeholder'),
      placeholderText: $('#placeholder-text'),
      toggleMic:     $('#toggle-mic'),
      toggleCam:     $('#toggle-cam'),
      flipCam:       $('#flip-cam'),
      shareScreen:   $('#share-screen'),
      screenNote:    $('#screen-note'),
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
    this.el.langBtn.addEventListener('click', () => {
      setLang(getLang() === 'ro' ? 'en' : 'ro');
      this._drawStatus();
    });
    this.el.logoutBtn.addEventListener('click', () => this._logout());
    this.el.guestJoinBtn.addEventListener('click', () => this._joinAsGuest());
    this.el.dropsSend.addEventListener('click', () => this._leaveDrop());
    window.addEventListener('online', () => { if (signOutOwed()) this._retrySignOut(0); });
    this.el.settingsBtn.addEventListener('click', () => {
      this.el.accountPanel.classList.toggle('hidden');
      if (this.el.accountPanel.classList.contains('hidden')) {
        this._restoreFocus();
      } else {
        // A fresh look at the panel starts without last time's results.
        for (const msg of [this.el.passMsg, this.el.duressMsg, this.el.sessionsMsg, this.el.deleteMsg]) msg.classList.add('hidden');
        this._renderContacts();
        this._captureFocus(this.el.accountPanel);
      }
    });
    this.el.contactsToggle.addEventListener('change', (e) => this._setContactsEnabled(e.target.checked));
    this.el.setDuressBtn.addEventListener('click', () => this._setDuress());
    this.el.changePassBtn.addEventListener('click', () => this._changePassword());
    this.el.genPassBtn.addEventListener('click', () => {
      this._fillPassphrase(this.el.authPass).then(() => this.el.genPassNote.classList.remove('hidden'));
    });
    this.el.genNewPassBtn.addEventListener('click', () => this._fillPassphrase(this.el.newPass));
    this.el.delAccountBtn.addEventListener('click', () => this._deleteAccount());
    this.el.signOutOthersBtn.addEventListener('click', () => this._signOutOthers());
    // Room
    this.el.createBtn.addEventListener('click', () => this.createRoom());
    this.el.joinBtn.addEventListener('click', () => this.joinRoom());
    this.el.copyBtn.addEventListener('click', () => this._copyCode());
    this.el.qrVerifyClose.addEventListener('click', () => this._closeQrVerify());
    this.el.keptRemove.addEventListener('click', () => this._answerKept('remove'));
    this.el.keptAsIs.addEventListener('click', () => this._answerKept('asIs'));
    this.el.keptCancel.addEventListener('click', () => this._answerKept(null));
    // Remembered switches. The markup's defaults are the safe ones; a stored
    // preference only ever changes them because the user did.
    this.el.relayToggle.checked = this._relayOnly;
    this.el.coverToggle.checked = this._coverEnabled;
    this.el.scrubToggle.checked = getPref('scrubMetadata');
    this.el.typingToggle.checked = getPref('typingIndicator');
    this.el.ringToggle.checked = getPref('callRing');
    this.el.idleSelect.value = String(getPref('idleLockMinutes'));
    this.el.themeSelect.value = getPref('theme');
    this.el.themeSelect.addEventListener('change', (e) => {
      setPref('theme', e.target.value);
      applyTheme(getPref('theme'));
    });
    this.el.ttlSelect.value = String(getPref('messageTtl'));
    this.el.ttlSelect.addEventListener('change', (e) => {
      setPref('messageTtl', Number.parseInt(e.target.value, 10));
    });
    this.el.idleSelect.toggleAttribute('data-off', this.el.idleSelect.value === '0');
    this.el.scrubToggle.addEventListener('change', (e) => setPref('scrubMetadata', e.target.checked));
    this.el.typingToggle.addEventListener('change', (e) => setPref('typingIndicator', e.target.checked));
    this.el.ringToggle.addEventListener('change', (e) => setPref('callRing', e.target.checked));
    this.el.idleSelect.addEventListener('change', (e) => {
      const minutes = Number.parseInt(e.target.value, 10);
      setPref('idleLockMinutes', minutes);
      e.target.toggleAttribute('data-off', minutes === 0);
      this._armIdleLock();
    });
    this.el.relayToggle.addEventListener('change', (e) => {
      this._relayOnly = e.target.checked;
      setPref('relayOnly', this._relayOnly);
    });
    this.el.coverToggle.addEventListener('change', (e) => {
      this._coverEnabled = e.target.checked;
      setPref('coverTraffic', this._coverEnabled);
      if (this._coverEnabled) this._startCoverTraffic(); else this._stopCoverTraffic();
    });
    // Chat
    this.el.sendBtn.addEventListener('click', () => this.sendMessage());
    this.el.messages.addEventListener('scroll', () => this._onLogScroll(), { passive: true });
    // The keyboard coming up, or the phone turning, shrinks the log from the
    // bottom: whoever was reading the latest message was left looking at
    // older ones.
    if (typeof ResizeObserver === 'function') new ResizeObserver(() => this._holdLogEnd()).observe(this.el.messages);
    // Anywhere on the picture closes it: there is nothing else to do there.
    this.el.imageViewer.addEventListener('click', () => this._closeImage());
    this.el.jumpNew.addEventListener('click', () => {
      this._scrollLogEnd();
      this._onLogScroll();
    });
    this.el.replyCancel.addEventListener('click', () => {
      this._cancelReply();
      this.el.msgInput.focus();
    });
    this.el.msgInput.addEventListener('keydown', (e) => {
      // Enter sends and Shift+Enter starts a new line — with a keyboard. On a
      // touch screen the return key writes a new line and Send sends, as in
      // every phone messenger. Never mid-composition: an IME uses Enter to
      // commit Japanese, Chinese or Korean text, not to send half of it.
      if (e.key !== 'Enter' || e.shiftKey || e.isComposing || e.keyCode === 229) return;
      if (window.matchMedia('(pointer: coarse)').matches) return;
      e.preventDefault();
      this.sendMessage();
    });
    this.el.msgInput.addEventListener('input', () => {
      this._fitComposer();
      this._sendTyping();
    });
    // Panic wipe: button or three Escapes within a second.
    this.el.panicBtn.addEventListener('click', () => this._panicWipe());
    window.addEventListener('keydown', (e) => this._onGlobalKey(e));
    // Privacy screen: blur messages whenever the tab is backgrounded.
    document.addEventListener('visibilitychange', () => this._onVisibilityChange());
    window.addEventListener('blur', () => this._showPrivacyScreen());
    window.addEventListener('focus', () => this._onPageBack());
    window.addEventListener('pageshow', () => this._onPageBack());
    window.addEventListener('popstate', () => this._onBack());
    for (const type of ['keydown', 'pointerdown', 'touchstart', 'wheel']) {
      document.addEventListener(type, () => this._noteActivity(), { passive: true, capture: true });
    }
    this.el.privacyScreen.addEventListener('click', () => this._hidePrivacyScreen());
    // File attach
    this.el.attachBtn.addEventListener('click', () => {
      if (this.encrypted) this.el.fileInput.click();
    });
    this.el.fileInput.addEventListener('change', (e) => {
      const files = [...e.target.files];
      e.target.value = '';
      this._sendFiles(files);
    });
    this.el.recordBtn.addEventListener('click', () => this._toggleRecord());
    this.el.recCancelBtn.addEventListener('click', () => this._discardRecording());
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
      this._sendFiles([...e.dataTransfer.files]);
    });
    // A screenshot pasted into the message field is sent like an attachment —
    // through the same metadata stripping. Pasted text is left to the field.
    this.el.msgInput.addEventListener('paste', (e) => {
      const files = [...(e.clipboardData?.files || [])];
      // Word, Excel and others put a picture of the selection on the clipboard
      // beside its text. Text there means the person copied text: paste it.
      if (!files.length || e.clipboardData.getData('text/plain')) return;
      e.preventDefault();
      this._sendFiles(files);
    });

    // Call controls
    this.el.callBtn.addEventListener('click', () => this._onCallBtnClick());
    this.el.acceptCall.addEventListener('click', () => this._acceptCall());
    this.el.acceptAudio.addEventListener('click', () => this._acceptCall(false));
    this.el.callVoice.addEventListener('click', () => this._placeCall(false));
    this.el.callVideo.addEventListener('click', () => this._placeCall(true));
    document.addEventListener('click', (e) => {
      if (this.el.callMenu.classList.contains('hidden') || e.target.closest('#call-menu, #call-btn')) return;
      this._showCallMenu(false);
    });
    this.el.rejectCall.addEventListener('click', () => this._rejectCall());
    this.el.toggleMic.addEventListener('click', () => this._toggleMic());
    this.el.toggleCam.addEventListener('click', () => this._toggleCam());
    this.el.flipCam.addEventListener('click', () => this._flipCam());
    this.el.shareScreen.addEventListener('click', () => this._toggleScreenShare());
    this.el.backToChat.addEventListener('click', () => this._toggleCallOverlay(false));
    this.el.endCall.addEventListener('click', () => this._endCall());

    window.addEventListener('beforeunload', () => this._cleanup());
  }

  _initMsgManager() {
    // Received files stay until their message goes; the oldest go first past
    // this. It has to hold the largest file that can be accepted, or that file
    // would push itself out the moment it arrived.
    const budget = { maxBlobBytes: MAX_FILE_SIZE + 4 * AUTO_ACCEPT_SIZE };
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
    }, budget);
    // Message key → the quotes of it in replies; bubble → its own quote.
    this._quotes = new Map();
    this._quoteOf = new WeakMap();
    this._replyTo = null;
    this.msgMgr.onRemoved = (key, el) => {
      this._forgetQuoted(key, el);
      // A picture shown full screen goes with its message: a timer or a burn
      // must not leave it on screen in the viewer.
      if (this._viewing === key) this._closeImage();
    };
  }

  /* ── Page navigation ── */

  _showPage(name) {
    document.querySelector('#boot')?.classList.add('hidden');
    if (name !== 'landing') this._stopDrops(name !== 'chat');
    this.el.auth.classList.add('hidden');
    this.el.landing.classList.add('hidden');
    this.el.chatWrap.classList.add('hidden');

    // Arriving through an invitation link: say so on whichever page comes
    // first, until the room is joined or left behind.
    this.el.authInvited.classList.toggle('hidden', !this._pendingJoin || !!this._pendingGuest);
    this.el.authGuest.classList.toggle('hidden', !this._pendingGuest);
    this.el.landingInvited.classList.toggle('hidden', !(name === 'landing' && (this._pendingJoin || this.guest)));
    // A guest has one room and no account: nothing to create, nothing to set.
    this.el.landing.classList.toggle('guest', !!this.guest);
    this.el.roomInput.readOnly = !!this.guest;
    const note = this.guest ? 'guest.landingNote' : 'invite.landingNote';
    if (this.el.landingInvited.dataset.i18n !== note) {
      this.el.landingInvited.dataset.i18n = note;
      this.el.landingInvited.textContent = t(note);
    }

    switch (name) {
      case 'auth':
        this.el.auth.classList.remove('hidden');
        this.el.authUser.focus();
        break;
      case 'landing':
        this.el.landing.classList.remove('hidden');
        this._refreshDrops();
        this.el.userDisplay.textContent = this.username;
        // Keyed for the translator only when it is a word of ours, never when
        // it is somebody's handle.
        if (this.guest) this.el.userDisplay.dataset.i18n = 'guest.name';
        else delete this.el.userDisplay.dataset.i18n;
        this.el.settingsBtn.style.display = this.guest ? 'none' : '';
        if (this.guest) this._pendingJoin = this._guestRoom;
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
    this._guardBack(name === 'chat');
  }

  /**
   * A conversation lives only in this page, so the back button — or the edge
   * swipe that a phone reads as one — ended it at a touch, with no way to get
   * it back. In a room, back now closes what is open over the conversation,
   * then asks for a second press before leaving.
   */
  _guardBack(on) {
    const guarded = history.state?.dd === 'room';
    if (on && !guarded) {
      history.pushState({ dd: 'room' }, '');
    } else if (!on && guarded) {
      this._unguarding = true;
      history.back();
    }
  }

  _onBack() {
    if (this._unguarding) { this._unguarding = false; return; }
    if (this.el.chatWrap.classList.contains('hidden')) return;
    const leave = this._backArmedUntil && Date.now() < this._backArmedUntil;
    this._backArmedUntil = 0;
    if (leave) { history.back(); return; }
    history.pushState({ dd: 'room' }, '');
    // The call screen goes back to the conversation; the call carries on.
    if (this._dismissTopDialog()) return;
    if (this._replyTo) { this._cancelReply(); return; }
    this._backArmedUntil = Date.now() + 3000;
    this._renderSystem(t('nav.backAgain'));
  }

  /* ── Room management ── */

  /**
   * Room creation and joining fail on the landing page, where the conversation
   * log is hidden: an error rendered there was never seen, and the button
   * simply seemed to do nothing. Say it under the buttons instead.
   */
  _landingError(text) {
    this.el.landingError.textContent = text || '';
    this.el.landingError.classList.toggle('hidden', !text);
    this.el.roomInput.toggleAttribute('aria-invalid', !!text);
  }

  /**
   * One room action at a time. Both await the network before they commit to
   * a room, and on a slow connection a second tap started a second run that
   * could overwrite the room code between the first one's join and its
   * invitation.
   */
  async _landingAction(action) {
    const work = this._workScope();
    if (!work.current() || this._landingBusy) return;
    this._landingBusy = true;
    try { await action(); } finally { if (work.current()) this._landingBusy = false; }
  }

  createRoom() {
    return this._landingAction(() => this._createRoom());
  }

  joinRoom() {
    return this._landingAction(() => this._joinRoom());
  }

  async _createRoom() {
    const work = this._workScope();
    this._landingError('');
    await this._loadIceServers();
    if (!work.current()) return;
    if (this._relayOnly && !this._hasRelay()) {
      this._landingError(t('warn.noRelay'));
      return;
    }
    // Request a server-generated room code (stronger entropy)
    try {
      const res = await fetch('/api/room', { method: 'POST', signal: work.signal });
      const data = await res.json();
      if (!work.current()) return;
      if (!res.ok || typeof data.code !== 'string' || !ROOM_CODE_RE.test(data.code)) {
        this._landingError(serverMessage(data.error, 'err.roomCreate'));
        return;
      }
      this.roomCode = data.code;
    } catch {
      if (work.current()) this._landingError(t('err.roomCreate'));
      return;
    }
    const created = this.roomCode;
    try {
      await this._connectSignaling();
      if (!work.current()) return;
      this._joinPending = true;
      this.ws.send(JSON.stringify({ type: 'join', room: this.roomCode }));
    } catch {
      // Not opened, and the person is told so: nothing may go on to join it
      // behind their back.
      if (this.roomCode === created) this.roomCode = null;
      if (work.current()) this._landingError(t('err.signaling'));
      return;
    }
    this._enterChat(this.roomCode);
    this._renderShareLink(this.roomCode);
    this._setStatus('waiting', () => t('st.waiting'));
  }

  _renderShareLink(code, guestPass = null) {
    const link = `${location.origin}/#join=${code}${guestPass ? `&guest=${guestPass}` : ''}`;
    const el = document.createElement('div');
    el.className = 'msg system share-link';
    // Keyed for the translator, so switching language turns the invitation
    // too instead of leaving it in the one it was drawn in.
    const btn = h('button', { class: 'btn btn-sm copy-link-btn', 'data-i18n': 'share.copy', text: t('share.copy') });
    const actions = h('div', { class: 'share-actions' }, btn);
    const intro = guestPass ? 'share.guestIntro' : 'share.intro';
    el.append(
      h('span', { class: 'share-intro', 'data-i18n': intro, text: t(intro) }),
      h('br'),
      h('span', { class: 'share-url', text: link }),
      ' ',
      actions,
    );
    btn.addEventListener('click', () => {
      this._copySecret(link).then(() => {
        btn.dataset.i18n = 'share.copiedClears';
        btn.textContent = t('share.copiedClears');
        setTimeout(() => {
          btn.dataset.i18n = 'share.copy';
          btn.textContent = t('share.copy');
        }, 2500);
      }).catch(() => this._copyFailed(el.querySelector('.share-url')));
    });
    // On a phone the link is going to another app anyway; the system share
    // sheet gets it there without a stop in the clipboard, which every app
    // with clipboard access can read.
    if (typeof navigator.share === 'function') {
      const shareBtn = h('button', { class: 'btn btn-sm native-share-btn', 'data-i18n': 'share.native', text: t('share.native') });
      shareBtn.addEventListener('click', () => {
        navigator.share({ url: link }).catch(() => { /* dismissed */ });
      });
      actions.append(shareBtn);
    }
    // For someone without an account: a link that lets one person into this
    // room once. Asked for, not made by default — most invitations go to
    // people who have an account, and a pass nobody needs should not exist.
    if (!guestPass && !this.guest) {
      const guestBtn = h('button', { class: 'btn btn-sm guest-link-btn', 'data-i18n': 'share.guest', text: t('share.guest') });
      guestBtn.addEventListener('click', async () => {
        const work = this._workScope();
        guestBtn.disabled = true;
        try {
          const res = await this._postJSON('/api/guest', { room: code }, work);
          if (!el.isConnected || this.roomCode !== code) return;
          if (res.ok && /^[0-9a-f]{32}$/.test(res.data.token || '')) {
            el.remove();
            this._renderShareLink(code, res.data.token);
            return;
          }
          guestBtn.dataset.i18n = 'share.guestFailed';
          guestBtn.textContent = t('share.guestFailed');
        } catch {
          if (!work.current()) return;
          guestBtn.dataset.i18n = 'share.guestFailed';
          guestBtn.textContent = t('share.guestFailed');
        }
        setTimeout(() => {
          guestBtn.disabled = false;
          guestBtn.dataset.i18n = 'share.guest';
          guestBtn.textContent = t('share.guest');
        }, 2500);
      });
      actions.append(guestBtn);
    }
    this.el.messages.appendChild(el);
    // The link is the useful half and appears at once; the QR joins it when the
    // generator has loaded.
    this._qrDataURL(link).then((qr) => {
      if (!qr || !el.isConnected) return;
      const img = document.createElement('img');
      img.className = 'share-qr';
      img.src = qr;
      img.alt = t('share.qrAlt');
      img.dataset.i18nAlt = 'share.qrAlt';
      el.appendChild(img);
      this.el.messages.scrollTop = this.el.messages.scrollHeight;
    });
    this._pruneRenderedNodes();
    this.el.messages.scrollTop = this.el.messages.scrollHeight;
  }

  /**
   * The 55KB generator is fetched only when a QR is actually drawn.
   *
   * Responses are served no-store so a cached client cannot outlive a fix,
   * which means every static import is paid again on every visit. This was the
   * largest one — bigger than crypto.js and peer.js together — for a feature
   * most visits never reach. The scanner was already lazy; this matches it.
   */
  async _qrDataURL(text) {
    try {
      const { default: qrcode } = await import('./vendor/qrcode.js');
      const qr = qrcode(0, 'M');
      qr.addData(text);
      qr.make();
      return qr.createDataURL(5, 2);
    } catch { return null; }
  }

  async _joinRoom() {
    const work = this._workScope();
    this._landingError('');
    if (!this.guest) this.el.landingInvited.classList.add('hidden');
    if (!this.el.roomInput.value.trim()) return;
    const code = roomCodeFrom(this.el.roomInput.value);
    if (!code || !ROOM_CODE_RE.test(code)) {
      this._landingError(t('err.roomCode'));
      return;
    }
    await this._loadIceServers();
    if (!work.current()) return;
    if (this._relayOnly && !this._hasRelay()) {
      this._landingError(t('warn.noRelay'));
      return;
    }
    try {
      await this._connectSignaling();
      if (!work.current()) return;
    } catch {
      if (work.current()) this._landingError(t('err.signaling'));
      return;
    }
    this.roomCode = code;
    this._joinPending = true;
    this.ws.send(JSON.stringify({ type: 'join', room: code }));
    this._enterChat(code);
    this._setStatus('connecting', () => t('st.joining'));
  }

  _enterChat(code) {
    scrubber().catch(() => {});
    this._showPage('chat');
    this.el.roomCode.textContent = code;
    this.el.roomInfo.classList.remove('hidden');
  }

  /* ── Signaling (WebSocket → signaling server) ── */

  _connectSignaling() {
    const work = this._workScope();
    return new Promise((resolve, reject) => {
      if (!work.current()) {
        reject(new DOMException('Operation cancelled', 'AbortError'));
        return;
      }
      if (this.ws && this.ws.readyState < WebSocket.CLOSING) {
        reject(new Error('Signaling connection already active'));
        return;
      }
      const generation = ++this._signalGeneration;
      this._signalWindowAt = Date.now();
      this._signalMessages = 0;
      this._signalBytes = 0;
      this._signalQ = Promise.resolve();
      let settled = false;
      let welcomed = false;
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const socket = new WebSocket(`${proto}//${location.host}/ws`);
      this.ws = socket;
      const finish = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        work.signal.removeEventListener('abort', onAbort);
        if (err) reject(err); else resolve();
      };
      const onAbort = () => finish(new DOMException('Operation cancelled', 'AbortError'));
      const timer = setTimeout(() => {
        if (settled || generation !== this._signalGeneration || this.ws !== socket) return;
        socket.close();
        finish(new Error('WebSocket welcome timeout'));
      }, 15000);
      work.signal.addEventListener('abort', onAbort, { once: true });

      socket.onmessage = (e) => {
        if (generation !== this._signalGeneration || this.ws !== socket) return;
        if (typeof e.data !== 'string' || !this._allowInboundSignal(e.data.length)) {
          socket.close(1008, 'signaling rate limit exceeded');
          return;
        }
        let msg;
        try {
          msg = JSON.parse(e.data);
        } catch {
          console.warn('[ws] Ignoring malformed signaling message');
          return;
        }
        if (msg.type === 'welcome' && !this.peerId && this._validPeerID(msg.peerId)) {
          this.peerId = msg.peerId;
          welcomed = true;
          finish();
        }
        if (!this.peerId && msg.type !== 'welcome') return;
        this._signalQ = this._signalQ
          .then(() => {
            if (generation !== this._signalGeneration || this.ws !== socket) return undefined;
            return this._onSignal(msg);
          })
          .catch((err) => console.warn('[ws] signaling message failed', err));
      };

      socket.onclose = (event) => {
        clearTimeout(timer);
        if (generation !== this._signalGeneration || this.ws !== socket) return;
        // The server ended the session on purpose: ask what that means here.
        if (event.reason === 'session revoked') this._recheckSession();
        // Only a connection that was made can be lost. One refused or timed
        // out on the way — a busy server, a rate limit — is reported to
        // whoever asked for it, which decides what follows. Treating it as
        // lost rejoined, in the background, a room whose creation had just
        // been reported as failed.
        if (welcomed && this.roomCode) this._onSignalingLost();
        else this._setStatus('disconnected', () => t('st.serverLost'));
        finish(new Error('WebSocket closed before welcome'));
      };
      socket.onerror = () => {
        clearTimeout(timer);
        if (generation !== this._signalGeneration || this.ws !== socket) return;
        // Could be an ended session — but only the server saying so counts.
        this._recheckSession();
        if (!settled) {
          finish(new Error('WebSocket error'));
        }
      };
    });
  }

  /**
   * The signaling socket dropped while in a room — on a phone, usually just a
   * network change. Conversations already running are direct and keep going;
   * only new arrivals need the server. So the client never tears a live
   * session down to reconnect (a rejoin is a new peer id, and a new safety
   * code to compare): it waits until the room is empty, then rejoins the same
   * code so whoever it is waiting for can still reach it.
   */
  _onSignalingLost() {
    this.ws = null;
    if (this._verifiedSessions().length > 0) {
      if (!this._warnedSignalLost) {
        this._warnedSignalLost = true;
        this._renderSystem(t('sys.signalLost'));
      }
    } else {
      this._setStatus('disconnected', () => t('st.reconnecting'));
    }
    this._scheduleRejoin(2000);
  }

  _scheduleRejoin(delay) {
    const work = this._workScope();
    clearTimeout(this._rejoinTimer);
    const room = this.roomCode;
    this._rejoinTimer = setTimeout(async () => {
      if (!work.current() || !room || this.roomCode !== room || this.ws) return;
      const next = Math.min(delay * 2, 30000);
      if (this.peers.size > 0) { this._scheduleRejoin(next); return; }
      this.peerId = null;
      this._announced = new Set();
      try {
        await this._connectSignaling();
      } catch {
        if (!work.current()) return;
        this.ws = null;
        if (this.roomCode === room) {
          this._setStatus('disconnected', () => t('st.reconnecting'));
          this._scheduleRejoin(next);
        }
        return;
      }
      if (!work.current() || this.roomCode !== room) return;
      this._warnedSignalLost = false;
      this._joinPending = true;
      this.ws.send(JSON.stringify({ type: 'join', room }));
    }, delay);
  }

  async _onSignal(msg) {
    const generation = this._signalGeneration;
    switch (msg.type) {
      case 'peer-joined':
        if (!this._validPeerID(msg.peerId) || msg.peerId === this.peerId) return;
        // The later of a pair waits for the other's offer before it has a
        // session, so remember who the server announced as well.
        this._announced.add(msg.peerId);
        if (!this.peers.has(msg.peerId) && this.peers.size >= MAX_REMOTE_PEERS) return;
        if (!this.peers.has(msg.peerId)) {
          this._setStatus('connecting', () => t('st.peerFound'));
        }
        // Deterministic initiator per pair: the lower peerId creates the offer.
        if (this.peerId < msg.peerId) {
          await this._loadIceServers();
          if (this._wiping || generation !== this._signalGeneration) return;
          await this._ensureSession(msg.peerId).conn.createOffer(msg.peerId);
        }
        break;

      case 'peer-left': {
        if (!this._validPeerID(msg.peerId)) return;
        this._announced.delete(msg.peerId);
        // The server only knows their signaling socket closed — a phone that
        // switched networks looks exactly like that. A session already
        // running is direct and its own channel reports a real departure, so
        // keep it; tearing it down here ended both sides of a conversation
        // over one side's blip, and let the server end any conversation it
        // liked by saying so.
        const s = this.peers.get(msg.peerId);
        if (s?.encrypted && s.conn.dc?.readyState === 'open') return;
        this._dropSession(msg.peerId, t('st.peerLeft'));
        break;
      }

      case 'joined':
        this._joinPending = false;
        // The server has us in the room. If nobody else is, this is a wait,
        // not a join in progress — say so, and offer the invitation, since
        // whoever entered a code first is the one who has to share it.
        if (this.peers.size === 0 && this._announced.size === 0) {
          this._setStatus('waiting', () => t('st.waiting'));
          if (!this.el.messages.querySelector('.share-link') && this.roomCode) {
            this._renderShareLink(this.roomCode);
          }
        }
        break;

      case 'error':
        // Refused at the door — a full room, a code the server will not take.
        // The chat view was already up, so the refusal used to sit in its
        // header over an empty room. Go back to where the code was entered and
        // say it there.
        if (this._joinPending) {
          this._joinPending = false;
          const reason = serverMessage(msg.error, 'st.unknownError');
          this._cleanup();
          this._showPage('landing');
          this._landingError(reason);
          break;
        }
        this._setStatus('disconnected', () => t('st.error').replace('{e}', serverMessage(msg.error, 'st.unknownError')));
        break;

      case 'offer': {
        if (!this._validSignal(msg)) return;
        await this._loadIceServers();
        if (this._wiping || generation !== this._signalGeneration) return;
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
    if (this.peers.size >= MAX_REMOTE_PEERS) {
      throw new Error('Room peer limit exceeded');
    }
    if (this._relayOnly && !this._hasRelay()) {
      if (!this._warnedNoRelay) {
        this._warnedNoRelay = true;
        this._renderSystem(t('warn.noRelay'));
      }
      throw new Error('A relay is required by the privacy setting');
    }
    const cryptoLayer = new CryptoLayer();
    const conn = new PeerConnection(
      { send: (o) => this.ws.send(JSON.stringify(o)) },
      cryptoLayer,
      (m) => this._onPeerMessage(peerId, m),
      (state, sas) => this._onConnState(peerId, state, sas),
      { iceServers: this.iceConfig.iceServers, relayOnly: this._relayOnly },
      this.identity,
    );
    conn.onRemoteTrack = (track) => this._onRemoteTrack(track);
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
    clearTimeout(this.peers.get(peerId)?.routeTimer);
    this.peers.delete(peerId); // delete first — close() re-enters _onConnState
    this._stopTyping(peerId);
    // Scanning the code of someone who has gone can only end in a verdict
    // about nobody, with the camera on in the meantime.
    if (this._qrPeerId === peerId && !this.el.qrVerify.classList.contains('hidden')) this._closeQrVerify();
    this.fileMgr.abortScope(peerId);
    this._syncWakeLock();
    for (const id of [...(this._delivery?.keys() || [])]) this._undeliverable(id, peerId);
    if (this._callPeerId === peerId) this._endCallCleanup();
    try { s.conn.close(); } catch { /* already closed */ }
    s.crypto.destroy();
    if (sysMsg) this._renderSystem(sysMsg.replace('{peer}', s.label));
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

  /**
   * Deterministic per-peer color for sender labels. The hue is the peer's;
   * the lightness is the theme's, chosen so every hue reads at 4.5:1 or more.
   */
  _peerColor(peerId) {
    let h = 0;
    for (const c of peerId) h = (h * 31 + c.charCodeAt(0)) % 360;
    return `hsl(${h}, 65%, var(--peer-lightness))`;
  }

  /** Recompute the aggregate room state: status bar, call button, verify bar. */
  _refreshRoomState() {
    const enc = this._encryptedSessions();
    const verified = this._verifiedSessions();
    this.encrypted = verified.length > 0;
    if (verified.length > 0) {
      const extra = this.peers.size > verified.length ? ' ⏳' : '';
      const count = verified.length;
      this._setStatus('encrypted', () => (count === 1
        ? t('st.verified')
        : t('st.verifiedN').replace('{n}', String(count))) + extra);
    } else if (enc.length > 0) {
      this._setStatus('connecting', () => t('st.unverified'));
    } else if (this.peers.size > 0) {
      this._setStatus('connecting', () => t('st.exchanging'));
    } else {
      this.encrypted = false;
      // Alone with no server connection is not waiting: nobody can arrive.
      const key = this.ws ? 'st.waiting' : 'st.reconnecting';
      this._setStatus(this.ws ? 'waiting' : 'disconnected', () => t(key));
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
    // The record button is about to be disabled, and it is also the stop
    // button: the microphone would stay live with no way to end it, for a
    // recording nobody can receive.
    if (!this.encrypted && this._recorder?.state === 'recording') {
      this._discardRecording({ quiet: true });
      this._renderSystem(t('rec.noOne'));
    }
    for (const control of [this.el.msgInput, this.el.sendBtn, this.el.attachBtn, this.el.recordBtn]) {
      control.disabled = !this.encrypted;
    }
    // Everyone left: the invitation is the useful thing on screen again.
    if (this.peers.size === 0) {
      for (const card of this.el.messages.querySelectorAll('.share-link')) card.classList.remove('compact');
    }
    this._updateComposerHint();
    this._renderVerifyBar();
  }

  /** Grow the message field with what is typed; CSS caps the height. */
  _fitComposer() {
    const field = this.el.msgInput;
    field.style.height = 'auto';
    field.style.height = `${field.scrollHeight + (field.offsetHeight - field.clientHeight)}px`;
  }

  /** A disabled message field says what it is waiting for, not "Type a message". */
  _updateComposerHint() {
    if (this._recorder?.state === 'recording') return;
    this.el.msgInput.placeholder = t(this.encrypted ? 'chat.msg'
      : this.peers.size > 0 ? 'chat.lockedPh' : 'chat.waitingPh');
  }

  _hasRelay() {
    return this.iceConfig.iceServers.some((server) => [server.urls].flat()
      .some((url) => /^turns?:/.test(String(url))));
  }

  /** Fetch self-hosted STUN/TURN ICE servers (with an ephemeral credential). */
  async _loadIceServers() {
    const work = this._workScope();
    if (!work.current()) return;
    const now = Date.now();
    if (this._iceExpiresAt - now > 5 * 60 * 1000) return;
    if (this._iceExpiresAt <= now) this.iceConfig.iceServers = [];
    try {
      const res = await fetch('/api/turn', { signal: work.signal });
      if (!res.ok) return;
      const raw = await res.text();
      if (!work.current()) return;
      if (raw.length > 32 * 1024) throw new Error('ICE response too large');
      const clean = sanitizeIceConfig(JSON.parse(raw));
      this.iceConfig.iceServers = clean.iceServers;
      this._iceExpiresAt = Date.now() + clean.ttl * 1000;
    } catch { /* relay-only remains blocked without valid relay credentials */ }
  }

  /* ── P2P connection state ── */

  _onConnState(peerId, state, sas) {
    const s = this.peers.get(peerId);
    switch (state) {
      case 'connected':
        if (s?.encrypted) {
          // Back from an interruption: the same session, nothing to redo.
          if (s.interrupted) { s.interrupted = false; this._renderSystem(t('sys.recovered').replace('{peer}', s.label)); }
          this._refreshRoomState();
        } else if (!this.encrypted) this._setStatus('connected', () => t('st.exchanging'));
        break;
      case 'interrupted':
        if (!s) return;
        s.interrupted = true;
        this._setStatus('connecting', () => t('st.interrupted'));
        break;
      case 'encrypted':
        if (!s) return;
        s.encrypted = true;
        s.sas = sas;
        s.verified = false;
        this._watchRoute(peerId);
        for (const card of this.el.messages.querySelectorAll('.share-link')) card.classList.add('compact');
        this._renderSystem(`⚠️ ${s.label} ${t('sys.awaitVerify')}`);
        this._refreshRoomState();
        break;
      case 'peer-confirmed':
        if (!s) return;
        s.peerConfirmed = true;
        this._renderVerifyBar();
        break;
      case 'identity-proved':
        this._onIdentityProved(peerId, sas); // `sas` carries the fingerprint here
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
        this._maybeOpenInbox(peerId);
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
        this._dropSession(peerId, t('sys.left'));
        break;
    }
  }

  /* ── Messaging ── */

  async sendMessage() {
    const generation = this._signalGeneration;
    const room = this.roomCode;
    const current = () => !this._wiping && this._signalGeneration === generation && this.roomCode === room;
    const text = this.el.msgInput.value.trim();
    if (!text || !this.encrypted) return;
    if (text.length > MAX_TEXT_LEN) {
      this._renderSystem(t('err.messageTooLarge'));
      return;
    }

    const burn = this.el.burnToggle.checked;
    const ttl = this._normalizeTTL(this.el.ttlSelect.value);
    const id = crypto.randomUUID();
    // Only which message, never its text: each side quotes its own copy, so a
    // reply cannot carry words past the timer or the burn that removed them.
    const reply = this._replyTo && this.msgMgr.has(this._replyTo.key) ? this._replyTo : null;
    const quoting = reply ? { replyTo: reply.wireId, replyAuthor: reply.author } : {};

    // Pairwise E2E: encrypt separately for every peer with that pair's own keys.
    const targets = [...this.peers].filter(([, s]) => s.encrypted && s.verified && s.conn.userVerified);
    this._awaitDelivery(id, targets.map(([peerId]) => peerId));
    for (const [peerId, s] of targets) {
      try {
        const { ciphertext, iv, epoch } = await s.crypto.encrypt(text);
        if (!current()) return;
        await s.conn.send({
          type: 'chat', id, ciphertext, iv, epoch, ttl, burnAfterReading: burn, ...quoting,
        });
      } catch (err) {
        if (!current()) return;
        console.warn('Send failed for one peer:', err);
        this._undeliverable(id, peerId);
      }
    }

    if (!current()) return;
    this._renderMsg(id, text, true, ttl, burn, null, null, reply?.key);
    this._cancelReply();
    this.el.msgInput.value = '';
    this._fitComposer();
  }

  async _onPeerMessage(peerId, msg) {
    if (!msg || typeof msg !== 'object' || typeof msg.type !== 'string') return;
    const s = this.peers.get(peerId);
    if (!s || !s.verified || !s.conn.userVerified) return;
    switch (msg.type) {
      case 'cover':
        // Decoy packet from the peer's cover generator. It has the same sealed
        // application shape as a short message, but does not hide timing or
        // aggregate volume. Silently discard it without acknowledgement.
        break;

      case 'typing':
        this._showTyping(peerId);
        break;

      case 'chat': {
        if (!this._validMessageID(msg.id) || !this._validEncryptedPayload(msg)) return;
        this._stopTyping(peerId);
        try {
          const text = await s.crypto.decrypt(msg.ciphertext, msg.iv, msg.epoch);
          if (this._wiping || this.peers.get(peerId) !== s) return;
          if (typeof text !== 'string' || text.length > MAX_TEXT_LEN) return;
          this._renderMsg(msg.id, text, false, msg.ttl, msg.burnAfterReading, s, peerId,
            this._quotedKey(msg));
          this._sendBestEffort(s.conn, { type: 'got', id: msg.id });
        } catch (err) {
          console.error('Decryption failed:', err.message);
        }
        break;
      }
      case 'got':
        if (this._validMessageID(msg.id)) this._onDelivered(peerId, msg.id);
        break;

      case 'file-refuse':
        // Only ever about this peer's own copy of a file we are sending.
        if (!this._validMessageID(msg.id) || !this.fileMgr.abortOutbound(msg.id, peerId)) break;
        this._undeliverable(msg.id, peerId);
        this._renderSystem(t('file.refused').replace('{peer}', s.label));
        break;

      case 'file-accept':
        // Only ever about this peer's own copy of a file we offered it.
        if (this._validMessageID(msg.id)) this.fileMgr.accepted(peerId, msg.id);
        break;

      case 'drop-inbox':
        // A saved contact handing us the key to its inbox. Kept only against
        // the identity this session proved, and only once it is a contact.
        if (!this.identity || this.guest || typeof msg.chain !== 'string' || msg.chain.length > 64) break;
        s.pendingInbox = { chain: msg.chain, n: msg.n };
        if (s.knownContact && s.identityFp) this._storeOutbox(peerId, s);
        break;

      case 'read': {
        if (!this._validMessageID(msg.id)) return;
        const own = this._messageKey(null, msg.id);
        // Only a message we sent to burn once read may be destroyed by a
        // receipt. The stock client only ever sends one for those; trusting the
        // claim for anything else lets a peer fabricate receipts for ordinary
        // messages and wipe our side of the conversation while keeping its own.
        if (this.msgMgr.burnsOnRead(own)) {
          this.msgMgr.remoteDestroy(own);
          this._renderSystem(t('msg.peerRemoved'));
        }
        break;
      }
      case 'delete': {
        if (!this._validMessageID(msg.id)) return;
        // A file still arriving that its sender called off.
        if (this.fileMgr.discardInbound(peerId, msg.id)) {
          document.getElementById(this._domMessageId(this._messageKey(peerId, msg.id)))?.remove();
          this._syncWakeLock();
          this._renderSystem(t('file.withdrawn').replace('{peer}', s.label));
          break;
        }
        const own = this._messageKey(null, msg.id);
        if (!this.msgMgr.has(own)) {
          // A peer withdrawing something it sent us: theirs to withdraw.
          this.msgMgr.remoteDestroy(this._messageKey(peerId, msg.id));
          break;
        }
        // A peer withdrawing something we wrote. Between two people that is the
        // cooperative removal this app offers: afterwards neither side has it.
        // In a room it is not — every other member keeps the message, and the
        // only person who loses it is the one who wrote it.
        if (this.peers.size === 1) {
          this.msgMgr.remoteDestroy(own);
          this._renderSystem(t('msg.peerRemoved'));
        }
        break;
      }

      // ── File transfer messages ──
      case 'file-offer':
      case 'file-part':
      case 'file-done': {
        let result;
        try {
          result = await this.fileMgr.handleMessage(msg, peerId);
        } catch (err) {
          console.warn('File transfer message rejected:', err);
        } finally {
          this._syncWakeLock();
        }
        if (!result || this._wiping || this.peers.get(peerId) !== s) break;
        switch (result.event) {
          case 'offer':
            await this._onFileOffer(result, s, peerId);
            break;
          case 'busy':
            this._sendBestEffort(s.conn, { type: 'file-refuse', id: result.id });
            this._renderSystem(t('file.busy').replace('{peer}', s.label));
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
            this._renderSystem(`⚠️ ${t('err.fileTransfer')}: ${result.error}`);
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

  /**
   * A peer offers a file. Its name and size are read first; a file up to the
   * old 25 MB limit is taken at once, as it always was, and anything larger
   * waits for this person to accept it.
   */
  async _onFileOffer(offer, s, peerId) {
    const generation = this._signalGeneration;
    const current = () => !this._wiping && this._signalGeneration === generation && this.peers.get(peerId) === s;
    let meta;
    try {
      const metaJson = await s.crypto.decrypt(offer.meta.ciphertext, offer.meta.iv, offer.meta.epoch);
      if (!current()) return;
      const rawMeta = JSON.parse(metaJson);
      assertFileSizeBinding(rawMeta?.fileSize, offer.size);
      meta = this._sanitizeFileMeta(rawMeta);
      if (!meta) throw new Error('Invalid file metadata');
    } catch (err) {
      if (!current()) return;
      console.error('File offer refused:', err.message);
      this.fileMgr.decline(peerId, offer.id);
      this._sendBestEffort(s.conn, { type: 'file-refuse', id: offer.id });
      this._renderSystem(t('err.fileDecrypt'));
      return;
    }
    if (offer.ask) {
      this._renderFileOffer(offer.id, meta, s, peerId);
      return;
    }
    this._acceptFile(offer.id, meta, s, peerId, null);
  }

  /** Take an offered file: from here its parts are received. */
  _acceptFile(id, meta, s, peerId, card) {
    const answer = this.fileMgr.accept(peerId, id, s.crypto, meta);
    if (answer === 'busy') {
      // Asked by hand: the question stays, to be answered once the file
      // already arriving is done. Taken automatically: turned away.
      if (card) {
        this._renderSystem(t('file.busyAccept'));
        return;
      }
      this.fileMgr.decline(peerId, id);
      this._sendBestEffort(s.conn, { type: 'file-refuse', id });
      this._renderSystem(t('file.busy').replace('{peer}', s.label));
      return;
    }
    if (answer !== 'ok') {
      card?.remove();
      return;
    }
    this._sendBestEffort(s.conn, { type: 'file-accept', id });
    this._renderFileProgress(id, 0, 1, peerId, meta);
    this._syncWakeLock();
  }

  /** An offer went unanswered, or a file stopped arriving. */
  _onFileLapse(peerId, id, why) {
    this._syncWakeLock();
    const s = this.peers.get(peerId);
    document.getElementById(this._domMessageId(this._messageKey(peerId, id)))?.remove();
    if (!s) return;
    if (why === 'offer') this._renderSystem(t('file.offerLapsed').replace('{peer}', s.label));
    else this._renderSystem(`⚠️ ${t('err.fileTransfer')}: ${t('file.stalled')}`);
  }

  async _onFileComplete(result, s, peerId) {
    const meta = this._sanitizeFileMeta(result.meta);
    if (!meta || result.blob.size !== meta.fileSize) {
      this._renderSystem(t('err.fileDecrypt'));
      return;
    }
    const blobUrl = URL.createObjectURL(result.blob);
    // Replace the progress placeholder with the file itself.
    this._renderFileComplete(
      result.id, blobUrl, meta, result.ttl, result.burnAfterReading, s, peerId,
    );
    this._sendBestEffort(s.conn, { type: 'got', id: result.id });
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

    const placeholder = document.getElementById(el.id);

    let preview;
    if (meta.fileType.startsWith('image/')) {
      preview = h('img', {
        src: blobUrl, alt: meta.fileName, class: 'file-preview-img', loading: 'lazy',
      });
      preview.addEventListener('click', (e) => {
        e.stopPropagation();
        this._openImage(key, blobUrl, meta.fileName);
      });
    } else if (meta.fileType.startsWith('video/')) {
      preview = h('video', {
        src: blobUrl, controls: '', playsinline: '', class: 'file-preview-video',
      });
    } else if (meta.fileType.startsWith('audio/')) {
      preview = h('audio', { src: blobUrl, controls: '', class: 'file-preview-audio' });
    }
    // A picture or video takes its height only once decoded, after the log
    // has scrolled to it: half of it was left below the screen.
    // An undecoded image is initially shorter than the transfer indicator.
    // Reserve that height until load so replacement cannot clamp scrollTop
    // before the image grows and the queued scroll event reaches us.
    if (placeholder && preview?.tagName === 'IMG' && !preview.complete) {
      el.style.minHeight = `${placeholder.getBoundingClientRect().height}px`;
    }
    const previewReady = () => {
      el.style.minHeight = '';
      this._holdLogEnd();
    };
    preview?.addEventListener(preview.tagName === 'IMG' ? 'load' : 'loadedmetadata', previewReady, { once: true });
    preview?.addEventListener('error', previewReady, { once: true });

    // Anything without a preview is one compact row — icon, name and size —
    // rather than a tall card around a lone icon.
    appendPresent(el,
      this._senderTag(mine, sender),
      preview && h('div', { class: 'file-content' }, preview),
      h('div', { class: 'file-details' },
        !preview && h('span', { class: 'file-icon', 'aria-hidden': 'true', text: '📄' }),
        this._fileName(/^voice\.(webm|ogg|m4a)$/.test(meta.fileName) && meta.fileType.startsWith('audio/')
          ? t('voice.label') : meta.fileName),
        h('span', { class: 'file-size', text: this._fmtSize(meta.fileSize) }),
        h('a', {
          href: blobUrl, download: meta.fileName, class: 'file-download',
          title: t('file.save'), text: `💾 ${t('file.save')}`,
        }),
      ),
      this._metaRow(burn, ttl),
      this._msgActions(el, key, mine),
    );
    this._applySenderColor(el, sender);

    this._appendToLog(el, mine, placeholder);

    this.msgMgr.add(key, el, ttl, burn, mine, blobUrl, {
      wireId: id,
      peerId,
      deferTtl: !mine && !this._onScreen(),
      blobBytes: meta.fileSize,
    });
    // Long enough to open or save it, not just to see that it came.
    if (!mine) this._markSeen(key, 15_000);
  }

  /**
   * A file's name on one line, its end cut short rather than its extension:
   * on a phone "raport-trimestrial.pdf" broke as "raport-trimestrial.p / df".
   * The whole name is the tooltip and what the file is saved as.
   */
  _fileName(name) {
    const dot = name.lastIndexOf('.');
    const split = dot > 0 && name.length - dot <= 8;
    return h('span', { class: 'file-name', title: name },
      h('span', { class: 'file-name-stem', text: split ? name.slice(0, dot) : name }),
      split && h('span', { class: 'file-name-ext', text: name.slice(dot) }));
  }

  _renderFileProgress(id, received, total, peerId, meta = null) {
    if (!this._validMessageID(id) || !Number.isSafeInteger(total) || total < 1) return;
    const key = this._messageKey(peerId, id);
    const el = document.createElement('div');
    el.className = 'msg theirs file-msg';
    el.id = this._domMessageId(key);
    // An offer card it answers is replaced where it stands.
    const offerCard = document.getElementById(el.id);
    el.append(
      // `total` counts transfer chunks, which mean nothing to the reader;
      // the percentage is what is shown and announced.
      h('div', { class: 'file-receiving' },
        meta && meta.fileSize > AUTO_ACCEPT_SIZE
          ? h('span', { class: 'file-receiving-name' }, this._fileName(meta.fileName),
            h('span', { class: 'file-size', text: this._fmtSize(meta.fileSize) }))
          : h('span', { 'data-i18n': 'file.receiving', text: t('file.receiving') }),
        h('div', {
          class: 'progress-bar', role: 'progressbar', 'aria-label': t('file.receiving'),
          'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': '0',
        }, h('div', { class: 'progress-fill' })),
        h('span', { class: 'progress-text', text: '0%' }),
        this._refuseButton(id, peerId, el),
      ),
    );
    this._appendToLog(el, false, offerCard);
  }

  /**
   * A file too large to take unasked: what it is, from whom, and the choice.
   * Nothing of it is sent until this side accepts.
   */
  _renderFileOffer(id, meta, s, peerId) {
    const key = this._messageKey(peerId, id);
    const el = h('div', { class: 'msg theirs file-msg file-offer', id: this._domMessageId(key) });
    const accept = h('button', {
      class: 'btn btn-sm primary file-accept', type: 'button', 'data-i18n': 'file.accept', text: t('file.accept'),
    });
    const refuse = h('button', {
      class: 'btn btn-sm file-decline', type: 'button', 'data-i18n': 'file.decline', text: t('file.decline'),
    });
    accept.addEventListener('click', (e) => {
      e.stopPropagation();
      if (this.peers.get(peerId) !== s) { el.remove(); return; }
      this._acceptFile(id, meta, s, peerId, el);
    });
    refuse.addEventListener('click', (e) => {
      e.stopPropagation();
      el.remove();
      if (!this.fileMgr.decline(peerId, id)) return;
      if (this.peers.get(peerId) === s) this._sendBestEffort(s.conn, { type: 'file-refuse', id });
    });
    appendPresent(el,
      this._senderTag(false, s),
      h('div', { class: 'file-details' },
        h('span', { class: 'file-icon', 'aria-hidden': 'true', text: '📦' }),
        this._fileName(meta.fileName),
        h('span', { class: 'file-size', text: this._fmtSize(meta.fileSize) })),
      h('p', { class: 'file-offer-note', 'data-i18n': 'file.offerNote', text: t('file.offerNote') }),
      h('div', { class: 'file-offer-actions' }, accept, refuse),
    );
    this._applySenderColor(el, s);
    this._appendToLog(el);
  }

  /**
   * Turn down a file while it arrives — 25 MB over mobile data, or something
   * not wanted at all. What came of it is dropped here, and the sender is
   * asked to stop sending the rest to this side; a client too old to know
   * the request keeps sending, and the rest is dropped as it comes.
   */
  _refuseButton(id, peerId, row) {
    const btn = h('button', {
      class: 'file-cancel', type: 'button', text: '✕',
      'aria-label': t('file.refuse'), title: t('file.refuse'), 'data-i18n-aria': 'file.refuse',
    });
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      this.fileMgr.discardInbound(peerId, id);
      this._syncWakeLock();
      row.remove();
      const s = this.peers.get(peerId);
      if (s?.verified) this._sendBestEffort(s.conn, { type: 'file-refuse', id });
    });
    return btn;
  }

  _updateFileProgress(id, received, total, peerId) {
    if (!this._validMessageID(id) || !Number.isSafeInteger(received) || !Number.isSafeInteger(total) || total < 1) return;
    const el = document.getElementById(this._domMessageId(this._messageKey(peerId, id)));
    if (!el) return;
    const bar  = el.querySelector('.progress-bar');
    const fill = el.querySelector('.progress-fill');
    const text = el.querySelector('.progress-text');
    const pct  = Math.min(100, Math.round((received / total) * 100));
    if (bar) bar.setAttribute('aria-valuenow', String(pct));
    if (fill) fill.style.width = `${pct}%`;
    if (text) text.textContent = `${pct}%`;
  }

  _renderFileComplete(id, blobUrl, meta, ttl, burn, sender = null, peerId = null) {
    if (!this._validMessageID(id)) return;
    this._renderFileMsg(id, blobUrl, meta, false, ttl, burn, sender, peerId);
  }

  /** Sender attribution tag — only on peers' messages, only in group rooms.
   * The color is applied afterwards via _applySenderColor (CSSOM), because an
   * inline style attribute would violate the strict CSP. */
  _senderTag(mine, sender) {
    if (mine || !sender || this.peers.size < 2) return null;
    return h('div', { class: 'msg-sender', text: sender.label });
  }

  /**
   * "Delete for everyone" on a message of ours. The protocol always had it —
   * timers and burn-after-reading use it — but nothing let a person withdraw
   * something they had sent. The button sits beside the bubble, shown on
   * hover or keyboard focus, and on a touch screen once the bubble is tapped,
   * so a stray tap on an empty corner cannot delete anything.
   */
  /**
   * A tick on a sent message once every recipient's client has said it
   * arrived and opened. Sending only meant it had left this tab: on a channel
   * that dropped a moment later, it may never have reached anyone. Only the
   * peers it was sent to can tick it, and arriving says nothing of reading.
   */
  _awaitDelivery(id, peerIds) {
    if (!peerIds.length) return;
    const pending = (this._delivery ||= new Map());
    pending.set(id, { waiting: new Set(peerIds), got: 0 });
    while (pending.size > MAX_RENDERED_NODES) pending.delete(pending.keys().next().value);
  }

  _onDelivered(peerId, id) {
    const d = this._delivery?.get(id);
    if (!d || !d.waiting.delete(peerId)) return;
    d.got++;
    if (!d.waiting.size) this._tickDelivered(id);
  }

  /** It will not reach this peer: failed to send, or they left first. */
  _undeliverable(id, peerId) {
    const d = this._delivery?.get(id);
    if (!d || !d.waiting.delete(peerId) || d.waiting.size) return;
    if (d.got) this._tickDelivered(id);
    else this._delivery.delete(id);
  }

  _tickDelivered(id) {
    this._delivery.delete(id);
    const el = this.msgMgr.messages.get(this._messageKey(null, id))?.element;
    if (!el || el.querySelector('.msg-tick')) return;
    el.append(h('span', {
      class: 'msg-tick', text: '✓',
      title: t('msg.delivered'), 'aria-label': t('msg.delivered'), 'data-i18n-aria': 'msg.delivered',
    }));
  }

  /**
   * Copy what a message says, then take it back out of the clipboard a
   * minute later, as with a room link: a clipboard manager or a synced
   * clipboard would otherwise keep it long after the message was gone.
   */
  _copyMessage(key) {
    const node = this.msgMgr.messages.get(key)?.element?.querySelector('.msg-text');
    if (!node) return;
    this._copySecret(node.textContent)
      .then(() => this._renderSystem(t('msg.copied')))
      .catch(() => this._copyFailed(node));
  }

  /** Show a picture full screen, until closed or until its message goes. */
  _openImage(key, src, name) {
    if (!this.msgMgr.has(key)) return;
    this._viewing = key;
    this.el.imageViewerImg.src = src;
    this.el.imageViewerImg.alt = name;
    this.el.imageViewer.classList.remove('hidden');
    this._makeModal(this.el.imageViewer);
    this._captureFocus(this.el.imageViewer);
  }

  _closeImage() {
    if (this.el.imageViewer.classList.contains('hidden')) return;
    this._viewing = null;
    this.el.imageViewer.classList.add('hidden');
    this.el.imageViewerImg.removeAttribute('src');
    this.el.imageViewerImg.alt = '';
    this._makeModal(null);
    this._restoreFocus();
  }

  /** Where the message a reply names lives here, if it is valid at all. */
  _quotedKey(msg) {
    if (msg.replyTo === undefined) return null;
    if (!this._validMessageID(msg.replyTo) || !this._validPeerID(msg.replyAuthor)) return null;
    return this._messageKey(msg.replyAuthor === this.peerId ? null : msg.replyAuthor, msg.replyTo);
  }

  /** A line of what a message says, for a quote: its text, or the file. */
  _quoteSnippet(key) {
    const entry = this.msgMgr.messages.get(key);
    const el = entry?.element;
    if (!el) return null;
    const text = el.querySelector('.msg-text')?.textContent
      ?? `📎 ${el.querySelector('.file-name')?.textContent ?? ''}`;
    const who = entry.isMine ? t('reply.you') : this.peers.get(entry.peerId)?.label ?? '';
    return { who, text: text.length > 100 ? `${text.slice(0, 100)}…` : text };
  }

  /**
   * The quote at the top of a reply. It is drawn from this side's own copy of
   * the message and is wiped with it — by its timer, a burn, or a delete for
   * everyone — so quoting never keeps words alive longer than the original.
   */
  _quoteEl(bubble, key) {
    const q = h('button', { class: 'msg-quote', type: 'button' });
    const snippet = this._quoteSnippet(key);
    if (!snippet) {
      this._quoteGone(q);
      return q;
    }
    q.append(h('span', { class: 'quote-who', text: snippet.who }),
      h('span', { class: 'quote-text', text: snippet.text }));
    q.addEventListener('click', (e) => {
      e.stopPropagation();
      const orig = this.msgMgr.messages.get(key)?.element;
      if (!orig) return;
      orig.scrollIntoView({ block: 'center', behavior: 'smooth' });
      orig.classList.remove('flash');
      void orig.offsetWidth; // restart the animation on a second tap
      orig.classList.add('flash');
    });
    if (!this._quotes.has(key)) this._quotes.set(key, new Set());
    this._quotes.get(key).add(q);
    this._quoteOf.set(bubble, { key, q });
    return q;
  }

  _quoteGone(q) {
    q.replaceChildren(t('reply.gone'));
    q.classList.add('gone');
    q.disabled = true;
  }

  /** A message is gone: so are its quotes, and a reply being written to it. */
  _forgetQuoted(key, el) {
    const own = el && this._quoteOf.get(el);
    if (own) {
      const set = this._quotes.get(own.key);
      set?.delete(own.q);
      if (set && !set.size) this._quotes.delete(own.key);
    }
    const quotes = this._quotes.get(key);
    if (quotes) {
      this._quotes.delete(key);
      for (const q of quotes) this._quoteGone(q);
    }
    if (this._replyTo?.key === key) this._cancelReply();
  }

  /**
   * Swipe a message to the right to answer it, as phone messengers do. The
   * listeners are passive, so a scroll is never held up waiting on them; a
   * mostly vertical drag is a scroll and lets go. A touch starting at the
   * very edge belongs to the system's back gesture.
   */
  _swipeToReply(bubble, key) {
    let x0 = null;
    let y0 = 0;
    let dx = 0;
    const reset = () => {
      x0 = null;
      dx = 0;
      bubble.style.transform = '';
    };
    bubble.addEventListener('touchstart', (e) => {
      const touch = e.touches[0];
      if (e.touches.length !== 1 || touch.clientX < 24) { reset(); return; }
      x0 = touch.clientX;
      y0 = touch.clientY;
      dx = 0;
    }, { passive: true });
    bubble.addEventListener('touchmove', (e) => {
      if (x0 === null) return;
      const mx = e.touches[0].clientX - x0;
      const my = e.touches[0].clientY - y0;
      if (Math.abs(my) > 12 && Math.abs(my) > Math.abs(mx)) { reset(); return; }
      dx = Math.max(0, Math.min(72, mx));
      bubble.style.transform = dx ? `translateX(${dx}px)` : '';
    }, { passive: true });
    bubble.addEventListener('touchend', () => {
      const swiped = x0 !== null && dx >= 56;
      reset();
      if (swiped) this._startReply(key);
    });
    bubble.addEventListener('touchcancel', reset);
  }

  _startReply(key) {
    const entry = this.msgMgr.messages.get(key);
    const snippet = this._quoteSnippet(key);
    if (!entry || !snippet || !this.encrypted) return;
    this._replyTo = { key, wireId: entry.wireId, author: entry.isMine ? this.peerId : entry.peerId };
    // The bar takes height from the conversation; at the bottom, stay there.
    const list = this.el.messages;
    const atBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 40;
    this.el.replyBarText.replaceChildren(
      h('span', { class: 'quote-who', text: snippet.who }),
      h('span', { class: 'quote-text', text: snippet.text }),
    );
    this.el.replyBar.classList.remove('hidden');
    if (atBottom) list.scrollTop = list.scrollHeight;
    this.el.msgInput.focus();
  }

  _cancelReply() {
    this._replyTo = null;
    this.el.replyBar.classList.add('hidden');
    this.el.replyBarText.replaceChildren();
  }

  /** Reply to any message; copy a text; delete for everyone, one's own. */
  _msgActions(bubble, key, mine, copyable = false) {
    const button = (cls, icon, label, onClick) => {
      const btn = h('button', {
        class: cls, type: 'button', text: icon,
        'aria-label': t(label), title: t(label), 'data-i18n-aria': label,
      });
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        bubble.classList.remove('actions-open');
        onClick();
      });
      return btn;
    };
    const actions = h('div', { class: 'msg-actions' },
      button('msg-reply', '↩️', 'aria.msgReply', () => this._startReply(key)),
      copyable && button('msg-copy', '📋', 'aria.msgCopy', () => this._copyMessage(key)),
      // Destroying it locally tells every verified peer to drop their copy.
      mine && button('msg-del', '🗑️', 'aria.msgDelete', () => this.msgMgr.destroy(key)),
    );
    this._swipeToReply(bubble, key);
    bubble.addEventListener('click', (e) => {
      if (e.target.closest('a, button, audio, video, input')) return;
      const open = !bubble.classList.contains('actions-open');
      for (const other of this.el.messages.querySelectorAll('.msg.actions-open')) other.classList.remove('actions-open');
      bubble.classList.toggle('actions-open', open);
      // On a phone the buttons open as a row under the message; the last
      // message's row would otherwise open below the fold.
      if (open) bubble.scrollIntoView({ block: 'nearest' });
    });
    return actions;
  }

  /**
   * When the message reached this screen, then the burn badge and TTL
   * countdown. The time is this device's clock and never travels: a sender's
   * timestamp on the wire would tell the other side the sender's clock and
   * time zone, and would be the sender's word anyway. It follows the device's
   * own time format rather than the page language.
   */
  _metaRow(burn, ttl) {
    const now = new Date();
    return h('div', { class: 'msg-meta' },
      h('time', {
        class: 'msg-time',
        datetime: now.toISOString(),
        text: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }),
      burn && h('span', { class: 'burn-badge', 'data-i18n': 'msg.burnBadge', text: t('msg.burnBadge') }),
      burn && ttl > 0 && ' ',
      ttl > 0 && h('span', { class: 'countdown', text: `${ttl}s` }),
    );
  }

  _applySenderColor(el, sender) {
    const tag = el.querySelector('.msg-sender');
    if (tag && sender) tag.style.color = sender.color;
  }

  _renderSystem(text) {
    const el = document.createElement('div');
    el.className = 'msg system';
    el.textContent = text;
    this._appendToLog(el);
  }

  /**
   * Add to the conversation without pulling someone who scrolled up to read
   * back down to the end at every new line. What they send themselves does
   * follow; anything else waits behind a "new messages" button, and a message
   * that arrives out of view is not yet seen — its timer and burn wait.
   */
  _appendToLog(el, follow = false, replace = null) {
    const list = this.el.messages;
    const atEnd = this._atLogEnd();
    if (replace?.parentNode === list) replace.replaceWith(el);
    else list.appendChild(el);
    this._pruneRenderedNodes();
    if (follow || atEnd) {
      this._scrollLogEnd();
      return;
    }
    this._scrolledAway = true;
    this.el.jumpNew.classList.remove('hidden');
  }

  _atLogEnd() {
    const list = this.el.messages;
    return list.scrollHeight - list.scrollTop - list.clientHeight < 80;
  }

  /** Something in the log grew: whoever was reading at the end stays there. */
  _holdLogEnd() {
    if (this._followingEnd !== false) this._scrollLogEnd();
  }

  _scrollLogEnd() {
    const list = this.el.messages;
    list.scrollTop = list.scrollHeight;
    this._logScrollTarget = list.scrollTop;
    this._followingEnd = true;
  }

  _onLogScroll() {
    // A programmatic scroll event can arrive after an image has grown the log.
    // At the position we requested, the reader has not scrolled away: keep
    // following even though that position is no longer the new bottom.
    if (this._followingEnd && Math.abs(this.el.messages.scrollTop - this._logScrollTarget) < 1) {
      this._scrollLogEnd();
    }
    this._followingEnd = this._atLogEnd();
    if (!this._scrolledAway || !this._atLogEnd()) return;
    this._scrolledAway = false;
    this.el.jumpNew.classList.add('hidden');
    this._flushUnseen();
  }

  /** `text` is a function, so a language switch can draw the same status
   *  again in the new language instead of leaving the old one up. */
  _setStatus(cls, text) {
    this._statusText = text;
    this.el.status.className = `status ${cls}`;
    this._drawStatus();
  }

  _drawStatus() {
    if (!this._statusText) return;
    const text = this._statusText();
    this.el.status.textContent = text;
    // A phone header ellipsizes the pill; the full text stays one hover away.
    this.el.status.title = text;
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
    this._copySecret(this.roomCode).then(() => {
      this.el.copyBtn.textContent = '✓';
      setTimeout(() => (this.el.copyBtn.textContent = '📋'), 1500);
    }).catch(() => this._copyFailed(this.el.roomCode));
  }

  /**
   * The browser refused the clipboard (no permission, no focus, or no API at
   * all). Nothing visible used to happen, which reads as "copied". Select the
   * text instead so the system's own copy works, and say so.
   */
  _copyFailed(node) {
    if (node) window.getSelection()?.selectAllChildren(node);
    this._renderSystem(t('share.copyFailed'));
  }

  /**
   * Copy a room code or link, then take it back out of the clipboard.
   *
   * The clipboard outlives the tab. Clipboard managers keep a history, and
   * Windows and Apple devices sync it to the user's other machines; a room
   * code left there is a capability sitting in places this app cannot wipe.
   * Browsers only allow writing while the page has focus, so a clear that
   * comes due in the background waits for the page to be focused again.
   */
  async _copySecret(text) {
    await navigator.clipboard.writeText(text);
    const generation = (this._clipGeneration = (this._clipGeneration || 0) + 1);
    clearTimeout(this._clipTimer);
    // Also held to the wall clock, like the idle lock: a phone that slept
    // with the code copied would otherwise keep it there a minute after waking.
    this._clipDeadline = Date.now() + 60_000;
    this._clipTimer = setTimeout(() => this._clearClipboard(generation), 60_000);
  }

  /** `generation` ties a deferred clear to the copy that scheduled it, so a
   *  stale one cannot wipe something copied since. Omit it to clear now. */
  _clearClipboard(generation = this._clipGeneration) {
    if (!this._clipGeneration || generation !== this._clipGeneration) return;
    clearTimeout(this._clipTimer);
    if (!navigator.clipboard) return;
    if (!document.hasFocus()) {
      window.addEventListener('focus', () => this._clearClipboard(generation), { once: true });
      return;
    }
    this._clipGeneration = 0;
    this._clipDeadline = 0;
    navigator.clipboard.writeText('').catch(() => {});
  }

  _fmtSize(bytes) {
    if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
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
    this._workController.abort();
    this._workController = new AbortController();
    this._landingBusy = false;
    this._setAuthBusy(false);
    for (const btn of [this.el.changePassBtn, this.el.setDuressBtn,
      this.el.delAccountBtn, this.el.signOutOthersBtn]) btn.disabled = false;
    // Invalidate pending signaling, file preparation and decryption before
    // destroying the sessions they belong to.
    this._signalGeneration++;
    this._sendingFiles = 0;
    this._answerKept(null);
    clearTimeout(this._rejoinTimer);
    this._rejoinTimer = null;
    this._warnedSignalLost = false;
    this._warnedSessionEnded = false;
    this._joinPending = false;
    this._closeQrVerify();
    this._discardRecording({ quiet: true });
    this._stopCoverTraffic();
    this._endCallCleanup();
    this._closeImage();
    this.msgMgr?.destroyAll();
    this._quotes?.clear();
    this._delivery?.clear();
    if (this._replyTo) this._cancelReply();
    this._unseen?.clear();
    this._clearTitle();
    this._hideTyping();
    // Tear down every pairwise session; clear the map first so the close
    // callbacks find nothing to re-process.
    const sessions = [...this.peers.values()];
    this.peers.clear();
    this.fileMgr.destroyAll();
    this._syncWakeLock();
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
    this._announced = new Set();
    this._signalQ = Promise.resolve();
    this.iceConfig = { iceServers: [] };
    this._iceExpiresAt = 0;
    this.el.messages.replaceChildren();
    this._scrolledAway = false;
    this._followingEnd = true;
    this.el.jumpNew.classList.add('hidden');
    this.encrypted = false;
    for (const control of [this.el.msgInput, this.el.sendBtn, this.el.attachBtn, this.el.recordBtn]) {
      control.disabled = true;
    }
  }

  /* ── Panic wipe ── */

  _onGlobalKey(e) {
    if (e.key !== 'Escape') return;

    // Escape is the universal way out of a dialog, and here it was also the
    // panic gesture — so someone pressing it to dismiss an overlay was pressing
    // the button that wipes their session. Dismissal wins while anything is
    // open, and does not count toward the wipe.
    if (this._dismissTopDialog()) {
      this._escTimes = [];
      return;
    }

    // Escape also throws away a recording in progress. Unlike closing a
    // dialog it still counts toward the triple-press wipe: someone mashing
    // Escape while the microphone is on is the case the wipe exists for.
    if (this._recorder?.state === 'recording') this._discardRecording();

    const now = Date.now();
    this._escTimes = (this._escTimes || []).filter((t) => now - t < 1000);
    this._escTimes.push(now);
    if (this._escTimes.length >= 3) { this._escTimes = []; this._panicWipe(); }
  }

  /**
   * Close the innermost open overlay, and report whether there was one.
   *
   * An incoming call is deliberately absent: it has accept and reject, and
   * resolving it with a stray keypress is not a kindness.
   */
  _dismissTopDialog() {
    const open = [
      [this.el.imageViewer, () => this._closeImage()],
      [this.el.callMenu, () => this._showCallMenu(false)],
      [this.el.keptAsk, () => this._answerKept(null)],
      [this.el.qrVerify, () => this._closeQrVerify()],
      [this.el.callOverlay, () => this._toggleCallOverlay(false)],
      [this.el.accountPanel, () => this.el.accountPanel.classList.add('hidden')],
    ].find(([el]) => el && !el.classList.contains('hidden'));
    if (!open) return false;
    open[1]();
    this._restoreFocus();
    return true;
  }

  /**
   * Remember where focus was, then move it into the dialog.
   *
   * Without this a keyboard or screen-reader user opens an overlay and stays
   * behind it: the next Tab continues through the page underneath, which is
   * both disorienting and a way to operate controls you cannot see.
   */
  _captureFocus(dialog) {
    this._focusReturn = document.activeElement;
    // Visible, not merely present: these panels hold sections that stay hidden
    // until asked for, and focusing one of those moves focus nowhere at all.
    const target = [...dialog.querySelectorAll(
      'button:not([disabled]), a[href], input:not([disabled]), select, textarea')]
      .find((el) => {
        // Measured, not offsetParent: that is null for anything positioned
        // fixed, which the call overlay is, so it would reject every control on
        // a dialog that is plainly on screen.
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
      });
    // On a touch screen a focused text field brings the keyboard up over the
    // panel that has just opened, before anyone chose to type; there the
    // panel itself takes focus.
    const typing = target?.matches('input:not([type="checkbox"]):not([type="radio"]), textarea');
    // The container itself is the fallback, which is why it carries tabindex="-1":
    // a dialog with nothing to focus should still put the reader inside it.
    ((typing && matchMedia('(pointer: coarse)').matches ? null : target) || dialog).focus?.();
  }

  /**
   * Make everything outside `dialog` inert, or undo it with null.
   *
   * Moving focus into a modal is half of it: Tab past its last control used to
   * walk on into the page underneath — the message field, the panic button —
   * controls the user could not see and could operate. `inert` takes the rest of
   * the page out of focus, clicks and the accessibility tree until the dialog
   * closes. Siblings of each ancestor are marked, so only the dialog's own
   * branch stays live.
   */
  _makeModal(dialog) {
    for (const el of this._inerted || []) el.inert = false;
    this._inerted = [];
    if (!dialog) return;
    for (let node = dialog; node && node !== document.body; node = node.parentElement) {
      for (const sibling of node.parentElement?.children || []) {
        if (sibling === node || sibling.inert || sibling.tagName === 'SCRIPT') continue;
        sibling.inert = true;
        this._inerted.push(sibling);
      }
    }
  }

  _restoreFocus() {
    const target = this._focusReturn;
    this._focusReturn = null;
    if (target && document.contains(target)) target.focus?.();
  }

  /**
   * Turning this on mints the long-term key; turning it off destroys it along
   * with every pin. There is no in-between state: while the feature is off this
   * browser presents nothing that outlives a session.
   */
  async _setContactsEnabled(enabled) {
    const generation = this._identityGeneration = (this._identityGeneration || 0) + 1;
    const current = () => !this._wiping && this._identityGeneration === generation;
    if (enabled) {
      try {
        const identity = await ensureIdentity({ isCurrent: current });
        if (!current()) return;
        this.identity = identity;
      } catch {
        this.el.contactsToggle.checked = false;
        this._renderContacts();
        return;
      }
    } else {
      if (!window.confirm(t('contacts.confirmOff'))) {
        this.el.contactsToggle.checked = true;
        return;
      }
      await clearIdentity().catch(() => {});
      this.identity = null;
    }
    this._renderContacts();
    this._refreshDrops();
  }

  async _restoreIdentity() {
    const generation = this._identityGeneration;
    const identity = await loadIdentity().catch(() => null);
    if (this._wiping || this._identityGeneration !== generation) return;
    this.identity = identity;
    this.el.contactsToggle.checked = !!this.identity;
    this._renderContacts();
    this._refreshDrops();
  }

  async _renderContacts() {
    const box = this.el.contactsList;
    if (!box) return;
    box.replaceChildren();
    const status = h('p', {
      class: 'account-hint',
      text: this.identity ? t('contacts.on') : t('contacts.off'),
    });
    box.append(status);
    if (!this.identity) return;

    const saved = await listContacts().catch(() => []);
    if (this._wiping || !this.identity) return;
    if (saved.length === 0) {
      box.append(h('p', { class: 'account-hint', text: t('contacts.none') }));
      return;
    }
    for (const contact of saved) {
      const forget = h('button', { class: 'btn btn-sm', text: t('contacts.forget') });
      forget.addEventListener('click', async () => {
        await forgetContact(contact.fingerprint);
        this._renderContacts();
        this._refreshDrops();
      });
      box.append(h('div', { class: 'contact-row' },
        h('span', { class: 'contact-name', text: contact.label || '—' }),
        h('code', { class: 'contact-fp', text: contact.fingerprint.slice(0, 16) }),
        forget,
      ));
    }
  }

  async _panicWipe() {
    if (this._wiping) return;
    this._wiping = true;
    this._clearClipboard();
    // Tear down every trace locally, end the session, and reload to a clean screen.
    this._cleanup();
    this.identity = null;
    clearPrefs();
    applyTheme(getPref('theme'));
    try { localStorage.removeItem('dd_lang'); } catch { /* storage may be blocked */ }
    if (this.el.messages) this.el.messages.replaceChildren();
    if (this.el.msgInput) this.el.msgInput.value = '';
    this.roomCode = null;
    this._announced = new Set();
    this.username = null;
    for (const input of [this.el.authUser, this.el.authPass, this.el.authInvite,
      this.el.currentPass, this.el.newPass, this.el.duressPass]) input.value = '';
    this._showPage('auth');
    // wipe=1 also asks the browser to drop cache and origin storage; a plain
    // logout leaves those alone.
    const controller = new AbortController();
    let timer;
    const deadline = new Promise((resolve) => { timer = setTimeout(resolve, 3000); });
    // Owed until the server answers: with no network the session survived the
    // wipe, and the page that loads next has to end it before anything else.
    setSignOutOwed('wipe');
    const logout = fetch('/api/logout?wipe=1', { method: 'POST', signal: controller.signal, keepalive: true })
      .then((res) => { if (res.ok) setSignOutOwed(null); });
    await Promise.race([Promise.allSettled([clearIdentity(), logout]), deadline]);
    clearTimeout(timer);
    controller.abort();
    location.replace(location.origin + '/');
  }

  /* ── Typing indicator ── */

  _sendTyping() {
    if (!this.encrypted || !this.el.typingToggle.checked) return;
    const now = Date.now();
    if (this._lastTypingSent && now - this._lastTypingSent < 1500) return;
    this._lastTypingSent = now;
    for (const s of this._verifiedSessions()) {
      this._sendBestEffort(s.conn, { type: 'typing' });
    }
  }

  /**
   * Who is typing, per peer. One shared flag meant a message from anyone hid
   * the indicator while someone else was still typing, and someone who left
   * mid-sentence stayed "typing" until the timer ran out.
   */
  _showTyping(peerId) {
    const typing = (this._typing ||= new Map());
    clearTimeout(typing.get(peerId));
    typing.set(peerId, setTimeout(() => this._stopTyping(peerId), 3000));
    this._renderTyping();
  }

  _stopTyping(peerId) {
    if (!this._typing?.has(peerId)) return;
    clearTimeout(this._typing.get(peerId));
    this._typing.delete(peerId);
    this._renderTyping();
  }

  _renderTyping() {
    const ids = [...(this._typing?.keys() || [])].filter((id) => this.peers.has(id));
    if (ids.length === 0) {
      this.el.typingIndicator.classList.add('hidden');
      return;
    }
    const text = this.el.typingIndicator.querySelector('[data-i18n="typing"]');
    if (text) {
      const labels = ids.map((id) => this.peers.get(id).label).filter(Boolean);
      if (this.peers.size < 2 || labels.length === 0) text.textContent = t('typing');
      else if (labels.length === 1) text.textContent = t('typing.one').replace('{name}', labels[0]);
      else text.textContent = t('typing.many').replace('{names}', labels.join(', '));
    }
    this.el.typingIndicator.classList.remove('hidden');
  }

  _hideTyping() {
    for (const timer of this._typing?.values() || []) clearTimeout(timer);
    this._typing?.clear();
    this.el.typingIndicator.classList.add('hidden');
  }

  /* ── Privacy screen ── */

  _onVisibilityChange() {
    if (document.hidden) {
      this._hiddenAt = Date.now();
      this._showPrivacyScreen();
    } else {
      this._onPageBack();
    }
  }

  /**
   * After a minute out of sight — a phone asleep, most often — the server has
   * stopped hearing pongs and taken this tab out of the room, while the
   * browser may still report the socket open. Someone following the link then
   * found an empty room. Alone, a fresh join disturbs nobody, so make one.
   * With peers the data channels carry the conversation and a rejoin is not
   * attempted, as when the signalling connection drops.
   */
  _resumeSignaling() {
    const away = this._hiddenAt ? Date.now() - this._hiddenAt : 0;
    this._hiddenAt = 0;
    if (away < 45_000 || !this.roomCode || !this.ws || this.peers.size > 0) return;
    // A dead connection can take its time to report closed, so stop waiting
    // on it: once this.ws is let go, its late close event is ignored.
    try { this.ws.close(); } catch { /* already closing */ }
    this._onSignalingLost();
  }

  /** The page is on screen again, perhaps after the phone slept: whatever
   *  ran out meanwhile goes now, before anyone sees it. */
  _onPageBack() {
    if (this._idleOverdue()) return;
    if (!document.hidden) this._resumeSignaling();
    this._syncWakeLock();
    if (this._clipDeadline && Date.now() >= this._clipDeadline) this._clearClipboard();
    this.msgMgr?.sweep();
    this._flushUnseen();
  }

  /** Cover the conversation. Also on window blur: a phone's app switcher
   *  takes its snapshot as the app loses focus, which can be before the page
   *  is reported hidden, and on a desktop alt-tab leaves the window on show. */
  _showPrivacyScreen() {
    // The privacy screen covers the conversation, and the picture closes:
    // coming back should not open on it, and the screen must stay liftable.
    this._closeImage();
    if (!this.el.chatWrap.classList.contains('hidden')) {
      this.el.privacyScreen.classList.remove('hidden');
    }
  }

  /**
   * Wipe the tab after a stretch with no key, pointer or touch — the panic
   * button pressed on behalf of someone who walked away. Thirty seconds before,
   * the conversation says so; any input resets the clock.
   */
  _armIdleLock() {
    clearTimeout(this._idleTimer);
    clearTimeout(this._idleWarnTimer);
    this._idleWarned = false;
    this._idleDeadline = 0;
    const minutes = Number.parseInt(this.el.idleSelect.value, 10);
    if (!minutes || !this.username) return;
    const ms = minutes * 60_000;
    // Timers count a monotonic clock that stops while a phone sleeps, so a
    // five-minute lock would still be waiting after a night in a pocket. The
    // deadline is wall-clock time, checked again whenever the page comes back.
    this._idleDeadline = Date.now() + ms;
    this._idleWarnTimer = setTimeout(() => {
      if (this._idleOverdue() || this._callInProgress()) return;
      this._idleWarned = true;
      if (!this.el.chatWrap.classList.contains('hidden')) this._renderSystem(t('idle.warning'));
    }, ms - 30_000);
    this._idleTimer = setTimeout(() => this._idleOverdue(), ms);
  }

  /** Signing out ends what the idle lock protects; wiping afterwards would
   *  only take the identity and pinned contacts the user chose to keep. */
  _disarmIdleLock() {
    clearTimeout(this._idleTimer);
    clearTimeout(this._idleWarnTimer);
    this._idleWarned = false;
    this._idleDeadline = 0;
  }

  /**
   * Wipe if the idle deadline has passed; true when it did.
   *
   * A call is someone present, though nobody touches the screen through it:
   * the lock wiped the tab half an hour into a conversation. The clock starts
   * over instead, and again when the call ends.
   */
  _idleOverdue() {
    if (!this._idleDeadline || !this.username || Date.now() < this._idleDeadline) return false;
    if (this._callInProgress()) {
      this._armIdleLock();
      return false;
    }
    this._disarmIdleLock();
    this._panicWipe();
    return true;
  }

  _noteActivity() {
    // The touch that wakes a phone is not activity from before it slept.
    if (this._idleOverdue()) return;
    const now = Date.now();
    // Re-arming on every mousemove would be thousands of timers a minute.
    if (!this._idleWarned && now - (this._lastActivity || 0) < 5000) return;
    this._lastActivity = now;
    this._armIdleLock();
  }

  _hidePrivacyScreen() {
    this.el.privacyScreen.classList.add('hidden');
    this._flushUnseen();
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
      && msg.to === this.peerId
      && typeof msg.payload === 'string'
      && msg.payload.length > 0
      && msg.payload.length <= 64 * 1024;
  }

  _allowInboundSignal(size) {
    const now = Date.now();
    if (now - this._signalWindowAt >= SIGNAL_WINDOW_MS) {
      this._signalWindowAt = now;
      this._signalMessages = 0;
      this._signalBytes = 0;
    }
    this._signalMessages++;
    this._signalBytes += size;
    return this._signalMessages <= MAX_SIGNAL_MESSAGES_PER_WINDOW
      && this._signalBytes <= MAX_SIGNAL_BYTES_PER_WINDOW;
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
    return safeFileMeta(meta);
  }
}

// The one class is written across several files, by subject. Each part's
// methods join it here, before the instance is made; a name defined twice is
// a mistake, and stops the app rather than quietly picking one.
for (const part of [AuthMethods, VerifyMethods, FileMethods, CallMethods, DropMethods]) {
  for (const name of Object.getOwnPropertyNames(part.prototype)) {
    if (name === 'constructor') continue;
    if (Object.hasOwn(DeadDrop.prototype, name)) throw new Error(`app: ${name} is defined twice`);
    Object.defineProperty(DeadDrop.prototype, name, Object.getOwnPropertyDescriptor(part.prototype, name));
  }
}

/**
 * Refuse, in as much detail as we have, rather than hand a password box to a
 * browser that cannot protect it. Built with the DOM directly: this runs on
 * whatever the browser turned out to be, so it uses nothing the app provides.
 */
function renderUnsupported(missing) {
  const detail = document.querySelector('#boot-detail');
  const message = document.querySelector('#boot-msg');
  if (!detail || !message) return;
  message.textContent = t('boot.unsupported');
  message.className = 'boot-fail';
  detail.append(
    h('p', { text: t('boot.explain') }),
    // The capability names stay in English on purpose: they are the algorithm
    // names, and a user pasting one into a search or a bug report is better
    // served by the term the rest of the world uses.
    h('ul', {}, ...missing.map((item) => h('li', { text: `${item.label} — ${item.reason}` }))),
    // WebRTC alone missing is almost always a choice, not an old browser: Tor
    // Browser turns it off, as do some privacy settings. "Use a current
    // Firefox" means nothing to someone already in one.
    h('p', { text: t(missing.every((item) => item.id === 'webrtc') ? 'boot.webrtcOff' : 'boot.suggest') }),
  );
  detail.classList.remove('hidden');
}

/** Say what is unavailable, without pretending the session is less protected. */
function renderDegraded(degraded) {
  const form = document.querySelector('#auth-form');
  if (!form || degraded.length === 0) return;
  form.after(h('p', { class: 'boot-note',
    text: `${t('boot.degraded')}: ${degraded.map((d) => d.label).join(', ')}. `
      + t('boot.stillSafe') }));
}

const support = await checkSupport();
if (support.ok) {
  new DeadDrop();
  renderDegraded(support.degraded);
} else {
  renderUnsupported(support.missing);
}

// Retire the former offline service worker and its caches. A cached cryptographic
// client can outlive a security deployment and mix protocol versions, while the
// app cannot actually chat offline; every load now comes from the embedded,
// no-store server bundle.
if ('serviceWorker' in navigator || 'caches' in window) {
  window.addEventListener('load', () => {
    (async () => {
      if ('serviceWorker' in navigator) {
        const registrations = await navigator.serviceWorker.getRegistrations();
        await Promise.all(registrations.filter((registration) => {
          const workers = [registration.installing, registration.waiting, registration.active].filter(Boolean);
          return workers.some((worker) => new URL(worker.scriptURL).pathname === '/sw.js');
        }).map((registration) => registration.unregister()));
      }
      if ('caches' in window) {
        const keys = await caches.keys();
        await Promise.all(keys.filter((key) => key.startsWith('deaddrop-')).map((key) => caches.delete(key)));
      }
    })().catch(() => {});
  });
}
