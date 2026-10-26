/**
 * Dead Drop — Main Application
 *
 * Orchestrates auth, signaling, P2P connection, encryption, and message lifecycle.
 */

import { CryptoLayer } from './crypto.js';
import { PeerConnection } from './peer.js';
import { MessageManager } from './messages.js';
import {
  FileTransferManager,
  MAX_FILE_SIZE,
  assertFileSizeBinding,
  safeFileMeta,
} from './filetransfer.js';
import { register as srpRegister, ClientLogin, DEFAULT_KDF } from './srp.js';
import {
  loadIdentity, ensureIdentity, clearIdentity,
  pinContact, findContact, forgetContact, listContacts,
} from './identity.js';
import { t, applyI18n, setLang, getLang } from './i18n.js';
import { sanitizeIceConfig, passwordProblem, passphrase } from './util.js';
import { callSignalAllowed } from './callsignal.js';
import { checkSupport } from './support.js';
import { isScrubbable, scrubImage } from './scrub.js';
import { getPref, setPref } from './prefs.js';

const ROOM_CODE_RE = /^[0-9a-f]{24}$/;
const MESSAGE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PEER_ID_RE = /^[0-9a-f]{32}$/;
const MAX_TEXT_LEN = 16 * 1024;

/** Media arrived for a call that had already ended; nothing left to do. */
class CallGone extends Error {}
const MAX_RENDERED_NODES = 600;
const MAX_REMOTE_PEERS = 5;
const SIGNAL_WINDOW_MS = 10 * 1000;
// How long a call rings before the caller gives up. The callee gives up a
// little later, so the caller's hang-up normally arrives first.
const CALL_RING_MS = 45 * 1000;
const CALL_MISSED_MS = CALL_RING_MS + 5 * 1000;
const MAX_SIGNAL_MESSAGES_PER_WINDOW = 240;
const MAX_SIGNAL_BYTES_PER_WINDOW = 1024 * 1024;
const ALLOWED_TTLS = new Set([0, 10, 30, 60, 300]);
const CURRENT_KDF_ITERATIONS = Number(DEFAULT_KDF.split(':')[1]);

/**
 * Build an element without ever handing a string to an HTML parser.
 *
 * `node.append()` inserts strings as text nodes, so nothing here can be talked
 * into creating markup. Every render path below uses this instead of innerHTML,
 * which is what lets the CSP refuse the innerHTML sink outright — see
 * require-trusted-types-for in internal/middleware/headers.go.
 */
/**
 * Element.append with h()'s rule for children: null, undefined and false mean
 * "nothing here". The DOM's own append stringifies them, which is how every
 * message in a two-person room came to read "null" above its text.
 */
function appendPresent(parent, ...children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    parent.append(child);
  }
  return parent;
}

function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child);
  }
  return node;
}

// The server answers in plain English. The ones a person can actually meet
// are translated here; anything else is shown as sent rather than hidden.
const SERVER_ERRORS = {
  'invalid credentials': 'srv.badLogin',
  'invalid or used invite code': 'srv.badInvite',
  'too many attempts — try again later': 'srv.tooMany',
  'too many requests': 'srv.tooMany',
  'username: 3–20 chars, letters/numbers/underscores': 'srv.username',
  'registration temporarily unavailable': 'srv.unavailable',
  'authentication temporarily unavailable': 'srv.unavailable',
  're-authentication required': 'srv.reauth',
  'session expired': 'srv.expired',
  'not authenticated': 'srv.expired',
  'room unavailable': 'srv.roomFull',
  'invalid room code': 'err.roomCode',
};

function serverMessage(text, fallbackKey) {
  if (!text) return t(fallbackKey);
  const key = SERVER_ERRORS[text];
  return key ? t(key) : text;
}

// Web addresses in a message become links — built as elements, never markup,
// and only for http(s). The visible text is the address itself, so a link
// cannot say one place and go to another. No preview is ever fetched: that
// would tell the linked site this device's address before anyone clicked.
const URL_IN_TEXT = /\bhttps?:\/\/[^\s<>"'`]+/gi;

// "see https://example.com." — the full stop belongs to the sentence. A
// closing bracket belongs to the address only when it closes one inside it,
// as in https://en.wikipedia.org/wiki/Foo_(bar).
function trimUrl(raw) {
  const pairs = { ')': '(', ']': '[', '}': '{' };
  let end = raw.length;
  while (end > 0) {
    const ch = raw[end - 1];
    if ('.,;:!?\'"'.includes(ch)) { end--; continue; }
    const open = pairs[ch];
    if (open) {
      const body = raw.slice(0, end);
      if (body.split(ch).length > body.split(open).length) { end--; continue; }
    }
    break;
  }
  return raw.slice(0, end);
}

function linkify(text) {
  const parts = [];
  let last = 0;
  for (const match of text.matchAll(URL_IN_TEXT)) {
    const raw = trimUrl(match[0]);
    let href;
    let shown = raw;
    try {
      const url = new URL(raw);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') continue;
      // "https://bank.example@elsewhere.example" goes to elsewhere.example;
      // everything before the @ is a user name, there to be read as the host.
      // Nobody sends a real link with credentials in it: left as text.
      if (url.username || url.password) continue;
      href = url.href;
      // A host in another script can be drawn to look like a familiar one —
      // "аpple.com" with a Cyrillic а. Browsers show such hosts in their
      // punycode form so the difference is visible; so does the link.
      if (url.hostname.split('.').some((label) => label.startsWith('xn--'))) shown = href;
    } catch { continue; }
    if (match.index > last) parts.push(text.slice(last, match.index));
    parts.push(h('a', {
      href, text: shown, target: '_blank', rel: 'noopener noreferrer nofollow', class: 'msg-link',
    }));
    last = match.index + raw.length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

/**
 * The room code in what someone typed or pasted: the code itself, or the whole
 * invitation link — which is what people are actually sent, and used to be cut
 * to its first 24 characters by the field's maxlength and refused.
 */
function roomCodeFrom(input) {
  const text = String(input || '').trim().toLowerCase();
  const match = text.match(/#join=([0-9a-f]{24})(?![0-9a-f])/) || text.match(/^([0-9a-f]{24})$/);
  return match ? match[1] : null;
}

function needsKdfUpgrade(kdf) {
  const match = /^pbkdf2:(\d+)$/.exec(kdf || '');
  return !match || Number(match[1]) < CURRENT_KDF_ITERATIONS;
}

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
    this.fileMgr.onTimeout = () => this._syncWakeLock();
    this.encrypted = false; // true when ≥1 pairwise session is encrypted and SAS-verified
    this.iceConfig = { iceServers: [] };
    this._iceExpiresAt = 0;
    // On by default: a direct connection hands the other person your IP
    // address. Falls back to direct only when no relay is configured, and says so.
    this._relayOnly = getPref('relayOnly');
    this._coverEnabled = getPref('coverTraffic'); // decoy traffic to mask when real chatting happens
    this._coverTimer = null;
    this._signalWindowAt = Date.now();
    this._signalMessages = 0;
    this._signalBytes = 0;
    this._signalQ = Promise.resolve();
    this._signalGeneration = 0;

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

  // Parse a shared join link (#join=<code>) and remember the room to pre-fill.
  _readJoinHash() {
    const m = location.hash.match(/^#join=([0-9a-f]{24})$/i);
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
      callMenu: $('#call-menu'),
      callVoice: $('#call-voice'),
      callVideo: $('#call-video'),
      acceptAudio: $('#accept-audio'),
      replyBarText: $('#reply-bar-text'),
      replyCancel: $('#reply-cancel'),
      idleSelect: $('#idle-select'),
      // Chat
      chatWrap:    $('#chat-wrap'),
      roomInfo:    $('#room-info'),
      roomCode:    $('#room-code'),
      copyBtn:     $('#copy-code'),
      messages:    $('#messages'),
      msgInput:    $('#msg-input'),
      landingError: $('#landing-error'),
      authInvited: $('#auth-invited'),
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
      toggleMic:     $('#toggle-mic'),
      toggleCam:     $('#toggle-cam'),
      flipCam:       $('#flip-cam'),
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
    this.el.settingsBtn.addEventListener('click', () => {
      this.el.accountPanel.classList.toggle('hidden');
      if (this.el.accountPanel.classList.contains('hidden')) {
        this._restoreFocus();
      } else {
        // A fresh look at the panel starts without last time's results.
        for (const msg of [this.el.passMsg, this.el.duressMsg, this.el.deleteMsg]) msg.classList.add('hidden');
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
    // Room
    this.el.createBtn.addEventListener('click', () => this.createRoom());
    this.el.joinBtn.addEventListener('click', () => this.joinRoom());
    this.el.copyBtn.addEventListener('click', () => this._copyCode());
    this.el.qrVerifyClose.addEventListener('click', () => this._closeQrVerify());
    // Remembered switches. The markup's defaults are the safe ones; a stored
    // preference only ever changes them because the user did.
    this.el.relayToggle.checked = this._relayOnly;
    this.el.coverToggle.checked = this._coverEnabled;
    this.el.scrubToggle.checked = getPref('scrubMetadata');
    this.el.typingToggle.checked = getPref('typingIndicator');
    this.el.ringToggle.checked = getPref('callRing');
    this.el.idleSelect.value = String(getPref('idleLockMinutes'));
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
    this.el.jumpNew.addEventListener('click', () => {
      this.el.messages.scrollTop = this.el.messages.scrollHeight;
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
      const file = e.target.files[0];
      if (file) this.sendFile(file);
      e.target.value = '';
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
      const file = e.dataTransfer.files[0];
      if (file && this.encrypted) this.sendFile(file);
    });
    // A screenshot pasted into the message field is sent like an attachment —
    // through the same metadata stripping. Pasted text is left to the field.
    this.el.msgInput.addEventListener('paste', (e) => {
      const files = [...(e.clipboardData?.files || [])];
      // Word, Excel and others put a picture of the selection on the clipboard
      // beside its text. Text there means the person copied text: paste it.
      if (!files.length || e.clipboardData.getData('text/plain')) return;
      e.preventDefault();
      if (!this.encrypted) return;
      for (const file of files.slice(0, 5)) this.sendFile(file);
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
    // Message key → the quotes of it in replies; bubble → its own quote.
    this._quotes = new Map();
    this._quoteOf = new WeakMap();
    this._replyTo = null;
    this.msgMgr.onRemoved = (key, el) => this._forgetQuoted(key, el);
  }

  /* ── Auth ── */

  async _checkAuth() {
    try {
      const res = await fetch('/api/me');
      if (res.ok) {
        const data = await res.json();
        this.username = data.username;
        // A returning visitor lands here rather than in _afterAuth, so without
        // this the identity stays unloaded and every saved contact is silently
        // forgotten on reload — the exact case the feature exists for.
        await this._restoreIdentity().catch(() => {});
        this._showPage('landing');
        // Nor did a reload arm the idle lock: it waited for the first key or
        // touch, so a tab reloaded and left alone was never wiped.
        this._armIdleLock();
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
      if (!ch.ok) { this._showAuthError(serverMessage(ch.data.error, 'srv.badLogin')); return; }

      // The challenge advertises each credential's password-stretch KDF.
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
      if (!auth.ok) { this._showAuthError(serverMessage(auth.data.error, 'srv.badLogin')); return; }
      // Authenticate the server too. Which locally-computed M2 matches tells this
      // browser which credential won; the server response remains identical for
      // primary and duress sessions, so it carries no observable decoy marker.
      const primaryOK = client.verifyServer(auth.data.M2);
      const duressOK = !!clientD && clientD.verifyServer(auth.data.M2);
      if (!primaryOK && !duressOK) {
        this._showAuthError(t('err.serverAuth'));
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
          await this._postJSON('/api/account/verifier',
            { ...up, ...(await this._reauthProof(username, password)) });
        } catch { /* best-effort; login already succeeded */ }
      }
      this._afterAuth();
    } catch {
      this._showAuthError(t('err.connection'));
    } finally {
      this._setAuthBusy(false);
    }
  }

  /** Prove the current password again for a credential change. A session cookie
   *  alone must not be able to rekey the account, so the server re-runs the SRP
   *  verification against whichever credential this session was opened with. */
  async _reauthProof(username, password) {
    const client = new ClientLogin(username, password);
    const ch = await this._postJSON('/api/srp/challenge', { username, A: client.start().A });
    if (!ch.ok) throw new Error('re-authentication challenge failed');
    const { M1 } = await client.finish(ch.data.salt, ch.data.B, ch.data.kdf);
    let M1d = '';
    if (ch.data.salt2 && ch.data.B2) {
      const clientD = new ClientLogin(username, password, client.a);
      clientD.start();
      M1d = (await clientD.finish(ch.data.salt2, ch.data.B2, ch.data.kdf2)).M1;
    }
    return { token: ch.data.token, M1, M1d };
  }

  async _register() {
    const username = this.el.authUser.value.trim();
    const password = this.el.authPass.value;
    const invite = this.el.authInvite.value.trim();
    if (!username || !password) return;
    const weak = passwordProblem(password, username);
    if (weak) { this._showAuthError(t(weak)); return; }
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
        this._showAuthError(serverMessage(res.data.error, 'srv.registerFailed'));
      }
    } catch {
      this._showAuthError(t('err.connection'));
    } finally {
      this._setAuthBusy(false);
    }
  }

  /**
   * Put a fresh six-word passphrase in `input` and show it. Visible on
   * purpose: a generated secret nobody wrote down is an account nobody can
   * open again. It goes back to dots once the auth or the change completes.
   * The word list is fetched only when asked for — the import map pins its
   * hash like every other module.
   */
  async _fillPassphrase(input) {
    const { WORDS } = await import('./wordlist.js');
    input.value = passphrase(WORDS);
    input.type = 'text';
    input.focus();
    input.select();
  }

  _concealPasswords() {
    for (const input of [this.el.authPass, this.el.newPass]) input.type = 'password';
    this.el.genPassNote.classList.add('hidden');
  }

  _afterAuth() {
    this._concealPasswords();
    this.el.authPass.value = '';
    this.el.authInvite.value = '';
    this.el.currentPass.value = '';
    this.el.accountPanel.classList.add('hidden');
    this._restoreIdentity().catch(() => {});
    this._showPage('landing');
    this._armIdleLock();
  }

  /**
   * Replace the password this session was opened with. The server re-checks the
   * current one, stores the new verifier, and signs out every other session —
   * the point of changing a password is usually that someone else has it. In a
   * decoy session the same request updates the decoy credential, so the flow
   * looks identical either way.
   */
  async _changePassword() {
    const next = this.el.newPass.value;
    const current = this.el.currentPass.value;
    const say = (text, ok = false) => this._accountMsg(this.el.passMsg, text, ok);
    const weak = passwordProblem(next, this.username);
    if (weak) {
      this.el.newPass.focus();
      say(t(weak));
      return;
    }
    if (!current) {
      this.el.currentPass.focus();
      say(t('account.needCurrent'));
      return;
    }
    await this._accountBusy(this.el.changePassBtn, say, async () => {
      let proof;
      try {
        proof = await this._reauthProof(this.username, current);
      } catch {
        say(t('account.wrongCurrent'));
        return;
      }
      const credential = await srpRegister(this.username, next);
      const res = await this._postJSON('/api/account/verifier', { ...credential, ...proof });
      if (res.status === 401) { say(t('account.wrongCurrent')); return; }
      if (!res.ok) { say(serverMessage(res.data.error, 'err.connection')); return; }
      say(t('account.passChanged'), true);
      this.el.newPass.value = '';
      this.el.currentPass.value = '';
      this._concealPasswords();
    });
  }

  /**
   * Set (or update) the duress password. Computed locally — never sent in the
   * clear. Held to the same strength rule as the real password: a decoy that
   * is easy to guess is a decoy that gets found.
   */
  async _setDuress() {
    const pw = this.el.duressPass.value;
    const current = this.el.currentPass.value;
    const say = (text, ok = false) => this._accountMsg(this.el.duressMsg, text, ok);
    const weak = passwordProblem(pw, this.username);
    if (weak) {
      this.el.duressPass.focus();
      say(t(weak));
      return;
    }
    if (!current) {
      this.el.currentPass.focus();
      say(t('account.needCurrent'));
      return;
    }
    // The server stores only verifiers and cannot tell two equal passwords
    // apart; this is the one place the comparison can be made.
    if (pw === current) {
      this.el.duressPass.focus();
      say(t('duress.sameAsReal'));
      return;
    }
    await this._accountBusy(this.el.setDuressBtn, say, async () => {
      let proof;
      try {
        proof = await this._reauthProof(this.username, current);
      } catch {
        say(t('account.wrongCurrent'));
        return;
      }
      const { salt, verifier, kdf } = await srpRegister(this.username, pw);
      const res = await this._postJSON('/api/account/duress', { salt, verifier, kdf, ...proof });
      if (res.status === 401) { say(t('account.wrongCurrent')); return; }
      if (!res.ok) { say(serverMessage(res.data.error, 'err.connection')); return; }
      say(t('duress.saved'), true);
      this.el.duressPass.value = '';
      this.el.currentPass.value = '';
    });
  }

  async _deleteAccount() {
    const current = this.el.currentPass.value;
    const say = (text) => this._accountMsg(this.el.deleteMsg, text);
    if (!current) {
      this.el.currentPass.focus();
      say(t('account.needCurrent'));
      return;
    }
    if (!confirm(t('account.confirmDelete'))) return;
    await this._accountBusy(this.el.delAccountBtn, say, async () => {
      let proof;
      try {
        proof = await this._reauthProof(this.username, current);
      } catch {
        say(t('account.wrongCurrent'));
        return;
      }
      const res = await this._postJSON('/api/account/delete', proof);
      if (res.status === 401) { say(t('account.wrongCurrent')); return; }
      if (!res.ok) { say(serverMessage(res.data.error, 'err.connection')); return; }
      this.el.currentPass.value = '';
      this._cleanup();
      location.replace(location.origin + '/');
    });
  }

  /** Show what an account action did, under its own button, until the next one. */
  _accountMsg(el, text, ok = false) {
    el.textContent = text;
    el.classList.toggle('ok', ok);
    el.classList.remove('hidden');
  }

  /**
   * Run one account action with its button held down, so a second click cannot
   * send a second request, and with a network failure reported rather than lost.
   */
  async _accountBusy(btn, say, action) {
    btn.disabled = true;
    try {
      await action();
    } catch {
      say(t('err.connection'));
    } finally {
      btn.disabled = false;
    }
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

  /**
   * The signaling socket failed: find out whether the login itself is gone.
   *
   * This used to rerun the boot-time check, which sent anyone whose network
   * blinked to the sign-in page (no answer read as "not logged in") and
   * anyone still logged in out of their room to the landing page. Only a 401
   * ends anything now; a network failure is left to the reconnect logic. A
   * conversation that is already running is direct and is not torn down —
   * it is told the login ended, and the room goes to sign-in once empty.
   */
  async _recheckSession() {
    let res;
    try { res = await fetch('/api/me'); } catch { return; }
    if (res.status !== 401) return;
    if (this._verifiedSessions().length > 0) {
      if (!this._warnedSessionEnded) {
        this._warnedSessionEnded = true;
        this._renderSystem(t('sys.sessionEnded'));
      }
      return;
    }
    this._disarmIdleLock();
    this._cleanup();
    this.username = null;
    this._showPage('auth');
    this._showAuthError(t('auth.sessionEnded'));
  }

  async _logout() {
    this._disarmIdleLock();
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
    document.querySelector('#boot')?.classList.add('hidden');
    this.el.auth.classList.add('hidden');
    this.el.landing.classList.add('hidden');
    this.el.chatWrap.classList.add('hidden');

    // Arriving through an invitation link: say so on whichever page comes
    // first, until the room is joined or left behind.
    this.el.authInvited.classList.toggle('hidden', !this._pendingJoin);
    this.el.landingInvited.classList.toggle('hidden', !(name === 'landing' && this._pendingJoin));

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
    if (this._landingBusy) return;
    this._landingBusy = true;
    try { await action(); } finally { this._landingBusy = false; }
  }

  createRoom() {
    return this._landingAction(() => this._createRoom());
  }

  joinRoom() {
    return this._landingAction(() => this._joinRoom());
  }

  async _createRoom() {
    this._landingError('');
    // Request a server-generated room code (stronger entropy)
    try {
      const res = await fetch('/api/room', { method: 'POST' });
      const data = await res.json();
      if (!res.ok || typeof data.code !== 'string' || !ROOM_CODE_RE.test(data.code)) {
        this._landingError(serverMessage(data.error, 'err.roomCreate'));
        return;
      }
      this.roomCode = data.code;
    } catch {
      this._landingError(t('err.roomCreate'));
      return;
    }
    await this._loadIceServers();
    try {
      await this._connectSignaling();
      this._joinPending = true;
      this.ws.send(JSON.stringify({ type: 'join', room: this.roomCode }));
    } catch {
      this._landingError(t('err.signaling'));
      return;
    }
    this._enterChat(this.roomCode);
    this._renderShareLink(this.roomCode);
    this._setStatus('waiting', () => t('st.waiting'));
  }

  _renderShareLink(code) {
    const link = `${location.origin}/#join=${code}`;
    const el = document.createElement('div');
    el.className = 'msg system share-link';
    // Keyed for the translator, so switching language turns the invitation
    // too instead of leaving it in the one it was drawn in.
    const btn = h('button', { class: 'btn btn-sm copy-link-btn', 'data-i18n': 'share.copy', text: t('share.copy') });
    const actions = h('div', { class: 'share-actions' }, btn);
    el.append(
      h('span', { class: 'share-intro', 'data-i18n': 'share.intro', text: t('share.intro') }),
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
    this._landingError('');
    this.el.landingInvited.classList.add('hidden');
    if (!this.el.roomInput.value.trim()) return;
    const code = roomCodeFrom(this.el.roomInput.value);
    if (!code || !ROOM_CODE_RE.test(code)) {
      this._landingError(t('err.roomCode'));
      return;
    }
    await this._loadIceServers();
    try {
      await this._connectSignaling();
    } catch {
      this._landingError(t('err.signaling'));
      return;
    }
    this.roomCode = code;
    this._joinPending = true;
    this.ws.send(JSON.stringify({ type: 'join', room: code }));
    this._enterChat(code);
    this._setStatus('connecting', () => t('st.joining'));
  }

  _enterChat(code) {
    this._showPage('chat');
    this.el.roomCode.textContent = code;
    this.el.roomInfo.classList.remove('hidden');
  }

  /* ── Signaling (WebSocket → signaling server) ── */

  _connectSignaling() {
    return new Promise((resolve, reject) => {
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
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const socket = new WebSocket(`${proto}//${location.host}/ws`);
      this.ws = socket;
      const timer = setTimeout(() => {
        if (settled || generation !== this._signalGeneration || this.ws !== socket) return;
        settled = true;
        socket.close();
        reject(new Error('WebSocket welcome timeout'));
      }, 15000);

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
          settled = true;
          clearTimeout(timer);
          resolve();
        }
        if (!this.peerId && msg.type !== 'welcome') return;
        this._signalQ = this._signalQ
          .then(() => {
            if (generation !== this._signalGeneration || this.ws !== socket) return undefined;
            return this._onSignal(msg);
          })
          .catch((err) => console.warn('[ws] signaling message failed', err));
      };

      socket.onclose = () => {
        clearTimeout(timer);
        if (generation !== this._signalGeneration || this.ws !== socket) return;
        if (settled && this.roomCode) this._onSignalingLost();
        else this._setStatus('disconnected', () => t('st.serverLost'));
        if (!settled) {
          settled = true;
          reject(new Error('WebSocket closed before welcome'));
        }
      };
      socket.onerror = () => {
        clearTimeout(timer);
        if (generation !== this._signalGeneration || this.ws !== socket) return;
        // Could be an ended session — but only the server saying so counts.
        this._recheckSession();
        if (!settled) {
          settled = true;
          reject(new Error('WebSocket error'));
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
    clearTimeout(this._rejoinTimer);
    const room = this.roomCode;
    this._rejoinTimer = setTimeout(async () => {
      if (!room || this.roomCode !== room || this.ws) return;
      const next = Math.min(delay * 2, 30000);
      if (this.peers.size > 0) { this._scheduleRejoin(next); return; }
      this.peerId = null;
      this._announced = new Set();
      try {
        await this._connectSignaling();
      } catch {
        this.ws = null;
        if (this.roomCode === room) {
          this._setStatus('disconnected', () => t('st.reconnecting'));
          this._scheduleRejoin(next);
        }
        return;
      }
      if (this.roomCode !== room) return;
      this._warnedSignalLost = false;
      this._joinPending = true;
      this.ws.send(JSON.stringify({ type: 'join', room }));
    }, delay);
  }

  async _onSignal(msg) {
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
    const cryptoLayer = new CryptoLayer();
    const conn = new PeerConnection(
      { send: (o) => this.ws.send(JSON.stringify(o)) },
      cryptoLayer,
      (m) => this._onPeerMessage(peerId, m),
      (state, sas) => this._onConnState(peerId, state, sas),
      { iceServers: this.iceConfig.iceServers, relayOnly: this._relayOnly && this._hasRelay() },
      this.identity,
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
    const relay = this.iceConfig.iceServers.some((server) => [server.urls].flat()
      .some((url) => /^turns?:/.test(String(url))));
    if (!relay && this._relayOnly && !this._warnedNoRelay) {
      this._warnedNoRelay = true;
      this._renderSystem(t('warn.noRelay'));
    }
    return relay;
  }

  /** Fetch self-hosted STUN/TURN ICE servers (with an ephemeral credential). */
  async _loadIceServers() {
    const now = Date.now();
    if (this._iceExpiresAt - now > 5 * 60 * 1000) return;
    if (this._iceExpiresAt <= now) this.iceConfig.iceServers = [];
    try {
      const res = await fetch('/api/turn');
      if (!res.ok) return;
      const raw = await res.text();
      if (raw.length > 32 * 1024) throw new Error('ICE response too large');
      const clean = sanitizeIceConfig(JSON.parse(raw));
      this.iceConfig.iceServers = clean.iceServers;
      this._iceExpiresAt = Date.now() + clean.ttl * 1000;
    } catch { /* keep host candidates only */ }
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
    if (!known) {
      this._maybeSaveContact(peerId); // the user may have already confirmed
      this._refreshRoomState();
      return;
    }
    s.knownContact = known;
    s.label = known.label || s.label;
    this._renderSystem(`🔖 ${s.label} ${t('contact.recognised')}`);
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
    pinContact(s.identityFp, label.trim() || s.label)
      .then(() => {
        s.knownContact = { fingerprint: s.identityFp, label };
        s.label = label.trim() || s.label;
        this._renderSystem(`🔖 ${s.label} ${t('contact.saved')}`);
        this._refreshRoomState();
      })
      .catch(() => this._renderSystem(t('contact.saveFailed')));
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

  _closeQrVerify() {
    this._stopQrScan();
    this.el.qrVerify.classList.add('hidden');
    this._makeModal(null);
    this._restoreFocus();
  }

  /* ── File transfer ── */

  async sendFile(file) {
    if (!this.encrypted) return;
    if (this.el.scrubToggle.checked && isScrubbable(file)) {
      try {
        file = await scrubImage(file);
      } catch (err) {
        console.warn('metadata removal failed:', err?.message);
        this._renderSystem(t('err.scrubFailed'));
        return;
      }
    }
    if (file.size > MAX_FILE_SIZE) {
      this._renderSystem(`${t('err.fileTooLarge')} — max ${MAX_FILE_SIZE / 1024 / 1024} MB`);
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
    //
    // The sender's copy appears at once, but on a slow link 25 MB takes a
    // while to leave; closing the tab before then loses it. Say how far it got.
    const targets = [...this.peers].filter(([, s]) => s.verified && s.conn.userVerified);
    const own = document.getElementById(this._domMessageId(this._messageKey(null, id)));
    const sending = own && targets.length
      ? h('div', { class: 'file-sending', text: t('file.sending').replace('{pct}', '0') })
      : null;
    if (sending) own.append(sending);
    const results = [];
    this._awaitDelivery(id, targets.map(([peerId]) => peerId));
    this._sendingFiles = (this._sendingFiles || 0) + 1;
    this._syncWakeLock();
    for (const [index, [peerId, s]] of targets.entries()) {
      const onProgress = sending && ((done, total) => {
        const pct = Math.min(100, Math.floor(((index + done / total) / targets.length) * 100));
        sending.textContent = t('file.sending').replace('{pct}', String(pct));
      });
      try {
        await this.fileMgr.send(file, id, s.crypto, s.conn, ttl, burn, onProgress, peerId);
        results.push({ status: 'fulfilled' });
      } catch (reason) {
        results.push({ status: 'rejected', reason });
        this._undeliverable(id, peerId);
      }
    }
    this._sendingFiles -= 1;
    this._syncWakeLock();
    sending?.remove();
    if (results.some((r) => r.status === 'rejected')) {
      console.error('File send failed:', results.find((r) => r.status === 'rejected')?.reason);
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
    this.sendFile(new File([blob], `voice.${ext}`, { type }));
  }

  /* ── Messaging ── */

  async sendMessage() {
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
        await s.conn.send({
          type: 'chat', id, ciphertext, iv, epoch, ttl, burnAfterReading: burn, ...quoting,
        });
      } catch (err) {
        console.warn('Send failed for one peer:', err);
        this._undeliverable(id, peerId);
      }
    }

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
      case 'file':
      case 'file-chunk':
      case 'file-end': {
        let result;
        try {
          result = this.fileMgr.handleMessage(msg, peerId);
        } catch (err) {
          console.warn('File transfer message rejected:', err);
        } finally {
          this._syncWakeLock();
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

  async _onFileComplete(result, s, peerId) {
    let fileData;
    try {
      // Decrypt metadata
      const metaJson = await s.crypto.decrypt(result.meta.ciphertext, result.meta.iv, result.meta.epoch);
      const rawMeta = JSON.parse(metaJson);
      assertFileSizeBinding(rawMeta?.fileSize, result.ciphertext.byteLength);
      const meta = this._sanitizeFileMeta(rawMeta);
      if (!meta) throw new Error('Invalid file metadata');

      // Decrypt file data
      fileData = await s.crypto.decryptBinary(result.ciphertext, result.fileIv, result.fileEpoch);
      assertFileSizeBinding(meta.fileSize, result.ciphertext.byteLength, fileData.byteLength);
      const blob    = new Blob([fileData], { type: meta.fileType });
      const blobUrl = URL.createObjectURL(blob);

      // Replace progress placeholder with actual preview
      this._renderFileComplete(
        result.id, blobUrl, meta, result.ttl, result.burnAfterReading, s, peerId,
      );
      this._sendBestEffort(s.conn, { type: 'got', id: result.id });
    } catch (err) {
      console.error('File decryption failed:', err.message);
      this._renderSystem(t('err.fileDecrypt'));
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
    this.el.localVideo.srcObject = null;
    this.el.remoteVideo.srcObject = null;
    // A call that fails mid-negotiation gets torn down here, and left the last
    // status behind: the user was told "connecting" forever with nothing to
    // connect to.
    this._showCallStatus('');
    this._toggleCallOverlay(false);
    this._showRinging(false);
    this.el.remotePlaceholder.classList.remove('hidden');
    this._updateCallBtn(false);
    this._showCallMenu(false);
    this._resetMuteButtons();
    this._refreshRoomState();
  }

  _onRemoteTrack(stream) {
    this.remoteStream = stream;
    this.el.remoteVideo.srcObject = stream;
    // A voice call has no picture to show: keep the placeholder up.
    this.el.remotePlaceholder.classList.toggle('hidden', stream.getVideoTracks().length > 0);
  }

  /** No camera in this call: the camera button has nothing to switch. */
  _syncCamButton() {
    const cam = this.localStream?.getVideoTracks()[0];
    this.el.toggleCam.disabled = !cam;
    this.el.flipCam.classList.add('hidden');
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
      this._msgActions(el, key, mine),
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

    let preview;
    if (meta.fileType.startsWith('image/')) {
      preview = h('img', {
        src: blobUrl, alt: meta.fileName, class: 'file-preview-img', loading: 'lazy',
      });
    } else if (meta.fileType.startsWith('video/')) {
      preview = h('video', {
        src: blobUrl, controls: '', playsinline: '', class: 'file-preview-video',
      });
    } else if (meta.fileType.startsWith('audio/')) {
      preview = h('audio', { src: blobUrl, controls: '', class: 'file-preview-audio' });
    }

    // Anything without a preview is one compact row — icon, name and size —
    // rather than a tall card around a lone icon.
    appendPresent(el,
      this._senderTag(mine, sender),
      preview && h('div', { class: 'file-content' }, preview),
      h('div', { class: 'file-details' },
        !preview && h('span', { class: 'file-icon', 'aria-hidden': 'true', text: '📄' }),
        h('span', { class: 'file-name',
          text: /^voice\.(webm|ogg|m4a)$/.test(meta.fileName) && meta.fileType.startsWith('audio/')
            ? t('voice.label') : meta.fileName }),
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

    this._appendToLog(el, mine);

    this.msgMgr.add(key, el, ttl, burn, mine, blobUrl, {
      wireId: id,
      peerId,
      deferTtl: !mine && !this._onScreen(),
      blobBytes: meta.fileSize,
    });
    // Long enough to open or save it, not just to see that it came.
    if (!mine) this._markSeen(key, 15_000);
  }

  _renderFileProgress(id, received, total, peerId) {
    if (!this._validMessageID(id) || !Number.isSafeInteger(total) || total < 1) return;
    const key = this._messageKey(peerId, id);
    const el = document.createElement('div');
    el.className = 'msg theirs file-msg';
    el.id = this._domMessageId(key);
    el.append(
      // `total` counts transfer chunks, which mean nothing to the reader;
      // the percentage is what is shown and announced.
      h('div', { class: 'file-receiving' },
        h('span', { text: t('file.receiving') }),
        h('div', {
          class: 'progress-bar', role: 'progressbar', 'aria-label': t('file.receiving'),
          'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': '0',
        }, h('div', { class: 'progress-fill' })),
        h('span', { class: 'progress-text', text: '0%' }),
      ),
    );
    this._appendToLog(el);
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
    const key = this._messageKey(peerId, id);
    const old = document.getElementById(this._domMessageId(key));
    if (old) old.remove();
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

  /** Reply to any message; delete for everyone, one's own. */
  _msgActions(bubble, key, mine) {
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

  /** Burn badge and TTL countdown, or nothing when neither applies. */
  _metaRow(burn, ttl) {
    if (!burn && ttl <= 0) return null;
    return h('div', { class: 'msg-meta' },
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
  _appendToLog(el, follow = false) {
    const list = this.el.messages;
    const atEnd = this._atLogEnd();
    list.appendChild(el);
    this._pruneRenderedNodes();
    if (follow || atEnd) {
      list.scrollTop = list.scrollHeight;
      return;
    }
    this._scrolledAway = true;
    this.el.jumpNew.classList.remove('hidden');
  }

  _atLogEnd() {
    const list = this.el.messages;
    return list.scrollHeight - list.scrollTop - list.clientHeight < 80;
  }

  _onLogScroll() {
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
    // Invalidate already-queued asynchronous signaling work before destroying
    // its sessions, socket, and ICE credentials.
    this._signalGeneration++;
    clearTimeout(this._rejoinTimer);
    this._rejoinTimer = null;
    this._warnedSignalLost = false;
    this._warnedSessionEnded = false;
    this._joinPending = false;
    this._closeQrVerify();
    this._discardRecording({ quiet: true });
    this._stopCoverTraffic();
    this._endCallCleanup();
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
      [this.el.callMenu, () => this._showCallMenu(false)],
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
    // The container itself is the fallback, which is why it carries tabindex="-1":
    // a dialog with nothing to focus should still put the reader inside it.
    (target || dialog).focus?.();
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
    if (enabled) {
      try {
        this.identity = await ensureIdentity();
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
  }

  async _restoreIdentity() {
    this.identity = await loadIdentity().catch(() => null);
    this.el.contactsToggle.checked = !!this.identity;
    this._renderContacts();
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
    if (saved.length === 0) {
      box.append(h('p', { class: 'account-hint', text: t('contacts.none') }));
      return;
    }
    for (const contact of saved) {
      const forget = h('button', { class: 'btn btn-sm', text: t('contacts.forget') });
      forget.addEventListener('click', async () => {
        await forgetContact(contact.fingerprint);
        this._renderContacts();
      });
      box.append(h('div', { class: 'contact-row' },
        h('span', { class: 'contact-name', text: contact.label || '—' }),
        h('code', { class: 'contact-fp', text: contact.fingerprint.slice(0, 16) }),
        forget,
      ));
    }
  }

  async _panicWipe() {
    this._clearClipboard();
    // Tear down every trace locally, end the session, and reload to a clean screen.
    this._cleanup();
    // The identity and its pinned contacts are the only things this app keeps
    // across sessions, so a panic wipe has to take them too.
    await clearIdentity().catch(() => {});
    if (this.el.messages) this.el.messages.replaceChildren();
    if (this.el.msgInput) this.el.msgInput.value = '';
    this.roomCode = null;
    this._announced = new Set();
    this.username = null;
    // wipe=1 also asks the browser to drop cache and origin storage; a plain
    // logout leaves those alone.
    try { await fetch('/api/logout?wipe=1', { method: 'POST' }); } catch { /* best effort */ }
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
