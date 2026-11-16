/**
 * Dead Drop — signing in, accounts and settings. Part of the app's one class, in a file of its
 * own: app.js adds these methods to it before the instance is made, and
 * they use `this` exactly as if written there.
 */

import { register as srpRegister, ClientLogin } from './srp.js';
import { t } from './i18n.js';
import { passwordProblem, passphrase } from './util.js';
import { firstAnswer } from './boot.js';
import { ROOM_CODE_RE, serverMessage, needsKdfUpgrade, signOutOwed, setSignOutOwed } from './app-shared.js';

export class AuthMethods {
  /* ── Auth ── */

  // Async work belongs to the current local session. Fetches can be aborted;
  // password derivation and storage must check the same scope before continuing.
  _workScope() {
    const signal = this._workController.signal;
    const current = () => !signal.aborted && !this._wiping;
    return { signal, current, check: () => {
      if (!current()) throw new DOMException('Operation cancelled', 'AbortError');
    } };
  }

  async _checkAuth() {
    const work = this._workScope();
    if (signOutOwed()) {
      // The answer asked for on load came from the session being ended.
      firstAnswer();
      this._showPage('auth');
      const done = await this._finishSignOut();
      if (work.current() && !done) this._showSignOutOwed();
      return;
    }
    try {
      const res = await (firstAnswer() ?? fetch('/api/me', { signal: work.signal }));
      if (!work.current()) return;
      if (res.ok) {
        const data = await res.json();
        if (!work.current()) return;
        if (data.guest === true) {
          // A link to some other room: being a guest of this one is no way
          // into that one. Offer what the link offers — a new pass replaces
          // this guest session, an ordinary invitation asks for an account —
          // rather than drop the visitor into the room they were not sent to.
          const elsewhere = this._pendingJoin && this._pendingJoin !== data.room;
          if (!elsewhere && ROOM_CODE_RE.test(data.room)) this._becomeGuest(data.room);
          else this._showPage('auth');
          return;
        }
        // Signed in to an account: the invitation is joined with it, and the
        // guest pass is left unused for whoever else it may have been sent to.
        this._pendingGuest = null;
        this.username = data.username;
        // A returning visitor lands here rather than in _afterAuth, so without
        // this the identity stays unloaded and every saved contact is silently
        // forgotten on reload — the exact case the feature exists for.
        await this._restoreIdentity().catch(() => {});
        if (!work.current()) return;
        this._showPage('landing');
        // Nor did a reload arm the idle lock: it waited for the first key or
        // touch, so a tab reloaded and left alone was never wiped.
        this._armIdleLock();
      } else {
        this._showPage('auth');
        const data = await res.json().catch(() => ({}));
        if (!work.current()) return;
        if (data.error === 'signed out') this._showAuthError(t('auth.signedOutElsewhere'));
      }
    } catch {
      if (work.current()) this._showPage('auth');
    }
  }

  async _login() {
    if (this._wiping) return;
    const work = this._workScope();
    const username = this.el.authUser.value.trim();
    const password = this.el.authPass.value;
    if (!username || !password) return;

    this._hideAuthError();
    this._setAuthBusy(true);
    try {
      // A sign-out still owed would reach the server after this and end the
      // session it is about to open.
      if (!await this._finishSignOut()) {
        if (work.current()) this._showSignOutOwed();
        return;
      }
      if (!work.current()) return;
      const client = new ClientLogin(username, password);
      const ch = await this._postJSON('/api/srp/challenge', { username, A: client.start().A }, work);
      if (!ch.ok) { this._showAuthError(serverMessage(ch.data.error, 'srv.badLogin')); return; }

      // The challenge advertises each credential's password-stretch KDF.
      const { M1 } = await client.finish(ch.data.salt, ch.data.B, ch.data.kdf);
      work.check();
      // Second proof against the duress challenge, reusing the same ephemeral `a`.
      // Exactly one of the two proofs matches server-side (real vs duress password).
      let clientD = null, M1d = '';
      if (ch.data.salt2 && ch.data.B2) {
        clientD = new ClientLogin(username, password, client.a);
        clientD.start();
        M1d = (await clientD.finish(ch.data.salt2, ch.data.B2, ch.data.kdf2)).M1;
      }
      const auth = await this._postJSON('/api/srp/authenticate', { token: ch.data.token, M1, M1d }, work);
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
            { ...up, ...(await this._reauthProof(username, password, work)) }, work);
        } catch { /* best-effort; login already succeeded */ }
      }
      if (work.current()) this._afterAuth();
    } catch {
      if (work.current()) this._showAuthError(t('err.connection'));
    } finally {
      if (work.current()) this._setAuthBusy(false);
    }
  }

  /** Prove the current password again for a credential change. A session cookie
   *  alone must not be able to rekey the account, so the server re-runs the SRP
   *  verification against whichever credential this session was opened with. */
  async _reauthProof(username, password, work = this._workScope()) {
    work.check();
    const client = new ClientLogin(username, password);
    const ch = await this._postJSON('/api/srp/challenge', { username, A: client.start().A }, work);
    if (!ch.ok) throw new Error('re-authentication challenge failed');
    const { M1 } = await client.finish(ch.data.salt, ch.data.B, ch.data.kdf);
    work.check();
    let M1d = '';
    if (ch.data.salt2 && ch.data.B2) {
      const clientD = new ClientLogin(username, password, client.a);
      clientD.start();
      M1d = (await clientD.finish(ch.data.salt2, ch.data.B2, ch.data.kdf2)).M1;
    }
    work.check();
    return { token: ch.data.token, M1, M1d };
  }

  async _register() {
    if (this._wiping) return;
    const work = this._workScope();
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
      if (!await this._finishSignOut()) {
        if (work.current()) this._showSignOutOwed();
        return;
      }
      if (!work.current()) return;
      const { salt, verifier, kdf } = await srpRegister(username, password);
      const res = await this._postJSON('/api/srp/register', { username, salt, verifier, kdf, invite }, work);
      if (res.ok) {
        this.username = res.data.username;
        this._afterAuth();
      } else {
        this._showAuthError(serverMessage(res.data.error, 'srv.registerFailed'));
      }
    } catch {
      if (work.current()) this._showAuthError(t('err.connection'));
    } finally {
      if (work.current()) this._setAuthBusy(false);
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
    // Signed in to an account: whatever guest pass or guest session this
    // browser had is beside the point now.
    this.guest = false;
    this._guestRoom = null;
    this._pendingGuest = null;
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
    await this._accountBusy(this.el.changePassBtn, say, async (work) => {
      let proof;
      try {
        proof = await this._reauthProof(this.username, current, work);
      } catch {
        if (work.current()) say(t('account.wrongCurrent'));
        return;
      }
      const credential = await srpRegister(this.username, next);
      const res = await this._postJSON('/api/account/verifier', { ...credential, ...proof }, work);
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
    await this._accountBusy(this.el.setDuressBtn, say, async (work) => {
      let proof;
      try {
        proof = await this._reauthProof(this.username, current, work);
      } catch {
        if (work.current()) say(t('account.wrongCurrent'));
        return;
      }
      const { salt, verifier, kdf } = await srpRegister(this.username, pw);
      const res = await this._postJSON('/api/account/duress', { salt, verifier, kdf, ...proof }, work);
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
    await this._accountBusy(this.el.delAccountBtn, say, async (work) => {
      let proof;
      try {
        proof = await this._reauthProof(this.username, current, work);
      } catch {
        if (work.current()) say(t('account.wrongCurrent'));
        return;
      }
      const res = await this._postJSON('/api/account/delete', proof, work);
      if (res.status === 401) { say(t('account.wrongCurrent')); return; }
      if (!res.ok) { say(serverMessage(res.data.error, 'err.connection')); return; }
      this.el.currentPass.value = '';
      this._cleanup();
      location.replace(location.origin + '/');
    });
  }

  /**
   * End every other session of this account. It wants the current password,
   * like every action here, so a stolen cookie cannot use it to throw the
   * owner out; the server closes those sessions' live connections too.
   */
  async _signOutOthers() {
    const current = this.el.currentPass.value;
    const say = (text, ok) => this._accountMsg(this.el.sessionsMsg, text, ok);
    if (!current) {
      this.el.currentPass.focus();
      say(t('account.needCurrent'));
      return;
    }
    await this._accountBusy(this.el.signOutOthersBtn, say, async (work) => {
      let proof;
      try {
        proof = await this._reauthProof(this.username, current, work);
      } catch {
        if (work.current()) say(t('account.wrongCurrent'));
        return;
      }
      const res = await this._postJSON('/api/account/signout-others', proof, work);
      if (res.status === 401) { say(t('account.wrongCurrent')); return; }
      if (!res.ok) { say(serverMessage(res.data.error, 'err.connection')); return; }
      this.el.currentPass.value = '';
      const ended = Number(res.data.ended) || 0;
      say(ended ? t('sessions.ended').replace('{n}', String(ended)) : t('sessions.none'), true);
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
    const work = this._workScope();
    if (!work.current() || btn.disabled) return;
    btn.disabled = true;
    try {
      await action(work);
    } catch {
      if (work.current()) say(t('err.connection'));
    } finally {
      if (work.current()) btn.disabled = false;
    }
  }

  async _postJSON(path, body, work = this._workScope()) {
    work.check();
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: work.signal,
    });
    let data = {};
    try { data = await res.json(); } catch { /* empty body */ }
    work.check();
    return { ok: res.ok, status: res.status, data };
  }

  /**
   * Join the room a guest link points to, with no account.
   *
   * The pass in the link is spent here, once, for a session that can enter
   * that one room and do nothing else. It proves nothing about who holds it,
   * which is why it changes nothing about what comes next: the safety code is
   * still compared before a word can be exchanged.
   */
  async _joinAsGuest() {
    if (this._wiping || !this._pendingGuest) return;
    const work = this._workScope();
    this._hideAuthError();
    this._setAuthBusy(true);
    try {
      if (!await this._finishSignOut()) {
        if (work.current()) this._showSignOutOwed();
        return;
      }
      if (!work.current()) return;
      const res = await this._postJSON('/api/guest/redeem', { token: this._pendingGuest }, work);
      if (res.ok && res.data.guest === true && ROOM_CODE_RE.test(res.data.room)) {
        this._pendingGuest = null;
        this._becomeGuest(res.data.room);
        return;
      }
      // Spent, expired or withdrawn: it will not work on a second try either.
      if (res.status === 403) {
        this._pendingGuest = null;
        this.el.authGuest.classList.add('hidden');
        this.el.authInvited.classList.toggle('hidden', !this._pendingJoin);
      }
      this._showAuthError(serverMessage(res.data.error, 'guest.failed'));
    } catch {
      if (work.current()) this._showAuthError(t('err.connection'));
    } finally {
      if (work.current()) this._setAuthBusy(false);
    }
  }

  _becomeGuest(room) {
    this.guest = true;
    this._guestRoom = room;
    this._pendingGuest = null;
    this._pendingJoin = room;
    this.username = t('guest.name');
    // "No account and no name" has to include the key this browser may hold
    // for saved contacts. Presenting it would let the host recognise the
    // guest as someone it has met before — a name by another route. It stays
    // on disk, untouched, for the account that turned it on.
    this._identityGeneration = (this._identityGeneration || 0) + 1;
    this.identity = null;
    this.el.authUser.value = '';
    this.el.authPass.value = '';
    this.el.authInvite.value = '';
    this._showPage('landing');
    this._armIdleLock();
  }

  _setAuthBusy(busy) {
    this.el.loginBtn.disabled = busy;
    this.el.registerBtn.disabled = busy;
    this.el.guestJoinBtn.disabled = busy;
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
   *
   * Unless the account's owner ended this session — a password change or
   * "sign out everywhere else" from another browser. That is someone taking
   * this browser's access away, a lost phone's most likely: the
   * conversations it still has open end with it.
   */
  async _recheckSession() {
    const work = this._workScope();
    if (!work.current()) return;
    let res;
    try { res = await fetch('/api/me', { signal: work.signal }); } catch { return; }
    if (!work.current()) return;
    if (res.status !== 401) return;
    const data = await res.json().catch(() => ({}));
    if (!work.current()) return;
    if (data.error === 'signed out') {
      this._disarmIdleLock();
      this._cleanup();
      this.username = null;
      this._showPage('auth');
      this._showAuthError(t('auth.signedOutElsewhere'));
      return;
    }
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
    // This side is signed out now, whatever the network does next. It used to
    // wait for the server first: offline, the request threw, the page stayed
    // where it was, and a reload signed the next person at the keyboard back in.
    this.username = null;
    this.guest = false;
    this._guestRoom = null;
    this.el.authUser.value = '';
    this.el.authPass.value = '';
    setSignOutOwed('1');
    this._showPage('auth');
    if (!await this._finishSignOut()) this._showSignOutOwed();
  }

  /** Ask the server to end this browser's session. Resolves true once it has
   *  answered; one request at a time, so a retry and a sign-in cannot cross. */
  _finishSignOut() {
    if (this._signOutAttempt) return this._signOutAttempt;
    const attempt = (async () => {
      const owed = signOutOwed();
      if (!owed) return true;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      try {
        const res = await fetch(owed === 'wipe' ? '/api/logout?wipe=1' : '/api/logout',
          { method: 'POST', signal: controller.signal, keepalive: true });
        if (!res.ok) return false;
        setSignOutOwed(null);
        clearTimeout(this._signOutTimer);
        if (this._signOutNotice) this._hideAuthError();
        return true;
      } catch {
        return false;
      } finally {
        clearTimeout(timer);
      }
    })();
    this._signOutAttempt = attempt;
    attempt.finally(() => { if (this._signOutAttempt === attempt) this._signOutAttempt = null; });
    return attempt;
  }

  /** Say that the server still holds the session, and keep trying to end it. */
  _showSignOutOwed() {
    this._showAuthError(t('auth.signOutOwed'));
    this._signOutNotice = true;
    this._retrySignOut(5000);
  }

  _retrySignOut(delay) {
    clearTimeout(this._signOutTimer);
    if (!signOutOwed()) return;
    this._signOutTimer = setTimeout(async () => {
      if (!await this._finishSignOut()) this._retrySignOut(Math.min(delay * 2, 60_000));
    }, delay);
  }

  _showAuthError(msg) {
    this._signOutNotice = false;
    this.el.authError.textContent = msg;
    this.el.authError.classList.remove('hidden');
  }

  _hideAuthError() {
    this._signOutNotice = false;
    this.el.authError.classList.add('hidden');
  }
}
