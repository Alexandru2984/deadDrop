package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"deaddrop/internal/middleware"
	"deaddrop/internal/srp"
	"deaddrop/internal/strictjson"
)

const srpMaxBody = 8192

/* ── store: SRP-aware methods ── */

func (s *store) getUser(username string) (user, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	return u, ok
}

func validSalt(h string) bool { b, err := hex.DecodeString(h); return err == nil && len(b) == 16 }

// defaultKdf is what fresh clients use and what anti-enumeration dummies
// advertise; it must stay in sync with DEFAULT_KDF in web/js/srp.js.
const defaultKdf = "pbkdf2:600000"

const minimumWritableKdfIterations = 600_000

var kdfRe = regexp.MustCompile(`^pbkdf2:(\d{1,9})$`)

// validKdf accepts the empty string (legacy, no stretch) or a pbkdf2 label with a
// sane iteration count. The server never executes the KDF — bounds only stop a
// poisoned label from freezing some future client for minutes at login.
func validKdf(kdf string) bool {
	if kdf == "" {
		return true
	}
	n, ok := parseKdfIterations(kdf)
	return ok && n >= 10_000 && n <= 5_000_000
}

func parseKdfIterations(kdf string) (int, bool) {
	m := kdfRe.FindStringSubmatch(kdf)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

func validateSRPCredential(saltHex, verifierHex, kdf string) error {
	if !validSalt(saltHex) {
		return errors.New("invalid salt")
	}
	if _, err := srp.DecodeVerifier(verifierHex); err != nil {
		return errors.New("invalid verifier")
	}
	if !validKdf(kdf) {
		return errors.New("invalid kdf")
	}
	return nil
}

func validateWritableSRPCredential(saltHex, verifierHex, kdf string) error {
	if err := validateSRPCredential(saltHex, verifierHex, kdf); err != nil {
		return err
	}
	iterations, ok := parseKdfIterations(kdf)
	if !ok || iterations < minimumWritableKdfIterations {
		return errors.New("kdf is below the current security minimum")
	}
	return nil
}

func (s *store) registerSRP(username, saltHex, verifierHex, kdf string) error {
	if !usernameRe.MatchString(username) {
		return errors.New("username: 3–20 chars, letters/numbers/underscores")
	}
	if err := validateWritableSRPCredential(saltHex, verifierHex, kdf); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[username]; exists {
		return errors.New("username already taken")
	}
	if len(s.users) >= maxUsers {
		return errors.New("account limit reached")
	}
	next := cloneUsers(s.users)
	s.revision++
	next[username] = user{Salt: saltHex, Verifier: verifierHex, Kdf: kdf,
		primaryRevision: s.revision, duressRevision: s.revision}
	return s.commit(next)
}

// setVerifier installs a new SRP salt+verifier for an existing account (password
// change, or a KDF hardening upgrade). Keeps the duress credential.
func (s *store) setVerifier(username, saltHex, verifierHex, kdf string) error {
	if err := validateWritableSRPCredential(saltHex, verifierHex, kdf); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return errors.New("no such account")
	}
	next := cloneUsers(s.users)
	s.revision++
	next[username] = user{
		Salt: saltHex, Verifier: verifierHex, Kdf: kdf,
		DuressSalt: u.DuressSalt, DuressVerifier: u.DuressVerifier, DuressKdf: u.DuressKdf,
		primaryRevision: s.revision, duressRevision: s.revision,
	}
	return s.commit(next)
}

func (s *store) deleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; !ok {
		return errors.New("no such account")
	}
	next := cloneUsers(s.users)
	delete(next, username)
	return s.commit(next)
}

// setDuress sets (or clears, when salt/verifier are empty) the duress credential
// for an existing account.
func (s *store) setDuress(username, saltHex, verifierHex, kdf string) error {
	if err := validateDuressUpdate(saltHex, verifierHex, kdf); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return errors.New("no such account")
	}
	u.DuressSalt, u.DuressVerifier, u.DuressKdf = saltHex, verifierHex, kdf
	s.revision++
	u.duressRevision = s.revision
	next := cloneUsers(s.users)
	next[username] = u
	return s.commit(next)
}

/* ── HTTP handlers ── */

type srpRegisterReq struct {
	Username string `json:"username"`
	Salt     string `json:"salt"`
	Verifier string `json:"verifier"`
	Kdf      string `json:"kdf"`
	Invite   string `json:"invite"`
}

func (h *Handler) SRPRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, srpMaxBody)
	var body srpRegisterReq
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if !usernameRe.MatchString(body.Username) {
		jsonErr(w, "username: 3–20 chars, letters/numbers/underscores", http.StatusBadRequest)
		return
	}
	if err := validateWritableSRPCredential(body.Salt, body.Verifier, body.Kdf); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Registration is invite-only unless OPEN_REGISTRATION=1 is set (then anyone can
	// register and the invite field is ignored).
	consumed := false
	if !OpenRegistration() {
		var err error
		consumed, err = h.invites.consume(body.Invite)
		if err != nil {
			log.Printf("[auth] invite store error: %v", err)
			jsonErr(w, "registration temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if !consumed {
			jsonErr(w, "invalid or used invite code", http.StatusForbidden)
			return
		}
	}
	h.accountMu.Lock()
	defer h.accountMu.Unlock()
	if err := h.store.registerSRP(body.Username, body.Salt, body.Verifier, body.Kdf); err != nil {
		if consumed {
			if restoreErr := h.invites.restore(body.Invite); restoreErr != nil {
				log.Printf("[auth] could not restore invite after failed registration: %v", restoreErr)
				jsonErr(w, "registration temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("[auth] new SRP account registered")
	h.startSession(w, r, body.Username)
}

type srpChallengeReq struct {
	Username string `json:"username"`
	A        string `json:"A"`
}

func (h *Handler) SRPChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, srpMaxBody)
	var body srpChallengeReq
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if !usernameRe.MatchString(body.Username) {
		jsonErr(w, "invalid parameter", http.StatusBadRequest)
		return
	}
	if ok, wait := h.lockout.admitChallenge(body.Username, middleware.ClientTag(r)); !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())))
		jsonErr(w, "too many attempts — try again later", http.StatusTooManyRequests)
		return
	}
	A, err := srp.DecodePublic(body.A)
	if err != nil {
		jsonErr(w, "invalid parameter", http.StatusBadRequest)
		return
	}

	u, ok := h.store.getUser(body.Username)
	if ok && !u.isSRP() {
		// A stored credential with no verifier cannot answer a proof. Treat it as
		// unknown so it receives the same dummy challenge — never a distinct reply
		// that would confirm the handle exists.
		ok = false
	}

	// Build the real challenge (real verifier, or an anti-enumeration dummy).
	// Dummies advertise the current default KDF — the same thing a fresh real
	// account would — so the response shape and timing stay indistinguishable.
	var ch *srp.Challenge
	var saltHex string
	kdf := defaultKdf
	real := false
	if ok {
		v, derr := srp.DecodeVerifier(u.Verifier)
		if derr != nil {
			jsonErr(w, "account error", http.StatusInternalServerError)
			return
		}
		ch, err = srp.NewChallenge(v)
		if err != nil {
			jsonErr(w, "account error", http.StatusInternalServerError)
			return
		}
		saltHex, kdf, real = u.Salt, u.Kdf, true
	} else {
		saltHex, ch, err = h.challenges.fakeSaltAndVerifier("real", body.Username)
		if err != nil {
			jsonErr(w, "server error", http.StatusInternalServerError)
			return
		}
	}

	// Always also emit a SECOND (duress) challenge — a real one if the account has a
	// duress credential, otherwise a deterministic dummy. Because the response shape
	// never changes, an observer cannot tell whether a duress password is configured.
	var chD *srp.Challenge
	var saltD string
	kdfD := defaultKdf
	realDuress := false
	if ok && u.hasDuress() {
		if vd, derr := srp.DecodeVerifier(u.DuressVerifier); derr == nil {
			chD, err = srp.NewChallenge(vd)
			if err != nil {
				jsonErr(w, "account error", http.StatusInternalServerError)
				return
			}
			saltD, kdfD, realDuress = u.DuressSalt, u.DuressKdf, true
		}
	}
	if chD == nil {
		saltD, chD, err = h.challenges.fakeSaltAndVerifier("duress", body.Username)
		if err != nil {
			jsonErr(w, "server error", http.StatusInternalServerError)
			return
		}
	}
	if ch == nil || chD == nil {
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	token, err := h.challenges.put(&pendingChallenge{
		username: body.Username, A: A,
		ch: ch, real: real, chDuress: chD, realDuress: realDuress,
		source:          middleware.ClientTag(r),
		primaryRevision: u.primaryRevision, duressRevision: u.duressRevision,
	})
	if err != nil {
		jsonErr(w, "authentication temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	jsonOK(w, map[string]any{
		"token": token,
		"salt":  saltHex, "B": ch.Bpub.Text(16), "kdf": kdf,
		"salt2": saltD, "B2": chD.Bpub.Text(16), "kdf2": kdfD,
	})
}

type srpAuthReq struct {
	Token string `json:"token"`
	M1    string `json:"M1"`
	M1d   string `json:"M1d"`
}

func (h *Handler) SRPAuthenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, srpMaxBody)
	var body srpAuthReq
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	p, ok := h.challenges.take(body.Token)
	if !ok {
		jsonErr(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	ip := middleware.ClientTag(r)
	if allowed, _ := h.lockout.allowed(p.username, ip); !allowed {
		jsonErr(w, "too many attempts — try again later", http.StatusTooManyRequests)
		return
	}
	primaryOK, duressOK, M2, M2d := verifyChallengeProofs(p, body.M1, body.M1d)
	// The owner may have changed/deleted the credential while this proof was
	// being computed, or after its challenge was taken out of the table. Check
	// its revision and issue the session atomically with account actions.
	h.accountMu.Lock()
	defer h.accountMu.Unlock()
	primaryOK, duressOK = h.currentProofs(p, primaryOK, duressOK)

	if primaryOK {
		if err := h.setCookieSession(w, r, p.username, false); err != nil {
			jsonErr(w, "could not create session", http.StatusInternalServerError)
			return
		}
		h.lockout.reset(p.username, ip)
		jsonOK(w, map[string]any{"username": p.username, "M2": hex.EncodeToString(M2), "features": sessionFeatures(false)})
		return
	}
	if duressOK {
		if err := h.setCookieSession(w, r, p.username, true); err != nil {
			jsonErr(w, "could not create session", http.StatusInternalServerError)
			return
		}
		h.lockout.reset(p.username, ip)
		jsonOK(w, map[string]any{"username": p.username, "M2": hex.EncodeToString(M2d), "features": sessionFeatures(true)})
		return
	}
	h.lockout.fail(p.username, ip)
	jsonErr(w, "invalid credentials", http.StatusUnauthorized)
}

// requireLiveSession is the preamble every credential-changing endpoint shares:
// POST only, a session cookie, and a session that is still live. It writes the
// error response itself and reports whether the caller should continue.
//
// The three handlers below had these lines copied between them. The risk is not
// the repetition: it is that a check added to one and missed in another looks
// like nothing at all in a diff.
//
// The fresh-proof check is deliberately *not* folded in. Each handler calls it
// on its own line, where it can be seen.
func (h *Handler) requireLiveSession(w http.ResponseWriter, r *http.Request) (username string, duress bool, cookie *http.Cookie, ok bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return "", false, nil, false
	}
	c, err := sessionCookie(r)
	if err != nil {
		jsonErr(w, "not authenticated", http.StatusUnauthorized)
		return "", false, nil, false
	}
	name, isDuress, live := h.sess.getMeta(c.Value)
	if !live {
		jsonErr(w, "not authenticated", http.StatusUnauthorized)
		return "", false, nil, false
	}
	if isGuestPrincipal(name) {
		// A guest has no account to change. Refused here, by name, rather
		// than left to fail further down for want of a stored credential.
		jsonErr(w, "not available to guests", http.StatusForbidden)
		return "", false, nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, srpMaxBody)
	return name, isDuress, c, true
}

// SetVerifier installs a new salt+verifier for the logged-in user. It requires a
// fresh SRP proof of the credential the session was opened with, so possession of
// a session cookie is not by itself enough to rekey the account.
//
// In a duress (decoy) session it updates the DURESS
// credential instead: "change password" behaves exactly as a coercer would expect
// (the password they know keeps working, with its new value), while the real
// verifier — derived from a password the decoy user never typed — stays untouched
// and the real owner is never locked out.
func (h *Handler) SetVerifier(w http.ResponseWriter, r *http.Request) {
	username, duress, c, ok := h.requireLiveSession(w, r)
	if !ok {
		return
	}
	var body struct {
		Salt     string `json:"salt"`
		Verifier string `json:"verifier"`
		Kdf      string `json:"kdf"`
		Token    string `json:"token"`
		M1       string `json:"M1"`
		M1d      string `json:"M1d"`
	}
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.lockAccountAction(w, r, username, duress) {
		return
	}
	defer h.accountMu.Unlock()
	if !h.requireFreshProof(r, username, duress, body.Token, body.M1, body.M1d) {
		jsonErr(w, "re-authentication required", http.StatusUnauthorized)
		return
	}
	if duress {
		if err := h.store.setDuress(username, body.Salt, body.Verifier, body.Kdf); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.sess.deleteUserKindExcept(username, true, c.Value)
		jsonOK(w, map[string]string{"status": "ok"})
		return
	}
	if err := h.store.setVerifier(username, body.Salt, body.Verifier, body.Kdf); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	// A primary password change is the account owner's revocation event: close
	// every other session, primary and decoy alike, and rotate this browser's own
	// token so the pre-change value stops being an authenticator too.
	h.sess.deleteUser(username)
	if err := h.setCookieSession(w, r, username, false); err != nil {
		jsonErr(w, "could not refresh session", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

// SetDuress sets or clears the duress credential for the logged-in user, after a
// fresh SRP proof of the credential this session was opened with. The
// browser computes (salt, verifier) from the duress password — it never reaches
// the server. A duress session must not be allowed to change the duress credential.
func (h *Handler) SetDuress(w http.ResponseWriter, r *http.Request) {
	username, duress, _, ok := h.requireLiveSession(w, r)
	if !ok {
		return
	}
	var body struct {
		Salt     string `json:"salt"`
		Verifier string `json:"verifier"`
		Kdf      string `json:"kdf"`
		Token    string `json:"token"`
		M1       string `json:"M1"`
		M1d      string `json:"M1d"`
	}
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.lockAccountAction(w, r, username, duress) {
		return
	}
	defer h.accountMu.Unlock()
	// The proof is checked before the decoy branch below, and against whichever
	// credential opened this session, so a decoy still answers 200 for its own
	// password and never reveals which branch it took.
	if !h.requireFreshProof(r, username, duress, body.Token, body.M1, body.M1d) {
		jsonErr(w, "re-authentication required", http.StatusUnauthorized)
		return
	}
	if err := validateDuressUpdate(body.Salt, body.Verifier, body.Kdf); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	if duress {
		// A decoy session must not modify duress settings — but answering 403 would
		// announce "this is the decoy". Validate and report success without writing.
		jsonOK(w, map[string]string{"status": "ok"})
		return
	}
	if err := h.store.setDuress(username, body.Salt, body.Verifier, body.Kdf); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.sess.deleteUserKind(username, true)
	jsonOK(w, map[string]string{"status": "ok"})
}

// DeleteAccount requires a fresh SRP proof and removes an account only from a
// primary session. A duress session
// preserves the real account but consumes the duress credential, so the password
// the coerced user surrendered genuinely stops working: a coercer who watches the
// deletion and then retries that password must not find the account still alive.
func (h *Handler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	username, duress, _, ok := h.requireLiveSession(w, r)
	if !ok {
		return
	}
	var body struct {
		Token string `json:"token"`
		M1    string `json:"M1"`
		M1d   string `json:"M1d"`
	}
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.lockAccountAction(w, r, username, duress) {
		return
	}
	defer h.accountMu.Unlock()
	// Destroying an account is irreversible, so a borrowed session must not be
	// able to do it either. A decoy proves its own credential and still gets the
	// deletion theatre below.
	if !h.requireFreshProof(r, username, duress, body.Token, body.M1, body.M1d) {
		jsonErr(w, "re-authentication required", http.StatusUnauthorized)
		return
	}
	if duress {
		// A write failure here must not change the response. Reporting an error
		// where a primary session reports success would itself expose the decoy,
		// which is a worse outcome than a duress password that outlives the wipe.
		if err := h.store.setDuress(username, "", "", ""); err != nil {
			log.Printf("[auth] could not clear duress credential on decoy delete: %v", err)
		}
		h.sess.deleteUserKind(username, true)
	} else {
		if err := h.store.deleteUser(username); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.sess.deleteUser(username)
		log.Printf("[auth] account deleted")
	}
	h.clearCookie(w, r)
	jsonOK(w, map[string]string{"status": "ok"})
}

// SignOutOthers ends every other session of the account — a browser left
// signed in somewhere else, a phone that was lost — keeping this one. Like the
// other account actions it wants a fresh proof of the credential this session
// was opened with, so a stolen cookie cannot use it to throw the owner out.
//
// From the real account it ends the decoy's sessions as well, as a password
// change does. From a decoy session it ends only other decoy sessions: a
// coercer can neither reach the real account's sessions nor tell from the
// answer which kind of session asked — both answer with how many they ended,
// counted among the sessions that kind can see.
//
// Live connections go with their sessions: the signaling pumps re-check the
// session and close a socket whose session is gone.
func (h *Handler) SignOutOthers(w http.ResponseWriter, r *http.Request) {
	username, duress, c, ok := h.requireLiveSession(w, r)
	if !ok {
		return
	}
	var body struct {
		Token string `json:"token"`
		M1    string `json:"M1"`
		M1d   string `json:"M1d"`
	}
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.lockAccountAction(w, r, username, duress) {
		return
	}
	defer h.accountMu.Unlock()
	if !h.requireFreshProof(r, username, duress, body.Token, body.M1, body.M1d) {
		jsonErr(w, "re-authentication required", http.StatusUnauthorized)
		return
	}
	var ended int
	if duress {
		ended = h.sess.deleteUserKindExcept(username, true, c.Value)
	} else {
		ended = h.sess.deleteUserExcept(username, c.Value)
	}
	jsonOK(w, map[string]any{"status": "ok", "ended": ended})
}

// GenerateInvite issues a new invite code. Protected by the ADMIN_TOKEN env secret.
func (h *Handler) GenerateInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	admin := strings.TrimSpace(os.Getenv("ADMIN_TOKEN"))
	if admin == "" || !subtleEqual(r.Header.Get("X-Admin-Token"), admin) {
		jsonErr(w, "forbidden", http.StatusForbidden)
		return
	}
	code, err := h.invites.Generate()
	if err != nil {
		jsonErr(w, "could not generate invite", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"invite": code})
}

/* ── helpers ── */

func (h *Handler) startSession(w http.ResponseWriter, r *http.Request, username string) {
	token, err := h.sess.create(username, false)
	if err != nil {
		jsonErr(w, "could not create session", http.StatusInternalServerError)
		return
	}
	h.setCookie(w, r, token)
	jsonOK(w, map[string]string{"username": username})
}

func (h *Handler) setCookieSession(w http.ResponseWriter, r *http.Request, username string, duress bool) error {
	token, err := h.sess.create(username, duress)
	if err != nil {
		return err
	}
	h.setCookie(w, r, token)
	return nil
}

func (h *Handler) clearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- flags are explicit; Secure is false only for local HTTP development
		Name: sessionCookieName(r), Value: "", Path: "/", MaxAge: -1,
		Expires: time.Unix(1, 0), HttpOnly: true,
		Secure: middleware.IsSecureRequest(r), SameSite: http.SameSiteStrictMode,
	})
}

// verifyChallengeProofs always executes both SRP verifications before deciding
// which credential won. Invalid encodings are normalized to a full-length zero
// proof, keeping the expensive path consistent and avoiding a primary-vs-duress
// timing oracle.
func verifyChallengeProofs(p *pendingChallenge, m1Hex, m1dHex string) (primaryOK, duressOK bool, m2, m2d []byte) {
	M1, primaryEncodingOK := decodeSRPProof(m1Hex)
	M1d, duressEncodingOK := decodeSRPProof(m1dHex)
	m2, _, primaryErr := p.ch.Verify(p.A, M1)
	m2d, _, duressErr := p.chDuress.Verify(p.A, M1d)
	encodingOK := primaryEncodingOK && duressEncodingOK
	primaryOK = encodingOK && primaryErr == nil && p.real
	duressOK = encodingOK && duressErr == nil && p.realDuress
	return primaryOK, duressOK, m2, m2d
}

// requireFreshProof re-authenticates the caller of a credential-changing
// endpoint. A session cookie alone must not be enough to rekey an account:
// otherwise a borrowed session — an unlocked browser, a hostile extension — is a
// permanent takeover. The proof has to match the session's own credential, so a
// decoy session can only re-prove the duress password.
func (h *Handler) requireFreshProof(r *http.Request, username string, duress bool, token, m1, m1d string) bool {
	p, ok := h.challenges.take(token)
	if !ok || p.username != username {
		return false
	}
	ip := middleware.ClientTag(r)
	if allowed, _ := h.lockout.allowed(username, ip); !allowed {
		return false
	}
	primaryOK, duressOK, _, _ := verifyChallengeProofs(p, m1, m1d)
	primaryOK, duressOK = h.currentProofs(p, primaryOK, duressOK)
	proved := primaryOK
	if duress {
		proved = duressOK
	}
	if !proved {
		h.lockout.fail(username, ip)
		return false
	}
	h.lockout.reset(username, ip)
	return true
}

// currentProofs must be called with accountMu held through the authorized
// action. Revisions are independent: a decoy change cannot invalidate a real
// user's pending login, while a primary password change revokes both kinds.
func (h *Handler) currentProofs(p *pendingChallenge, primaryOK, duressOK bool) (bool, bool) {
	u, exists := h.store.getUser(p.username)
	return primaryOK && exists && p.primaryRevision != 0 && p.primaryRevision == u.primaryRevision,
		duressOK && exists && p.duressRevision != 0 && p.duressRevision == u.duressRevision
}

// lockAccountAction re-checks the cookie after reading the body and waiting
// for other account actions. A session valid at request arrival may have been
// revoked meanwhile. On success the caller must defer accountMu.Unlock().
func (h *Handler) lockAccountAction(w http.ResponseWriter, r *http.Request, username string, duress bool) bool {
	h.accountMu.Lock()
	c, err := sessionCookie(r)
	if err == nil {
		name, kind, live := h.sess.getMeta(c.Value)
		if live && name == username && kind == duress {
			return true
		}
	}
	h.accountMu.Unlock()
	jsonErr(w, "not authenticated", http.StatusUnauthorized)
	return false
}

func decodeSRPProof(encoded string) ([]byte, bool) {
	proof := make([]byte, sha256.Size)
	if len(encoded) != sha256.Size*2 {
		return proof, false
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size {
		return proof, false
	}
	return decoded, true
}

func validateDuressUpdate(salt, verifier, kdf string) error {
	if salt == "" && verifier == "" && kdf == "" {
		return nil
	}
	return validateWritableSRPCredential(salt, verifier, kdf)
}

func hmacSum(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}
