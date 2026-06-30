package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"deaddrop/internal/srp"
)

const (
	srpMaxBody       = 8192
	challengeTTL     = 2 * time.Minute
	lockoutThreshold = 5
	lockoutWindow    = 15 * time.Minute
)

/* ── store: SRP-aware methods ── */

func (s *store) getUser(username string) (user, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	return u, ok
}

func (s *store) exists(username string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.users[username]
	return ok
}

func validSalt(h string) bool { b, err := hex.DecodeString(h); return err == nil && len(b) == 16 }

func (s *store) registerSRP(username, saltHex, verifierHex string) error {
	if !usernameRe.MatchString(username) {
		return errors.New("username: 3–20 chars, letters/numbers/underscores")
	}
	if !validSalt(saltHex) {
		return errors.New("invalid salt")
	}
	if _, err := srp.DecodeVerifier(verifierHex); err != nil {
		return errors.New("invalid verifier")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[username]; exists {
		return errors.New("username already taken")
	}
	s.users[username] = user{Salt: saltHex, Verifier: verifierHex}
	return s.save()
}

// setVerifier installs a new SRP salt+verifier for an existing account (used for
// legacy→SRP upgrade and password change). Clears any legacy bcrypt hash.
func (s *store) setVerifier(username, saltHex, verifierHex string) error {
	if !validSalt(saltHex) {
		return errors.New("invalid salt")
	}
	if _, err := srp.DecodeVerifier(verifierHex); err != nil {
		return errors.New("invalid verifier")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; !ok {
		return errors.New("no such account")
	}
	s.users[username] = user{Salt: saltHex, Verifier: verifierHex}
	return s.save()
}

func (s *store) deleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; !ok {
		return errors.New("no such account")
	}
	delete(s.users, username)
	return s.save()
}

/* ── pending SRP challenges (one-time, short-lived) ── */

type pendingChallenge struct {
	username string
	A        *big.Int
	ch       *srp.Challenge
	real     bool
	expiry   time.Time
}

type challengeStore struct {
	mu     sync.Mutex
	m      map[string]*pendingChallenge
	secret []byte // for deterministic fake verifiers (anti-enumeration)
}

func newChallengeStore() *challengeStore {
	cs := &challengeStore{m: make(map[string]*pendingChallenge), secret: randomBytes(32)}
	go cs.reap()
	return cs
}

func (cs *challengeStore) put(p *pendingChallenge) string {
	tok := hex.EncodeToString(randomBytes(32))
	p.expiry = time.Now().Add(challengeTTL)
	cs.mu.Lock()
	cs.m[tok] = p
	cs.mu.Unlock()
	return tok
}

func (cs *challengeStore) take(tok string) (*pendingChallenge, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	p, ok := cs.m[tok]
	if !ok {
		return nil, false
	}
	delete(cs.m, tok) // one-time use
	if time.Now().After(p.expiry) {
		return nil, false
	}
	return p, true
}

func (cs *challengeStore) reap() {
	for range time.NewTicker(time.Minute).C {
		now := time.Now()
		cs.mu.Lock()
		for k, p := range cs.m {
			if now.After(p.expiry) {
				delete(cs.m, k)
			}
		}
		cs.mu.Unlock()
	}
}

// fakeSaltAndVerifier deterministically derives a plausible salt+verifier for an
// unknown username so the challenge step is indistinguishable from a real account.
func (cs *challengeStore) fakeSaltAndVerifier(username string) (string, *srp.Challenge) {
	salt := hmacSum(cs.secret, "salt:"+username)[:16]
	fakePw := hex.EncodeToString(hmacSum(cs.secret, "pw:"+username))
	v := srp.Verifier(username, fakePw, salt)
	ch, _ := srp.NewChallenge(v)
	return hex.EncodeToString(salt), ch
}

/* ── per-account login lockout ── */

type lockEntry struct {
	fails int
	until time.Time
}

type lockout struct {
	mu sync.Mutex
	m  map[string]*lockEntry
}

func newLockout() *lockout { return &lockout{m: make(map[string]*lockEntry)} }

func (l *lockout) allowed(username string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[username]
	if e == nil {
		return true, 0
	}
	if time.Now().Before(e.until) {
		return false, time.Until(e.until)
	}
	return true, 0
}

func (l *lockout) fail(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[username]
	if e == nil {
		e = &lockEntry{}
		l.m[username] = e
	}
	e.fails++
	if e.fails >= lockoutThreshold {
		e.until = time.Now().Add(lockoutWindow)
		e.fails = 0
	}
}

func (l *lockout) reset(username string) {
	l.mu.Lock()
	delete(l.m, username)
	l.mu.Unlock()
}

/* ── invite codes (file-backed, single-use) ── */

type invites struct {
	mu   sync.Mutex
	path string
}

func newInvites(dir string) *invites { return &invites{path: filepath.Join(dir, "invites.json")} }

// GenerateInviteForDir creates and stores a new invite code in dataDir. For the
// `deaddrop invite` CLI subcommand. The running server reads invites fresh on each
// registration, so a code minted here is immediately usable.
func GenerateInviteForDir(dataDir string) (string, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return "", err
	}
	return newInvites(dataDir).Generate()
}

func (iv *invites) load() ([]string, error) {
	data, err := os.ReadFile(iv.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var codes []string
	if err := json.Unmarshal(data, &codes); err != nil {
		return nil, err
	}
	return codes, nil
}

func (iv *invites) save(codes []string) error {
	data, _ := json.MarshalIndent(codes, "", "  ")
	tmp := iv.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, iv.path)
}

// consume removes a code if present, returning true on success.
func (iv *invites) consume(code string) bool {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return false
	}
	iv.mu.Lock()
	defer iv.mu.Unlock()
	codes, err := iv.load()
	if err != nil {
		return false
	}
	for i, c := range codes {
		if subtleEqual(strings.ToUpper(c), code) {
			codes = append(codes[:i], codes[i+1:]...)
			iv.save(codes)
			return true
		}
	}
	return false
}

// Generate creates, stores and returns a new single-use invite code.
func (iv *invites) Generate() (string, error) {
	code := newInviteCode()
	iv.mu.Lock()
	defer iv.mu.Unlock()
	codes, err := iv.load()
	if err != nil {
		return "", err
	}
	codes = append(codes, code)
	if err := iv.save(codes); err != nil {
		return "", err
	}
	return code, nil
}

func newInviteCode() string {
	const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789" // no I,L,O,0,1
	b := randomBytes(12)
	var sb strings.Builder
	sb.WriteString("DD-")
	for i, x := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(x)%len(alphabet)])
	}
	return sb.String()
}

/* ── HTTP handlers ── */

type srpRegisterReq struct {
	Username string `json:"username"`
	Salt     string `json:"salt"`
	Verifier string `json:"verifier"`
	Invite   string `json:"invite"`
}

func (h *Handler) SRPRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, srpMaxBody)
	var body srpRegisterReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if h.store.exists(body.Username) {
		jsonErr(w, "username already taken", http.StatusBadRequest)
		return
	}
	if !h.invites.consume(body.Invite) {
		jsonErr(w, "invalid or used invite code", http.StatusForbidden)
		return
	}
	if err := h.store.registerSRP(body.Username, body.Salt, body.Verifier); err != nil {
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if ok, wait := h.lockout.allowed(body.Username); !ok {
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
		// Legacy bcrypt account — client must fall back to password login (then upgrade).
		jsonOK(w, map[string]any{"legacy": true})
		return
	}

	var ch *srp.Challenge
	var saltHex string
	real := false
	if ok {
		v, derr := srp.DecodeVerifier(u.Verifier)
		if derr != nil {
			jsonErr(w, "account error", http.StatusInternalServerError)
			return
		}
		ch, _ = srp.NewChallenge(v)
		saltHex, real = u.Salt, true
	} else {
		// Unknown user: emit a deterministic fake challenge (anti-enumeration).
		saltHex, ch = h.challenges.fakeSaltAndVerifier(body.Username)
	}
	if ch == nil {
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}
	token := h.challenges.put(&pendingChallenge{username: body.Username, A: A, ch: ch, real: real})
	jsonOK(w, map[string]any{"token": token, "salt": saltHex, "B": ch.Bpub.Text(16)})
}

type srpAuthReq struct {
	Token string `json:"token"`
	M1    string `json:"M1"`
}

func (h *Handler) SRPAuthenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, srpMaxBody)
	var body srpAuthReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	p, ok := h.challenges.take(body.Token)
	if !ok {
		jsonErr(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if allowed, _ := h.lockout.allowed(p.username); !allowed {
		jsonErr(w, "too many attempts — try again later", http.StatusTooManyRequests)
		return
	}
	M1, err := hex.DecodeString(body.M1)
	if err != nil {
		jsonErr(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	M2, _, verr := p.ch.Verify(p.A, M1)
	if verr != nil || !p.real {
		h.lockout.fail(p.username)
		jsonErr(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	h.lockout.reset(p.username)
	h.setCookieSession(w, r, p.username)
	jsonOK(w, map[string]string{"username": p.username, "M2": hex.EncodeToString(M2)})
}

// SetVerifier installs a new salt+verifier for the logged-in user (legacy upgrade
// or password change). Auth-gated by the caller.
func (h *Handler) SetVerifier(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := h.currentUser(r)
	if username == "" {
		jsonErr(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, srpMaxBody)
	var body struct {
		Salt     string `json:"salt"`
		Verifier string `json:"verifier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.store.setVerifier(username, body.Salt, body.Verifier); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

// DeleteAccount removes the logged-in user's account and clears the session.
func (h *Handler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := h.currentUser(r)
	if username == "" {
		jsonErr(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	if err := h.store.deleteUser(username); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	if c, err := r.Cookie("dd_session"); err == nil {
		h.sess.delete(c.Value)
	}
	h.clearCookie(w, r)
	log.Printf("[auth] account deleted")
	jsonOK(w, map[string]string{"status": "ok"})
}

// GenerateInvite issues a new invite code. Protected by the ADMIN_TOKEN env secret.
func (h *Handler) GenerateInvite(w http.ResponseWriter, r *http.Request) {
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
	token, err := h.sess.create(username)
	if err != nil {
		jsonErr(w, "could not create session", http.StatusInternalServerError)
		return
	}
	h.setCookie(w, r, token)
	jsonOK(w, map[string]string{"username": username})
}

func (h *Handler) setCookieSession(w http.ResponseWriter, r *http.Request, username string) {
	token, err := h.sess.create(username)
	if err != nil {
		jsonErr(w, "could not create session", http.StatusInternalServerError)
		return
	}
	h.setCookie(w, r, token)
}

func (h *Handler) clearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: "dd_session", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: isSecureRequest(r), SameSite: http.SameSiteStrictMode,
	})
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func hmacSum(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := 0; i < len(a); i++ {
		d |= a[i] ^ b[i]
	}
	return d == 0
}
