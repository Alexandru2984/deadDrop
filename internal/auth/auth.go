package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"deaddrop/internal/middleware"
	"deaddrop/internal/strictjson"

	"golang.org/x/crypto/bcrypt"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)

/* ── User Store (file-backed) ── */

// user holds either a legacy bcrypt hash (kept so existing accounts are never
// locked out) or an SRP verifier+salt. SRP login sends proofs rather than the
// password. New accounts are SRP-only; legacy accounts send their password once
// to the legacy endpoint and auto-upgrade on that login.
type user struct {
	Hash     string `json:"hash,omitempty"`     // legacy bcrypt over SHA-256(password)
	Salt     string `json:"salt,omitempty"`     // SRP salt (hex)
	Verifier string `json:"verifier,omitempty"` // SRP verifier v = g^x mod N (hex)
	// Kdf names the client-side password stretch applied before the SRP x
	// derivation (e.g. "pbkdf2:600000"). Empty = pre-stretch account (bare RFC 5054
	// SHA-256); those upgrade transparently on their next login. The server never
	// runs the KDF — it only stores the label and echoes it in the login challenge.
	Kdf string `json:"kdf,omitempty"`
	// Optional duress credential: logging in with it succeeds but flags the session
	// as duress (decoy), so a coerced user can surrender a working password without
	// revealing the real one.
	DuressSalt     string `json:"duressSalt,omitempty"`
	DuressVerifier string `json:"duressVerifier,omitempty"`
	DuressKdf      string `json:"duressKdf,omitempty"`
}

func (u user) isSRP() bool     { return u.Verifier != "" }
func (u user) hasDuress() bool { return u.DuressVerifier != "" }

type store struct {
	mu        sync.RWMutex
	users     map[string]user
	path      string
	dummyHash []byte // valid bcrypt hash for constant-time comparison on unknown users
}

const (
	maxUsers        = 10_000
	maxUsersFileLen = 32 << 20
)

const legacyBcryptCost = 12

func newStore(dir string) (*store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("secure auth data directory: %w", err)
	}
	// Generate a valid bcrypt hash at startup for constant-time dummy comparison.
	// This prevents user enumeration via timing — the work is identical whether
	// the user exists or not. Must be the same cost factor as real hashes.
	dummy, err := bcrypt.GenerateFromPassword([]byte("dummy-constant-time"), legacyBcryptCost)
	if err != nil {
		return nil, fmt.Errorf("initialize legacy authentication: %w", err)
	}
	s := &store{users: make(map[string]user), path: filepath.Join(dir, "users.json"), dummyHash: dummy}
	if info, err := os.Lstat(s.path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("users.json is not a regular file")
		}
		if info.Size() > maxUsersFileLen {
			return nil, errors.New("users.json exceeds size limit")
		}
		data, err := os.ReadFile(s.path)
		if err != nil {
			return nil, fmt.Errorf("read users.json: %w", err)
		}
		if err := json.Unmarshal(data, &s.users); err != nil {
			return nil, fmt.Errorf("corrupt users.json: %w", err)
		}
		if len(s.users) > maxUsers {
			return nil, fmt.Errorf("users.json exceeds account limit")
		}
		for username, u := range s.users {
			if err := validateStoredUser(username, u); err != nil {
				return nil, fmt.Errorf("invalid account %q: %w", username, err)
			}
		}
		if err := os.Chmod(s.path, 0600); err != nil {
			return nil, fmt.Errorf("secure users.json: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect users.json: %w", err)
	}
	log.Printf("[auth] loaded %d users from %s", len(s.users), s.path)
	return s, nil
}

func (s *store) register(username, password string) error {
	if !usernameRe.MatchString(username) {
		return errors.New("username: 3–20 chars, letters/numbers/underscores")
	}
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if len(password) > 128 {
		return errors.New("password must be at most 128 characters")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[username]; exists {
		return errors.New("username already taken")
	}
	if len(s.users) >= maxUsers {
		return errors.New("account limit reached")
	}
	hash, err := bcrypt.GenerateFromPassword(prehashPassword(password), legacyBcryptCost)
	if err != nil {
		return err
	}
	next := cloneUsers(s.users)
	next[username] = user{Hash: string(hash)}
	return s.commit(next)
}

func (s *store) authenticate(username, password string) error {
	s.mu.RLock()
	u, ok := s.users[username]
	s.mu.RUnlock()
	if !ok || u.Hash == "" {
		// Constant-time work to prevent user-enumeration via timing.
		// Uses a valid bcrypt hash generated at startup (same cost factor).
		bcrypt.CompareHashAndPassword(s.dummyHash, prehashPassword(password))
		return errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.Hash), prehashPassword(password)); err != nil {
		return errors.New("invalid credentials")
	}
	return nil
}

func (s *store) commit(next map[string]user) error {
	if err := atomicWriteJSON(s.path, next); err != nil {
		return err
	}
	s.users = next
	return nil
}

func cloneUsers(src map[string]user) map[string]user {
	dst := make(map[string]user, len(src)+1)
	for username, u := range src {
		dst[username] = u
	}
	return dst
}

func validateStoredUser(username string, u user) error {
	if !usernameRe.MatchString(username) {
		return errors.New("invalid username")
	}
	if u.Hash != "" {
		if u.Salt != "" || u.Verifier != "" || u.Kdf != "" {
			return errors.New("mixed legacy and SRP credentials")
		}
		cost, err := bcrypt.Cost([]byte(u.Hash))
		if err != nil || cost != legacyBcryptCost {
			return errors.New("invalid bcrypt hash")
		}
	} else if err := validateSRPCredential(u.Salt, u.Verifier, u.Kdf); err != nil {
		return fmt.Errorf("invalid primary credential: %w", err)
	}
	if u.DuressSalt == "" && u.DuressVerifier == "" && u.DuressKdf == "" {
		return nil
	}
	if err := validateSRPCredential(u.DuressSalt, u.DuressVerifier, u.DuressKdf); err != nil {
		return fmt.Errorf("invalid duress credential: %w", err)
	}
	return nil
}

// prehashPassword hashes the password with SHA-256 before bcrypt.
// This prevents bcrypt's 72-byte truncation — passwords of any length are fully compared.
func prehashPassword(password string) []byte {
	h := sha256.Sum256([]byte(password))
	return []byte(hex.EncodeToString(h[:]))
}

/* ── Sessions (in-memory, ephemeral — lost on restart by design) ── */

type session struct {
	username  string
	duress    bool
	expiresAt time.Time
}

type sessions struct {
	mu sync.RWMutex
	m  map[string]*session
}

const maxSessions = 10_000

func newSessions() *sessions {
	sm := &sessions{m: make(map[string]*session)}
	go sm.reap()
	return sm
}

func (sm *sessions) create(username string, duress bool) (string, error) {
	for {
		tok, err := genToken()
		if err != nil {
			return "", err
		}
		sm.mu.Lock()
		sm.removeExpiredLocked(time.Now())
		if len(sm.m) >= maxSessions {
			sm.mu.Unlock()
			return "", errors.New("session limit reached")
		}
		if _, collision := sm.m[tok]; collision {
			sm.mu.Unlock()
			continue
		}
		sm.m[tok] = &session{username: username, duress: duress, expiresAt: time.Now().Add(24 * time.Hour)}
		sm.mu.Unlock()
		return tok, nil
	}
}

func (sm *sessions) get(token string) (string, bool) {
	username, _, ok := sm.getMeta(token)
	return username, ok
}

func (sm *sessions) getMeta(token string) (string, bool, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.m[token]
	if !ok || time.Now().After(s.expiresAt) {
		return "", false, false
	}
	return s.username, s.duress, true
}

func (sm *sessions) delete(token string) {
	sm.mu.Lock()
	delete(sm.m, token)
	sm.mu.Unlock()
}

func (sm *sessions) deleteUser(username string) {
	sm.deleteUserExcept(username, "")
}

func (sm *sessions) deleteUserExcept(username, keepToken string) {
	sm.mu.Lock()
	for token, s := range sm.m {
		if token != keepToken && s.username == username {
			delete(sm.m, token)
		}
	}
	sm.mu.Unlock()
}

func (sm *sessions) deleteUserKind(username string, duress bool) {
	sm.deleteUserKindExcept(username, duress, "")
}

func (sm *sessions) deleteUserKindExcept(username string, duress bool, keepToken string) {
	sm.mu.Lock()
	for token, s := range sm.m {
		if token != keepToken && s.username == username && s.duress == duress {
			delete(sm.m, token)
		}
	}
	sm.mu.Unlock()
}

func (sm *sessions) removeExpiredLocked(now time.Time) {
	for token, s := range sm.m {
		if now.After(s.expiresAt) {
			delete(sm.m, token)
		}
	}
}

// reap removes expired sessions every 10 minutes.
func (sm *sessions) reap() {
	for range time.NewTicker(10 * time.Minute).C {
		sm.mu.Lock()
		now := time.Now()
		sm.removeExpiredLocked(now)
		sm.mu.Unlock()
	}
}

func genToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

/* ── HTTP Handler ── */

// Handler exposes auth endpoints and middleware.
type Handler struct {
	store      *store
	sess       *sessions
	invites    *invites
	lockout    *lockout
	challenges *challengeStore
}

func NewHandler(dataDir string) (*Handler, error) {
	st, err := newStore(dataDir)
	if err != nil {
		return nil, err
	}
	challenges, err := newChallengeStore(dataDir)
	if err != nil {
		return nil, err
	}
	return &Handler{
		store:      st,
		sess:       newSessions(),
		invites:    newInvites(dataDir),
		lockout:    newLockout(),
		challenges: challenges,
	}, nil
}

const maxAuthBody = 4096 // 4 KB max for auth JSON payloads

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBody)
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.store.register(body.Username, body.Password); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	token, err := h.sess.create(body.Username, false)
	if err != nil {
		log.Printf("[auth] session token error: %v", err)
		jsonErr(w, "could not create session", http.StatusInternalServerError)
		return
	}
	log.Printf("[auth] new account registered")
	h.setCookie(w, r, token)
	jsonOK(w, map[string]string{"username": body.Username})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBody)
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if !usernameRe.MatchString(body.Username) || len(body.Password) > 128 {
		jsonErr(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	ip := middleware.ExtractIP(r)
	if allowed, wait := h.lockout.allowed(body.Username, ip); !allowed {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())))
		jsonErr(w, "too many attempts — try again later", http.StatusTooManyRequests)
		return
	}
	if err := h.store.authenticate(body.Username, body.Password); err != nil {
		h.lockout.fail(body.Username, ip)
		jsonErr(w, err.Error(), http.StatusUnauthorized)
		return
	}
	h.lockout.reset(body.Username, ip)
	token, err := h.sess.create(body.Username, false)
	if err != nil {
		log.Printf("[auth] session token error: %v", err)
		jsonErr(w, "could not create session", http.StatusInternalServerError)
		return
	}
	h.setCookie(w, r, token)
	jsonOK(w, map[string]string{"username": body.Username})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c, err := sessionCookie(r); err == nil {
		h.sess.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName(r),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		HttpOnly: true,
		Secure:   middleware.IsSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
	jsonOK(w, map[string]string{"status": "ok"})
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, err := sessionCookie(r)
	if err != nil {
		jsonErr(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	username, _, ok := h.sess.getMeta(c.Value)
	if !ok {
		jsonErr(w, "session expired", http.StatusUnauthorized)
		return
	}
	jsonOK(w, map[string]any{"username": username, "features": sessionFeatures(false)})
}

// sessionFeatures is deliberately identical for primary and duress sessions.
// Different response capabilities would reveal the decoy in DevTools, to browser
// extensions, or to anyone comparing the two login flows.
func sessionFeatures(_ bool) []string {
	return []string{"settings"}
}

// RequireAuth rejects unauthenticated requests before they reach the next handler.
func (h *Handler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.SessionValid(r) {
			jsonErr(w, "session expired", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// SessionValid re-checks the cookie-backed in-memory session. Long-lived
// transports use it periodically so logout, deletion, and expiry revoke an
// already-open WebSocket instead of only blocking future upgrades.
func (h *Handler) SessionValid(r *http.Request) bool {
	_, ok := h.SessionPrincipal(r)
	return ok
}

// SessionPrincipal returns the account identity only for in-process resource
// accounting. It is never serialized or logged by the signaling layer.
func (h *Handler) SessionPrincipal(r *http.Request) (string, bool) {
	c, err := sessionCookie(r)
	if err != nil {
		return "", false
	}
	return h.sess.get(c.Value)
}

// setCookie detects HTTPS (via X-Forwarded-Proto from nginx) to set the Secure flag.
func (h *Handler) setCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName(r),
		Value:    token,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   middleware.IsSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func sessionCookieName(r *http.Request) string {
	if middleware.IsSecureRequest(r) {
		return "__Host-dd_session"
	}
	return "dd_session"
}

func sessionCookie(r *http.Request) (*http.Cookie, error) {
	return r.Cookie(sessionCookieName(r))
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func subtleEqual(a, b string) bool {
	aSum := sha256.Sum256([]byte(a))
	bSum := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aSum[:], bSum[:]) == 1
}
