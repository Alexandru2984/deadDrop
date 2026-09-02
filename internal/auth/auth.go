package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"deaddrop/internal/middleware"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)

/* ── User Store (file-backed) ── */

// user holds an SRP verifier+salt. Login sends proofs, never the password.
//
// Hash is retained for detection only: it names the removed bcrypt credential
// so a users.json written by an older build fails loudly at startup instead of
// silently decoding into an account that can never authenticate.
type user struct {
	Hash     string `json:"hash,omitempty"`     // removed bcrypt credential — rejected on load
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
	mu    sync.RWMutex
	users map[string]user
	path  string
}

const (
	maxUsers        = 10_000
	maxUsersFileLen = 32 << 20
)

func newStore(dir string) (*store, error) {
	path := filepath.Join(dir, "users.json")
	root, name, err := openPrivateRoot(path)
	if err != nil {
		return nil, fmt.Errorf("secure auth data directory: %w", err)
	}
	defer root.Close()
	s := &store{users: make(map[string]user), path: path}
	if info, err := root.Lstat(name); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("users.json is not a regular file")
		}
		if info.Size() > maxUsersFileLen {
			return nil, errors.New("users.json exceeds size limit")
		}
		file, err := root.Open(name)
		if err != nil {
			return nil, fmt.Errorf("read users.json: %w", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxUsersFileLen+1))
		if chmodErr := file.Chmod(0600); readErr == nil && chmodErr != nil {
			readErr = chmodErr
		}
		if closeErr := file.Close(); readErr == nil && closeErr != nil {
			readErr = closeErr
		}
		if readErr != nil {
			return nil, fmt.Errorf("read users.json: %w", readErr)
		}
		if len(data) > maxUsersFileLen {
			return nil, errors.New("users.json exceeds size limit")
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
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect users.json: %w", err)
	}
	log.Printf("[auth] loaded %d users from %s", len(s.users), s.path)
	return s, nil
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
		return errors.New("bcrypt credential is no longer supported; delete the account and re-register with SRP")
	}
	if err := validateSRPCredential(u.Salt, u.Verifier, u.Kdf); err != nil {
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

/* ── Sessions (in-memory, ephemeral — lost on restart by design) ── */

type session struct {
	username  string
	duress    bool
	expiresAt time.Time
	// lastSeen tracks activity for the idle bound. It is an atomic so a validity
	// check can refresh it while holding only a read lock — every WebSocket pump
	// re-checks its session every few seconds, so this is a hot path.
	lastSeen atomic.Int64
}

func (s *session) live(now time.Time) bool {
	if now.After(s.expiresAt) {
		return false
	}
	return now.Sub(time.Unix(0, s.lastSeen.Load())) <= sessionIdleTimeout
}

type sessions struct {
	mu sync.RWMutex
	m  map[string]*session
}

const (
	maxSessions = 10_000
	// A session dies at whichever bound comes first. The absolute cap limits how
	// long a stolen cookie is worth anything; the idle bound closes the far more
	// common case of a browser left open and walked away from. Long-lived
	// transports re-check their session every few seconds, so an active chat
	// keeps itself alive without any client-side keepalive.
	sessionAbsoluteTTL = 12 * time.Hour
	sessionIdleTimeout = 30 * time.Minute
)

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
		now := time.Now()
		entry := &session{username: username, duress: duress, expiresAt: now.Add(sessionAbsoluteTTL)}
		entry.lastSeen.Store(now.UnixNano())
		sm.m[tok] = entry
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
	now := time.Now()
	if !ok || !s.live(now) {
		return "", false, false
	}
	s.lastSeen.Store(now.UnixNano())
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
		if !s.live(now) {
			delete(sm.m, token)
		}
	}
}

// reap drops sessions past either bound.
func (sm *sessions) reap() {
	for range time.NewTicker(5 * time.Minute).C {
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

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c, err := sessionCookie(r); err == nil {
		h.sess.delete(c.Value)
	}
	setClearSiteData(w, r, r.URL.Query().Get("wipe") == "1")
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- flags are explicit; Secure is false only for local HTTP development
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
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- flags are explicit; Secure is false only for local HTTP development
		Name:     sessionCookieName(r),
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionAbsoluteTTL.Seconds()),
		HttpOnly: true,
		Secure:   middleware.IsSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// setClearSiteData asks the browser to drop local traces of this origin.
//
// "cookies" is deliberately NOT requested. The directive is specified to clear
// cookies for the whole registrable domain, not just this origin, so on a host
// that serves other applications under sibling subdomains it would sign the user
// out of all of them. The session cookie is expired explicitly instead, which is
// precise and origin-scoped.
//
// "storage" is requested only for a panic wipe: it also unregisters service
// workers, which is the right call when the user is destroying local traces, but
// would silently discard the pinned-code registration on an ordinary logout.
func setClearSiteData(w http.ResponseWriter, r *http.Request, wipeStorage bool) {
	if !middleware.IsSecureRequest(r) {
		return // the directive is ignored outside secure contexts anyway
	}
	if wipeStorage {
		w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
		return
	}
	w.Header().Set("Clear-Site-Data", `"cache"`)
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
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func subtleEqual(a, b string) bool {
	aSum := sha256.Sum256([]byte(a))
	bSum := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aSum[:], bSum[:]) == 1
}
