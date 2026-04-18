package auth

import (
	"crypto/rand"
	"crypto/sha256"
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

	"golang.org/x/crypto/bcrypt"
)

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)

/* ── User Store (file-backed, password hashes only) ── */

type user struct {
	Hash string `json:"hash"`
}

type store struct {
	mu    sync.RWMutex
	users map[string]user
	path  string
}

func newStore(dir string) (*store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &store{users: make(map[string]user), path: filepath.Join(dir, "users.json")}
	if data, err := os.ReadFile(s.path); err == nil {
		if err := json.Unmarshal(data, &s.users); err != nil {
			return nil, fmt.Errorf("corrupt users.json: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read users.json: %w", err)
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
	hash, err := bcrypt.GenerateFromPassword(prehashPassword(password), 12)
	if err != nil {
		return err
	}
	s.users[username] = user{Hash: string(hash)}
	return s.save()
}

func (s *store) authenticate(username, password string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		// Constant-time work to prevent user-enumeration via timing
		bcrypt.CompareHashAndPassword(
			[]byte("$2a$12$000000000000000000000u000000000000000000000000000000"),
			prehashPassword(password),
		)
		return errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.Hash), prehashPassword(password)); err != nil {
		return errors.New("invalid credentials")
	}
	return nil
}

func (s *store) save() error {
	data, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
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
	expiresAt time.Time
}

type sessions struct {
	mu sync.RWMutex
	m  map[string]*session
}

func newSessions() *sessions {
	sm := &sessions{m: make(map[string]*session)}
	go sm.reap()
	return sm
}

func (sm *sessions) create(username string) string {
	tok := genToken()
	sm.mu.Lock()
	sm.m[tok] = &session{username: username, expiresAt: time.Now().Add(24 * time.Hour)}
	sm.mu.Unlock()
	return tok
}

func (sm *sessions) get(token string) (string, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.m[token]
	if !ok || time.Now().After(s.expiresAt) {
		return "", false
	}
	return s.username, true
}

func (sm *sessions) delete(token string) {
	sm.mu.Lock()
	delete(sm.m, token)
	sm.mu.Unlock()
}

// reap removes expired sessions every 10 minutes.
func (sm *sessions) reap() {
	for range time.NewTicker(10 * time.Minute).C {
		sm.mu.Lock()
		now := time.Now()
		for k, s := range sm.m {
			if now.After(s.expiresAt) {
				delete(sm.m, k)
			}
		}
		sm.mu.Unlock()
	}
}

func genToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

/* ── HTTP Handler ── */

// Handler exposes auth endpoints and middleware.
type Handler struct {
	store *store
	sess  *sessions
}

func NewHandler(dataDir string) (*Handler, error) {
	st, err := newStore(dataDir)
	if err != nil {
		return nil, err
	}
	return &Handler{store: st, sess: newSessions()}, nil
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.store.register(body.Username, body.Password); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("[auth] registered user=%s", body.Username)
	h.setCookie(w, r, h.sess.create(body.Username))
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.store.authenticate(body.Username, body.Password); err != nil {
		jsonErr(w, err.Error(), http.StatusUnauthorized)
		return
	}
	log.Printf("[auth] login user=%s", body.Username)
	h.setCookie(w, r, h.sess.create(body.Username))
	jsonOK(w, map[string]string{"username": body.Username})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie("dd_session"); err == nil {
		h.sess.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: "dd_session", Value: "", Path: "/",
		MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	jsonOK(w, map[string]string{"status": "ok"})
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("dd_session")
	if err != nil {
		jsonErr(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	username, ok := h.sess.get(c.Value)
	if !ok {
		jsonErr(w, "session expired", http.StatusUnauthorized)
		return
	}
	jsonOK(w, map[string]string{"username": username})
}

// RequireAuth rejects unauthenticated requests before they reach the next handler.
func (h *Handler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("dd_session")
		if err != nil {
			jsonErr(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		if _, ok := h.sess.get(c.Value); !ok {
			jsonErr(w, "session expired", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// setCookie detects HTTPS (via X-Forwarded-Proto from nginx) to set the Secure flag.
func (h *Handler) setCookie(w http.ResponseWriter, r *http.Request, token string) {
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     "dd_session",
		Value:    token,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
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
