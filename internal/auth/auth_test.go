package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	dir := t.TempDir()
	h, err := NewHandler(dir)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func TestRegisterAndLogin(t *testing.T) {
	h := newTestHandler(t)

	// Register
	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "securepass1"})
	req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Register(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("register expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Login
	body, _ = json.Marshal(map[string]string{"username": "alice", "password": "securepass1"})
	req = httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify session cookie set
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "dd_session" && c.Value != "" {
			found = true
			if c.SameSite != http.SameSiteStrictMode {
				t.Errorf("session SameSite = %v, want Strict", c.SameSite)
			}
		}
	}
	if !found {
		t.Fatal("expected dd_session cookie")
	}
}

func TestCookieSecureFlagTrustsOnlyLocalProxy(t *testing.T) {
	h := newTestHandler(t)

	local := httptest.NewRequest(http.MethodGet, "http://dead.micutu.com/", nil)
	local.RemoteAddr = "127.0.0.1:1234"
	local.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	h.setCookie(w, local, "test-token")
	if got := w.Result().Cookies()[0]; !got.Secure || got.Name != "__Host-dd_session" {
		t.Fatalf("cookie behind local TLS proxy = %#v, want Secure __Host- cookie", got)
	}

	public := httptest.NewRequest(http.MethodGet, "http://dead.micutu.com/", nil)
	public.RemoteAddr = "203.0.113.10:1234"
	public.Header.Set("X-Forwarded-Proto", "https")
	w = httptest.NewRecorder()
	h.setCookie(w, public, "test-token")
	if got := w.Result().Cookies()[0]; got.Secure || got.Name != "dd_session" {
		t.Fatalf("untrusted forwarded proto controlled cookie policy: %#v", got)
	}
}

func TestGenerateInviteRequiresPost(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "test-admin-token-with-enough-entropy")
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/admin/invite", nil)
	req.Header.Set("X-Admin-Token", "test-admin-token-with-enough-entropy")
	w := httptest.NewRecorder()
	h.GenerateInvite(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET invite: got %d, want 405", w.Code)
	}
}

func TestPasswordTooShort(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"username": "bob", "password": "short"})
	req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Register(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short password, got %d", w.Code)
	}
}

func TestPasswordTooLong(t *testing.T) {
	h := newTestHandler(t)

	long := make([]byte, 129)
	for i := range long {
		long[i] = 'a'
	}
	body, _ := json.Marshal(map[string]string{"username": "bob", "password": string(long)})
	req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Register(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for long password, got %d", w.Code)
	}
}

func TestDuplicateUsername(t *testing.T) {
	h := newTestHandler(t)

	for i := 0; i < 2; i++ {
		body, _ := json.Marshal(map[string]string{"username": "alice", "password": "securepass1"})
		req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.Register(w, req)

		if i == 1 && w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for duplicate, got %d", w.Code)
		}
	}
}

func TestWrongPassword(t *testing.T) {
	h := newTestHandler(t)

	// Register
	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "securepass1"})
	req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Register(w, req)

	// Login with wrong password
	body, _ = json.Marshal(map[string]string{"username": "alice", "password": "wrongpassword"})
	req = httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestNonexistentUser(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"username": "ghost", "password": "doesntmatter"})
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRequireAuth(t *testing.T) {
	h := newTestHandler(t)

	inner := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}
	handler := h.RequireAuth(inner)

	// No cookie → 401
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without cookie, got %d", w.Code)
	}

	// Invalid cookie → 401
	req = httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "dd_session", Value: "bad-token"})
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with bad cookie, got %d", w.Code)
	}
}

func TestBodySizeLimit(t *testing.T) {
	h := newTestHandler(t)

	// Send a very large body (>4096 bytes)
	big := make([]byte, 8192)
	for i := range big {
		big[i] = 'x'
	}
	req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Register(w, req)

	// Should fail (bad JSON or body too large), not crash
	if w.Code == http.StatusOK {
		t.Fatal("expected rejection for oversized body")
	}
}

func TestCorruptUsersJSON(t *testing.T) {
	dir := t.TempDir()

	// Write corrupt JSON
	corrupt := []byte("{bad json!!")
	os.WriteFile(filepath.Join(dir, "users.json"), corrupt, 0600)

	_, err := NewHandler(dir)
	if err == nil {
		t.Fatal("expected error for corrupt users.json")
	}
}

func TestBcryptPrehash(t *testing.T) {
	h := newTestHandler(t)

	// Register with a 100-char password (exceeds bcrypt's 72-byte limit without prehash)
	longPass := "abcdefghij" // 10 chars
	for len(longPass) < 100 {
		longPass += "abcdefghij"
	}
	body, _ := json.Marshal(map[string]string{"username": "longy", "password": longPass})
	req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Register(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register with long password: expected 200, got %d", w.Code)
	}

	// Login with correct long password
	body, _ = json.Marshal(map[string]string{"username": "longy", "password": longPass})
	req = httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.Login(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login with correct long password: expected 200, got %d", w.Code)
	}

	// Login with truncated version should FAIL (proves prehash works)
	body, _ = json.Marshal(map[string]string{"username": "longy", "password": longPass[:72]})
	req = httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.Login(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("login with truncated password: expected 401, got %d", w.Code)
	}
}

func TestLogoutRequiresPost(t *testing.T) {
	h := newTestHandler(t)

	// Register and login to get a session
	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "securepass1"})
	req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Register(w, req)

	cookie := w.Result().Cookies()[0]

	// GET logout should be rejected (CSRF protection)
	req = httptest.NewRequest(http.MethodGet, "/api/logout", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.Logout(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout: expected 405, got %d", w.Code)
	}

	// POST logout should work
	req = httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.Logout(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST logout: expected 200, got %d", w.Code)
	}
}

func TestAtomicSave(t *testing.T) {
	dir := t.TempDir()
	h, err := NewHandler(dir)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	// Register a user (triggers save)
	body, _ := json.Marshal(map[string]string{"username": "bob", "password": "securepass1"})
	req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Register(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d", w.Code)
	}

	// Verify users.json exists and no .tmp file lingers
	usersPath := filepath.Join(dir, "users.json")
	tmpPath := usersPath + ".tmp"

	if _, err := os.Stat(usersPath); os.IsNotExist(err) {
		t.Fatal("users.json not found after save")
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatal("users.json.tmp should not exist after atomic save")
	}

	// Verify the file is valid JSON
	data, err := os.ReadFile(usersPath)
	if err != nil {
		t.Fatalf("read users.json: %v", err)
	}
	var users map[string]interface{}
	if err := json.Unmarshal(data, &users); err != nil {
		t.Fatalf("users.json is not valid JSON: %v", err)
	}
	if _, ok := users["bob"]; !ok {
		t.Fatal("user 'bob' not found in users.json")
	}
}

func TestLockoutIsPerIP(t *testing.T) {
	l := newLockout()
	// One IP hammers the account past the threshold…
	for i := 0; i < 5; i++ {
		l.fail("victim", "203.0.113.9")
	}
	if ok, _ := l.allowed("victim", "203.0.113.9"); ok {
		t.Fatal("attacker IP should be locked out after threshold failures")
	}
	// …but the legitimate user on a different IP is unaffected.
	if ok, _ := l.allowed("victim", "198.51.100.7"); !ok {
		t.Fatal("a different IP must not be locked out (account-lockout DoS)")
	}
	// A success clears only that IP's slate.
	l.reset("victim", "203.0.113.9")
	if ok, _ := l.allowed("victim", "203.0.113.9"); !ok {
		t.Fatal("reset should clear the lockout for that username+IP")
	}
}

func TestValidKdf(t *testing.T) {
	valid := []string{"", "pbkdf2:600000", "pbkdf2:10000", "pbkdf2:5000000"}
	for _, k := range valid {
		if !validKdf(k) {
			t.Errorf("validKdf(%q) = false, want true", k)
		}
	}
	invalid := []string{
		"pbkdf2:9999",      // below the floor — no real stretch
		"pbkdf2:5000001",   // above the cap — could freeze a client at login
		"pbkdf2:",          // no count
		"pbkdf2:1e6",       // not a plain integer
		"argon2id:3",       // unknown algorithm
		"PBKDF2:600000",    // case matters; must match the client exactly
		" pbkdf2:600000",   // no padding
		"pbkdf2:600000000", // 9 digits but over the cap
	}
	for _, k := range invalid {
		if validKdf(k) {
			t.Errorf("validKdf(%q) = true, want false", k)
		}
	}
}

func TestWritableKdfCannotBeDowngraded(t *testing.T) {
	salt, verifier := testSRPCredential("alice", "password")
	for _, kdf := range []string{"", "pbkdf2:10000", "pbkdf2:599999"} {
		if err := validateWritableSRPCredential(salt, verifier, kdf); err == nil {
			t.Errorf("writable credential accepted weak kdf %q", kdf)
		}
	}
	for _, kdf := range []string{defaultKdf, "pbkdf2:1000000", "pbkdf2:5000000"} {
		if err := validateWritableSRPCredential(salt, verifier, kdf); err != nil {
			t.Errorf("writable credential rejected kdf %q: %v", kdf, err)
		}
	}
}
