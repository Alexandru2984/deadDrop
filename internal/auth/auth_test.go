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
		}
	}
	if !found {
		t.Fatal("expected dd_session cookie")
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
