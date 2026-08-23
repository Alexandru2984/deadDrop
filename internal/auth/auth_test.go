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

// srpRoundTrip drives /api/srp/challenge + /api/srp/authenticate exactly as the
// browser does and returns the authenticate response.
func srpRoundTrip(t *testing.T, h *Handler, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	a, A := testClientA(t)
	body, _ := json.Marshal(map[string]string{"username": username, "A": A.Text(16)})
	req := httptest.NewRequest(http.MethodPost, "/api/srp/challenge", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.SRPChallenge(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("challenge: got %d: %s", w.Code, w.Body.String())
	}
	var ch struct {
		Token, Salt, B, Salt2, B2 string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ch); err != nil {
		t.Fatalf("challenge body: %v", err)
	}
	m1, _ := testClientProof(t, a, A, username, password, ch.Salt, ch.B)
	m1d, _ := testClientProof(t, a, A, username, password, ch.Salt2, ch.B2)
	body, _ = json.Marshal(map[string]string{"token": ch.Token, "M1": m1, "M1d": m1d})
	req = httptest.NewRequest(http.MethodPost, "/api/srp/authenticate", bytes.NewReader(body))
	w = httptest.NewRecorder()
	h.SRPAuthenticate(w, req)
	return w
}

func registerTestAccount(t *testing.T, h *Handler, username, password string) {
	t.Helper()
	salt, verifier := testSRPCredential(username, password)
	if err := h.store.registerSRP(username, salt, verifier, defaultKdf); err != nil {
		t.Fatalf("registerSRP: %v", err)
	}
}

func TestSRPLoginSetsStrictSessionCookie(t *testing.T) {
	h := newTestHandler(t)
	registerTestAccount(t, h, "alice", "correct horse battery staple")

	w := srpRoundTrip(t, h, "alice", "correct horse battery staple")
	if w.Code != http.StatusOK {
		t.Fatalf("authenticate: got %d: %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "dd_session" && c.Value != "" {
			if c.SameSite != http.SameSiteStrictMode || !c.HttpOnly {
				t.Fatalf("session cookie = %#v, want HttpOnly + SameSite=Strict", c)
			}
			return
		}
	}
	t.Fatal("expected a dd_session cookie")
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

func TestDuplicateUsername(t *testing.T) {
	h := newTestHandler(t)
	salt, verifier := testSRPCredential("alice", "correct horse battery staple")
	if err := h.store.registerSRP("alice", salt, verifier, defaultKdf); err != nil {
		t.Fatal(err)
	}
	if err := h.store.registerSRP("alice", salt, verifier, defaultKdf); err == nil {
		t.Fatal("expected a duplicate registration to be rejected")
	}
}

func TestWrongPassword(t *testing.T) {
	h := newTestHandler(t)
	registerTestAccount(t, h, "alice", "correct horse battery staple")
	if w := srpRoundTrip(t, h, "alice", "wrong password entirely"); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

// An unknown handle must receive a complete, plausible challenge and then a
// plain 401 — never a distinct field or status that confirms it does not exist.
func TestNonexistentUserIsIndistinguishable(t *testing.T) {
	h := newTestHandler(t)
	registerTestAccount(t, h, "alice", "correct horse battery staple")

	shape := func(username string) map[string]any {
		t.Helper()
		_, A := testClientA(t)
		body, _ := json.Marshal(map[string]string{"username": username, "A": A.Text(16)})
		req := httptest.NewRequest(http.MethodPost, "/api/srp/challenge", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.SRPChallenge(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("challenge for %q: got %d", username, w.Code)
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	real, ghost := shape("alice"), shape("ghost")
	if len(real) != len(ghost) {
		t.Fatalf("challenge shapes differ: real=%v ghost=%v", real, ghost)
	}
	for key := range real {
		if _, ok := ghost[key]; !ok {
			t.Fatalf("unknown-user challenge is missing %q", key)
		}
	}
	for _, forbidden := range []string{"legacy", "exists", "error"} {
		if _, ok := ghost[forbidden]; ok {
			t.Fatalf("challenge leaks account state via %q", forbidden)
		}
	}
	if w := srpRoundTrip(t, h, "ghost", "doesntmatter"); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown user authenticate: got %d, want 401", w.Code)
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
	big := make([]byte, 32*1024)
	for i := range big {
		big[i] = 'x'
	}
	req := httptest.NewRequest(http.MethodPost, "/api/srp/register", bytes.NewReader(big))
	w := httptest.NewRecorder()
	h.SRPRegister(w, req)
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

func TestLogoutRequiresPost(t *testing.T) {
	h := newTestHandler(t)
	registerTestAccount(t, h, "alice", "correct horse battery staple")
	token, err := h.sess.create("alice", false)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: "dd_session", Value: token}

	req := httptest.NewRequest(http.MethodGet, "/api/logout", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.Logout(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout: expected 405, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.Logout(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST logout: expected 200, got %d", w.Code)
	}
	if _, ok := h.sess.get(token); ok {
		t.Fatal("logout did not invalidate the session")
	}
}

func TestAtomicSave(t *testing.T) {
	dir := t.TempDir()
	h, err := NewHandler(dir)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	salt, verifier := testSRPCredential("bob", "correct horse battery staple")
	if err := h.store.registerSRP("bob", salt, verifier, defaultKdf); err != nil {
		t.Fatalf("registerSRP: %v", err)
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
