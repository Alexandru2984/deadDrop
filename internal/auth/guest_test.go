package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testRoom = "abcdef123456abcdef123456"

func testValidRoom(code string) bool { return len(code) == 24 && isLowerHexString(code) }

func withSession(req *http.Request, token string) *http.Request {
	if token != "" {
		req.AddCookie(&http.Cookie{Name: "dd_session", Value: token})
	}
	return req
}

func mintGuestPass(t *testing.T, h *Handler, hostToken, room string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"room": room})
	w := httptest.NewRecorder()
	h.GuestPass(testValidRoom)(w, withSession(httptest.NewRequest(http.MethodPost, "/api/guest", bytes.NewReader(body)), hostToken))
	return w
}

func passFrom(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("mint: got %d: %s", w.Code, w.Body.String())
	}
	var out struct{ Token string }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Token) != guestPassHexLen {
		t.Fatalf("mint body %q: %v", w.Body.String(), err)
	}
	return out.Token
}

func redeemGuestPass(h *Handler, pass, existingToken string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"token": pass})
	w := httptest.NewRecorder()
	h.GuestRedeem(w, withSession(httptest.NewRequest(http.MethodPost, "/api/guest/redeem", bytes.NewReader(body)), existingToken))
	return w
}

func sessionFrom(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == "dd_session" && c.Value != "" {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Fatalf("guest cookie is not HttpOnly and SameSite=Strict: %+v", c)
			}
			return c.Value
		}
	}
	t.Fatalf("no session cookie in %d: %s", w.Code, w.Body.String())
	return ""
}

func TestGuestPassAdmitsOnePersonToOneRoom(t *testing.T) {
	h := newTestHandler(t)
	host := createTestSession(t, h, "alice", false)
	pass := passFrom(t, mintGuestPass(t, h, host, testRoom))

	w := redeemGuestPass(h, pass, "")
	if w.Code != http.StatusOK {
		t.Fatalf("redeem: got %d: %s", w.Code, w.Body.String())
	}
	guest := sessionFrom(t, w)

	principal, room, ok := h.sess.access(guest)
	if !ok || room != testRoom || !isGuestPrincipal(principal) {
		t.Fatalf("guest session = %q in %q (live %t)", principal, room, ok)
	}
	if usernameRe.MatchString(principal) {
		t.Fatalf("guest principal %q could be registered as an account name", principal)
	}
	if got, isGuest := h.SessionGuestRoom(withSession(httptest.NewRequest(http.MethodGet, "/ws", nil), guest)); !isGuest || got != testRoom {
		t.Fatalf("SessionGuestRoom = %q, %t", got, isGuest)
	}
	if _, isGuest := h.SessionGuestRoom(withSession(httptest.NewRequest(http.MethodGet, "/ws", nil), host)); isGuest {
		t.Fatal("an account session was reported as a guest")
	}

	// /api/me names the room and nothing about who vouched.
	me := httptest.NewRecorder()
	h.Me(me, withSession(httptest.NewRequest(http.MethodGet, "/api/me", nil), guest))
	var seen map[string]any
	if err := json.Unmarshal(me.Body.Bytes(), &seen); err != nil {
		t.Fatal(err)
	}
	if seen["guest"] != true || seen["room"] != testRoom || seen["username"] != "guest" {
		t.Fatalf("/api/me for a guest = %s", me.Body.String())
	}
	if strings.Contains(me.Body.String(), "alice") || strings.Contains(me.Body.String(), principal) {
		t.Fatalf("/api/me for a guest leaks an identity: %s", me.Body.String())
	}

	// The pass worked once.
	if again := redeemGuestPass(h, pass, ""); again.Code != http.StatusForbidden {
		t.Fatalf("second use of a pass: got %d, want 403", again.Code)
	}
}

func TestGuestCannotActAsAnAccount(t *testing.T) {
	h := newTestHandler(t)
	registerTestAccount(t, h, "alice", "correct horse battery staple")
	host := createTestSession(t, h, "alice", false)
	guest := sessionFrom(t, redeemGuestPass(h, passFrom(t, mintGuestPass(t, h, host, testRoom)), ""))

	if w := mintGuestPass(t, h, guest, testRoom); w.Code != http.StatusForbidden {
		t.Fatalf("a guest minting a pass: got %d, want 403", w.Code)
	}
	for name, handler := range map[string]http.HandlerFunc{
		"verifier": h.SetVerifier, "duress": h.SetDuress,
		"delete": h.DeleteAccount, "signout-others": h.SignOutOthers,
	} {
		w := httptest.NewRecorder()
		handler(w, withSession(httptest.NewRequest(http.MethodPost, "/api/account/"+name, strings.NewReader(`{}`)), guest))
		if w.Code != http.StatusForbidden {
			t.Errorf("guest calling account/%s: got %d, want 403: %s", name, w.Code, w.Body.String())
		}
	}
	// And the account it was vouched by is untouched by any of that.
	if w := srpRoundTrip(t, h, "alice", "correct horse battery staple"); w.Code != http.StatusOK {
		t.Fatalf("host can no longer sign in: %d %s", w.Code, w.Body.String())
	}
}

func TestGuestPassRefusals(t *testing.T) {
	h := newTestHandler(t)
	host := createTestSession(t, h, "alice", false)

	if w := mintGuestPass(t, h, "", testRoom); w.Code != http.StatusUnauthorized {
		t.Fatalf("mint without a session: got %d, want 401", w.Code)
	}
	for _, room := range []string{"", "abc", strings.ToUpper(testRoom), testRoom + "0", "zzzzzz123456abcdef123456"} {
		if w := mintGuestPass(t, h, host, room); w.Code != http.StatusBadRequest {
			t.Errorf("mint for room %q: got %d, want 400", room, w.Code)
		}
	}
	for _, pass := range []string{"", "0", strings.Repeat("g", guestPassHexLen), strings.Repeat("a", guestPassHexLen),
		strings.Repeat("A", guestPassHexLen), strings.Repeat("a", guestPassHexLen+2)} {
		if w := redeemGuestPass(h, pass, ""); w.Code != http.StatusForbidden {
			t.Errorf("redeem %q: got %d, want 403", pass, w.Code)
		}
	}

	// Someone signed in to an account keeps that session: a guest cookie
	// never replaces it, and the pass is left for whoever it was meant for.
	pass := passFrom(t, mintGuestPass(t, h, host, testRoom))
	other := createTestSession(t, h, "bob", false)
	if w := redeemGuestPass(h, pass, other); w.Code != http.StatusConflict {
		t.Fatalf("redeem while signed in: got %d, want 409", w.Code)
	}
	assertSession(t, h, other, true, "the account session of whoever opened the link")
	if w := redeemGuestPass(h, pass, ""); w.Code != http.StatusOK {
		t.Fatalf("the pass was spent by a refused attempt: %d", w.Code)
	}
}

func TestGuestPassDiesWithTheSessionThatVouched(t *testing.T) {
	h := newTestHandler(t)
	host := createTestSession(t, h, "alice", false)
	pass := passFrom(t, mintGuestPass(t, h, host, testRoom))

	h.sess.delete(host) // signed out; a password change or deletion ends it the same way
	if w := redeemGuestPass(h, pass, ""); w.Code != http.StatusForbidden {
		t.Fatalf("pass outlived the session that minted it: got %d", w.Code)
	}
}

func TestGuestPassExpires(t *testing.T) {
	h := newTestHandler(t)
	host := createTestSession(t, h, "alice", false)
	pass := passFrom(t, mintGuestPass(t, h, host, testRoom))

	h.guests.mu.Lock()
	h.guests.m[tokenKey(pass)].expires = time.Now().Add(-time.Second)
	h.guests.mu.Unlock()
	if w := redeemGuestPass(h, pass, ""); w.Code != http.StatusForbidden {
		t.Fatalf("expired pass: got %d, want 403", w.Code)
	}
}

func TestGuestSessionIsShortAndCannotBeRenewed(t *testing.T) {
	h := newTestHandler(t)
	host := createTestSession(t, h, "alice", false)
	guest := sessionFrom(t, redeemGuestPass(h, passFrom(t, mintGuestPass(t, h, host, testRoom)), ""))

	h.sess.mu.RLock()
	s := h.sess.m[tokenKey(guest)]
	left := time.Until(s.expiresAt)
	h.sess.mu.RUnlock()
	if left > guestSessionTTL || left < guestSessionTTL-time.Minute {
		t.Fatalf("guest session lasts %s, want about %s", left, guestSessionTTL)
	}
	if guestSessionTTL >= sessionAbsoluteTTL {
		t.Fatal("a guest session must not outlast an account's")
	}

	// Activity keeps an idle session alive but never moves the absolute end.
	h.sess.mu.Lock()
	s.expiresAt = time.Now().Add(-time.Second)
	h.sess.mu.Unlock()
	if _, _, ok := h.sess.access(guest); ok {
		t.Fatal("a guest session past its end was still accepted")
	}
}

func TestGuestLimitsPerHost(t *testing.T) {
	h := newTestHandler(t)
	host := createTestSession(t, h, "alice", false)

	// The newest links win: the host means the one just made.
	passes := make([]string, 0, maxGuestPassesPerHost+2)
	for i := 0; i < maxGuestPassesPerHost+2; i++ {
		passes = append(passes, passFrom(t, mintGuestPass(t, h, host, testRoom)))
		h.guests.mu.Lock()
		h.guests.m[tokenKey(passes[i])].minted = time.Now().Add(time.Duration(i) * time.Millisecond)
		h.guests.mu.Unlock()
	}
	h.guests.mu.Lock()
	held := len(h.guests.m)
	h.guests.mu.Unlock()
	if held != maxGuestPassesPerHost {
		t.Fatalf("%d passes outstanding for one host, want %d", held, maxGuestPassesPerHost)
	}
	if w := redeemGuestPass(h, passes[0], ""); w.Code != http.StatusForbidden {
		t.Fatalf("the oldest pass survived being replaced: %d", w.Code)
	}
	if w := redeemGuestPass(h, passes[len(passes)-1], ""); w.Code != http.StatusOK {
		t.Fatalf("the newest pass does not work: %d", w.Code)
	}

	// One account cannot fill the session table with guests.
	for i := 1; i < maxGuestSessionsPerHost; i++ {
		if _, err := h.sess.createGuest(testRoom, "alice"); err != nil {
			t.Fatalf("guest %d: %v", i, err)
		}
	}
	if _, err := h.sess.createGuest(testRoom, "alice"); err == nil {
		t.Fatalf("more than %d guests signed in for one host", maxGuestSessionsPerHost)
	}
	if _, err := h.sess.createGuest(testRoom, "bob"); err != nil {
		t.Fatalf("one host's guests used up another's allowance: %v", err)
	}
}
