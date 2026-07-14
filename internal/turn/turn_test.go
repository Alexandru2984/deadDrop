package turn

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHandlerMintsValidEphemeralCredential(t *testing.T) {
	cfg := Config{
		Secret:   "test-secret-with-at-least-32-characters",
		TurnURLs: []string{"turn:198.51.100.1:3478?transport=udp"},
		StunURLs: []string{"stun:198.51.100.1:3478"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	w := httptest.NewRecorder()
	cfg.Handler()(w, httptest.NewRequest(http.MethodGet, "/api/turn", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store, no-transform" {
		t.Errorf("Cache-Control = %q, want no-store, no-transform", cc)
	}

	var body struct {
		IceServers []struct {
			URLs       []string `json:"urls"`
			Username   string   `json:"username"`
			Credential string   `json:"credential"`
		} `json:"iceServers"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.IceServers) != 2 {
		t.Fatalf("want STUN + TURN entries, got %d", len(body.IceServers))
	}
	turn := body.IceServers[1]
	if turn.Username == "" || turn.Credential == "" {
		t.Fatal("TURN entry missing username/credential")
	}

	// Username must be a future expiry timestamp.
	parts := strings.Split(turn.Username, ":")
	if len(parts) != 2 || len(parts[1]) != 16 {
		t.Fatalf("username lacks a per-credential nonce: %q", turn.Username)
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		t.Fatalf("username not a timestamp: %v", err)
	}
	if time.Until(time.Unix(exp, 0)) <= 0 {
		t.Error("credential already expired")
	}

	// Credential must equal base64(HMAC-SHA1(secret, username)) — coturn's scheme.
	mac := hmac.New(sha1.New, []byte(cfg.Secret))
	mac.Write([]byte(turn.Username))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if turn.Credential != want {
		t.Errorf("credential = %q, want %q", turn.Credential, want)
	}
}

func TestConfigValidation(t *testing.T) {
	valid := []Config{
		{},
		{StunURLs: []string{"stun:127.0.0.1:3478", "stuns:[::1]:5349"}},
		{Secret: "0123456789abcdef0123456789abcdef", TurnURLs: []string{
			"turn:turn.example.com:3478?transport=udp",
			"turns:turn.example.com:5349?transport=tcp",
		}},
	}
	for i, cfg := range valid {
		if err := cfg.Validate(); err != nil {
			t.Errorf("valid config %d rejected: %v", i, err)
		}
	}

	invalid := []Config{
		{Secret: "short", TurnURLs: []string{"turn:turn.example.com"}},
		{TurnURLs: []string{"turn:turn.example.com"}},
		{Secret: "0123456789abcdef0123456789abcdef"},
		{Secret: "0123456789abcdef0123456789abcdef", TurnURLs: []string{"https://example.com"}},
		{Secret: "0123456789abcdef0123456789abcdef", TurnURLs: []string{"turn:user@example.com"}},
		{Secret: "0123456789abcdef0123456789abcdef", TurnURLs: []string{"turn:example.com:"}},
		{Secret: "0123456789abcdef0123456789abcdef", TurnURLs: []string{"turn:example.com?"}},
		{Secret: "0123456789abcdef0123456789abcdef", TurnURLs: []string{"turn:example.com#"}},
		{Secret: "0123456789abcdef0123456789abcdef", TurnURLs: []string{"turn:example.com?transport=sctp"}},
		{StunURLs: []string{"stun:example.com?transport=udp"}},
		{StunURLs: []string{"stun://example.com"}},
		{StunURLs: []string{"stun:a..example.com"}},
		{StunURLs: []string{"stun:999.999.999.999"}},
	}
	for i, cfg := range invalid {
		if err := cfg.Validate(); err == nil {
			t.Errorf("invalid config %d accepted: %+v", i, cfg)
		}
	}
}

func TestHandlerRejectsWrongMethodAndInvalidConfig(t *testing.T) {
	cfg := Config{Secret: "short", TurnURLs: []string{"turn:example.com"}}
	w := httptest.NewRecorder()
	cfg.Handler()(w, httptest.NewRequest(http.MethodPost, "/api/turn", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", w.Code)
	}
	w = httptest.NewRecorder()
	cfg.Handler()(w, httptest.NewRequest(http.MethodGet, "/api/turn", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("invalid config status = %d, want 500", w.Code)
	}
}

func TestHandlerNoTurnConfigured(t *testing.T) {
	cfg := Config{StunURLs: []string{"stun:198.51.100.1:3478"}}
	if cfg.Enabled() {
		t.Fatal("Enabled() should be false without a secret/urls")
	}
	w := httptest.NewRecorder()
	cfg.Handler()(w, httptest.NewRequest(http.MethodGet, "/api/turn", nil))

	var body struct {
		IceServers []struct {
			Credential string `json:"credential"`
		} `json:"iceServers"`
	}
	json.NewDecoder(w.Body).Decode(&body)
	if len(body.IceServers) != 1 || body.IceServers[0].Credential != "" {
		t.Errorf("expected STUN-only with no credential, got %+v", body.IceServers)
	}
}
