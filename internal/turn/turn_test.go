package turn

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestHandlerMintsValidEphemeralCredential(t *testing.T) {
	cfg := Config{
		Secret:   "test-secret",
		TurnURLs: []string{"turn:198.51.100.1:3478?transport=udp"},
		StunURLs: []string{"stun:198.51.100.1:3478"},
	}
	w := httptest.NewRecorder()
	cfg.Handler()(w, httptest.NewRequest(http.MethodGet, "/api/turn", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
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
	exp, err := strconv.ParseInt(turn.Username, 10, 64)
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
