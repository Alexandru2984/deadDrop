package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"deaddrop/internal/auth"
	"deaddrop/internal/signaling"
	"deaddrop/internal/srp"

	"github.com/gorilla/websocket"
)

func TestAllowedOriginsProductionDefault(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", "")
	t.Setenv("ALLOW_LOCAL_ORIGINS", "")
	got, err := allowedOrigins(8088)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://dead.micutu.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowedOrigins = %v, want %v", got, want)
	}
}

func TestLoopbackHostDetection(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "[::1]", "localhost", "LOCALHOST"} {
		if !isLoopbackHost(host) {
			t.Errorf("loopback host %q rejected", host)
		}
	}
	for _, host := range []string{"0.0.0.0", "::", "192.0.2.1", "example.com", "[[::1]]", ""} {
		if isLoopbackHost(host) {
			t.Errorf("public/invalid host %q accepted as loopback", host)
		}
	}
	if got := listenAddress("::1", 8088); got != "[::1]:8088" {
		t.Fatalf("IPv6 listen address = %q", got)
	}
	if got := listenAddress("[::1]", 8088); got != "[::1]:8088" {
		t.Fatalf("bracketed IPv6 listen address = %q", got)
	}
}

func TestAuthenticatedWebSocketIsRevokedAfterLogout(t *testing.T) {
	t.Setenv("OPEN_REGISTRATION", "1")
	authH, err := auth.NewHandler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hub := signaling.NewHub()
	go hub.Run()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/srp/register", authH.SRPRegister)
	mux.HandleFunc("/api/logout", authH.Logout)
	mux.HandleFunc("/ws", authH.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := authH.SessionPrincipal(r)
		signaling.HandleWebSocket(hub, w, r, signaling.ConnectionAccess{
			Principal: principal,
			Valid:     func() bool { return authH.SessionValid(r) },
		})
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	previousOrigins := signaling.AllowedOrigins
	signaling.AllowedOrigins = []string{srv.URL}
	defer func() { signaling.AllowedOrigins = previousOrigins }()

	salt := []byte("0123456789abcdef")
	verifier := srp.Verifier("alice", "stretched-test-secret", salt)
	registration, _ := json.Marshal(map[string]string{
		"username": "alice",
		"salt":     hex.EncodeToString(salt),
		"verifier": verifier.Text(16),
		"kdf":      "pbkdf2:600000",
	})
	response, err := http.Post(srv.URL+"/api/srp/register", "application/json", bytes.NewReader(registration))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || len(response.Cookies()) != 1 {
		t.Fatalf("registration status=%d cookies=%d", response.StatusCode, len(response.Cookies()))
	}
	cookie := response.Cookies()[0]

	header := http.Header{}
	header.Set("Origin", srv.URL)
	header.Set("Cookie", cookie.String())
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var welcome signaling.SignalMessage
	if err := conn.ReadJSON(&welcome); err != nil {
		t.Fatal(err)
	}
	if welcome.Type != "welcome" || len(welcome.PeerID) != signaling.PeerIDHexLen {
		t.Fatalf("invalid welcome: %+v", welcome)
	}

	logoutReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutResp, err := http.DefaultClient.Do(logoutReq)
	if err != nil {
		t.Fatal(err)
	}
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusOK {
		t.Fatalf("logout status=%d", logoutResp.StatusCode)
	}

	if err := conn.WriteJSON(signaling.SignalMessage{Type: "unsupported"}); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("WebSocket survived session revocation")
	}
}

func TestAllowedOriginsExplicitLocalAndOnion(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", "HTTPS://DEAD.MICUTU.COM,http://127.0.0.1:8088,http://exampleexample.onion")
	got, err := allowedOrigins(8088)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://dead.micutu.com",
		"http://127.0.0.1:8088",
		"http://exampleexample.onion",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowedOrigins = %v, want %v", got, want)
	}
}

func TestAllowedOriginsRejectsUnsafeValues(t *testing.T) {
	bad := []string{
		"http://dead.micutu.com",
		"https://dead.micutu.com/path",
		"https://user@dead.micutu.com",
		"https://dead.micutu.com:",
		"https://dead.micutu.com?",
		"https://dead.micutu.com#",
		"https://a..example.com",
		"https://999.999.999.999",
		"http://.onion",
		"*",
		"",
	}
	for _, value := range bad {
		t.Run(strings.ReplaceAll(value, "/", "_"), func(t *testing.T) {
			t.Setenv("ALLOWED_ORIGINS", value)
			t.Setenv("ALLOW_LOCAL_ORIGINS", "")
			if value == "" {
				// Empty means use the safe production default.
				if _, err := allowedOrigins(8088); err != nil {
					t.Fatalf("empty override should use default: %v", err)
				}
				return
			}
			if _, err := allowedOrigins(8088); err == nil {
				t.Fatalf("unsafe origin %q accepted", value)
			}
		})
	}
}
