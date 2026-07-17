package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	appassets "deaddrop"
	"deaddrop/internal/auth"
	"deaddrop/internal/signaling"
	"deaddrop/internal/srp"

	"github.com/gorilla/websocket"
)

func TestInviteCLIFileIOIsBoundedAndDoesNotClobber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invites.json")
	want := []byte(`["DD-AAAA-BBBB-CCCC"]`)
	if err := writeInviteExportFile(path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("export mode = %o, want 600", got)
	}
	got, err := readInviteImportFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("read export = %q, %v", got, err)
	}
	if err := writeInviteExportFile(path, []byte("replacement")); err == nil {
		t.Fatal("export overwrote an existing file")
	}
	got, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("failed export changed file = %q, %v", got, err)
	}
	tooLarge := bytes.NewReader(make([]byte, maxInviteImportBytes+1))
	if _, err := readBoundedInviteInput(tooLarge); err == nil {
		t.Fatal("oversized invite input was accepted")
	}
}

func TestInviteCLIImportCannotFollowLinkOutsideSelectedRoot(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "import.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := readInviteImportFile(link); err == nil {
		t.Fatal("import followed a symlink outside its selected directory")
	}
}

func TestEmbeddedWebHandlerIsBoundedAndReadOnly(t *testing.T) {
	h := embeddedWebHandler(appassets.WebFS())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET / status=%d", w.Code)
	}
	body, _ := io.ReadAll(w.Result().Body)
	if !bytes.Contains(body, []byte("Dead Drop")) {
		t.Fatal("embedded index was not served")
	}

	for _, target := range []string{"/js/", "/../index.html", "/missing"} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s status=%d, want 404", target, w.Code)
		}
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST / status=%d Allow=%q", w.Code, w.Header().Get("Allow"))
	}
}

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

func TestRuntimeEnvironmentFailsClosed(t *testing.T) {
	for _, name := range []string{
		"ALLOWED_ORIGINS", "ALLOW_LOCAL_ORIGINS", "ALLOW_PUBLIC_BIND",
		"ENABLE_ADMIN_API", "ADMIN_TOKEN", "OPEN_REGISTRATION",
		"TRUST_PROXY_HEADERS", "TURN_SECRET", "TURN_URLS", "STUN_URLS",
	} {
		t.Setenv(name, "")
	}
	if _, _, err := validateRuntimeEnvironment(8088); err != nil {
		t.Fatalf("safe defaults rejected: %v", err)
	}

	t.Setenv("TRUST_PROXY_HEADERS", "1")
	if _, _, err := validateRuntimeEnvironment(8088); err == nil {
		t.Fatal("obsolete trust-all proxy switch was accepted")
	}
	t.Setenv("TRUST_PROXY_HEADERS", "")
	t.Setenv("ENABLE_ADMIN_API", "1")
	t.Setenv("ADMIN_TOKEN", "short")
	if _, _, err := validateRuntimeEnvironment(8088); err == nil {
		t.Fatal("network admin API accepted a weak token")
	}
	t.Setenv("ENABLE_ADMIN_API", "maybe")
	if _, _, err := validateRuntimeEnvironment(8088); err == nil {
		t.Fatal("invalid boolean environment value was accepted")
	}
}

func TestConfiguredListenAddressRequiresPublicOptIn(t *testing.T) {
	t.Setenv("PORT", "8100")
	t.Setenv("HOST", "0.0.0.0")
	t.Setenv("ALLOW_PUBLIC_BIND", "")
	if _, _, _, err := configuredListenAddress(); err == nil {
		t.Fatal("public bind was accepted without explicit opt-in")
	}
	t.Setenv("ALLOW_PUBLIC_BIND", "1")
	port, pinned, host, err := configuredListenAddress()
	if err != nil || port != 8100 || !pinned || host != "0.0.0.0" {
		t.Fatalf("explicit public bind parsed as port=%d pinned=%t host=%q err=%v", port, pinned, host, err)
	}
	t.Setenv("HOST", "example.com")
	if _, _, _, err := configuredListenAddress(); err == nil {
		t.Fatal("hostname bind was accepted instead of an explicit IP literal")
	}
}

func TestConfiguredOnionPortValidation(t *testing.T) {
	t.Setenv("ONION_PORT", "")
	if _, enabled, err := configuredOnionPort(8100); err != nil || enabled {
		t.Fatalf("unset ONION_PORT: enabled=%t err=%v, want disabled", enabled, err)
	}
	t.Setenv("ONION_PORT", "8101")
	port, enabled, err := configuredOnionPort(8100)
	if err != nil || !enabled || port != 8101 {
		t.Fatalf("valid ONION_PORT parsed as port=%d enabled=%t err=%v", port, enabled, err)
	}
	for _, invalid := range []string{"8100", "0", "70000", "nope"} {
		t.Setenv("ONION_PORT", invalid)
		if _, _, err := configuredOnionPort(8100); err == nil {
			t.Fatalf("ONION_PORT=%q was accepted", invalid)
		}
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
	t.Setenv("ALLOWED_ORIGINS", "HTTPS://DEAD.MICUTU.COM,http://exampleexample.onion")
	got, err := allowedOrigins(8088)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://dead.micutu.com",
		"http://exampleexample.onion",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowedOrigins = %v, want %v", got, want)
	}
}

func TestAllowedOriginsLocalDevelopmentMode(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", "")
	t.Setenv("ALLOW_LOCAL_ORIGINS", "1")
	got, err := allowedOrigins(8088)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http://localhost:8088", "http://127.0.0.1:8088"}
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
		"https://dead.micutu.com,http://127.0.0.1:8088",
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
