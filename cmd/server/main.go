package main

import (
	"context"
	"deaddrop/internal/dnsname"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	appassets "deaddrop"
	"deaddrop/internal/auth"
	"deaddrop/internal/middleware"
	"deaddrop/internal/signaling"
	"deaddrop/internal/turn"
)

// inviteDataDir is where invite codes (and other state) live, relative to the
// working directory — the same "data" dir the server uses.
const inviteDataDir = "data"

const maxInviteImportBytes = 4 << 20

func openCLIFileRoot(filename string) (*os.Root, string, error) {
	clean := filepath.Clean(filename)
	name := filepath.Base(clean)
	if name == "." || name == ".." || name == string(filepath.Separator) {
		return nil, "", errors.New("invalid file path")
	}
	root, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return nil, "", err
	}
	return root, name, nil
}

func readBoundedInviteInput(input io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(input, maxInviteImportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxInviteImportBytes {
		return nil, errors.New("invite import exceeds 4 MiB")
	}
	return raw, nil
}

func readInviteImportFile(filename string) ([]byte, error) {
	root, name, err := openCLIFileRoot(filename)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("invite import is not a regular file")
	}
	return readBoundedInviteInput(file)
}

func writeInviteExportFile(filename string, data []byte) (err error) {
	root, name, err := openCLIFileRoot(filename)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	keep := false
	closed := false
	defer func() {
		if !closed {
			if closeErr := file.Close(); err == nil && closeErr != nil {
				err = closeErr
			}
		}
		if !keep {
			_ = root.Remove(name)
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	closeErr := file.Close()
	closed = true
	if closeErr != nil {
		return closeErr
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	if err := dir.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}

// runInviteCLI handles the `invite` / `invites` subcommands and exits. Codes go
// to stdout (pipe-friendly); human status goes to stderr.
//
//	deaddrop invite               mint one code
//	deaddrop invite N             mint N codes
//	deaddrop invites [list]       list unused codes (+ count on stderr)
//	deaddrop invites export [f]   dump codes as JSON to file f (or stdout)
//	deaddrop invites import <f|-> merge codes from file f (or stdin), dedup
func runInviteCLI(args []string) {
	sub := ""
	if len(args) > 1 {
		sub = args[1]
	}

	if args[0] == "invite" {
		n := 1
		if sub != "" {
			v, err := strconv.Atoi(sub)
			if err != nil || v < 1 {
				log.Fatal("invite: expected a positive integer count")
			}
			n = v
		}
		codes, err := auth.GenerateInvitesForDir(inviteDataDir, n)
		if err != nil {
			log.Fatalf("invite: %v", err)
		}
		for _, c := range codes {
			fmt.Println(c)
		}
		return
	}

	switch sub {
	case "", "list":
		codes, err := auth.ListInvitesForDir(inviteDataDir)
		if err != nil {
			log.Fatalf("invites list: %v", err)
		}
		for _, c := range codes {
			fmt.Println(c)
		}
		fmt.Fprintf(os.Stderr, "%d unused invite code(s)\n", len(codes))

	case "export":
		codes, err := auth.ListInvitesForDir(inviteDataDir)
		if err != nil {
			log.Fatalf("invites export: %v", err)
		}
		data, _ := json.MarshalIndent(codes, "", "  ")
		if len(args) > 2 && args[2] != "-" {
			if err := writeInviteExportFile(args[2], data); err != nil {
				log.Fatalf("invites export: %v", err)
			}
			fmt.Fprintf(os.Stderr, "exported %d code(s) to %q\n", len(codes), args[2])
		} else {
			fmt.Println(string(data))
		}

	case "import":
		if len(args) < 3 {
			log.Fatalf("usage: deaddrop invites import <file|->")
		}
		var (
			raw []byte
			err error
		)
		if args[2] == "-" {
			raw, err = readBoundedInviteInput(os.Stdin)
		} else {
			raw, err = readInviteImportFile(args[2])
		}
		if err != nil {
			log.Fatalf("invites import: %v", err)
		}
		added, skipped, err := auth.ImportInvitesForDir(inviteDataDir, auth.ParseInviteCodes(raw))
		if err != nil {
			log.Fatalf("invites import: %v", err)
		}
		fmt.Fprintf(os.Stderr, "imported %d new code(s), skipped %d (malformed or duplicate)\n", added, skipped)

	default:
		log.Fatal("unknown invites subcommand (use: list, export, import)")
	}
}

func main() {
	// CLI subcommands (invite management) run and exit; anything else starts the server.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "invite", "invites":
			runInviteCLI(os.Args[1:])
			return
		case "check-config":
			if err := checkRuntimeConfiguration(); err != nil {
				log.Fatalf("configuration invalid: %v", err)
			}
			fmt.Println("configuration valid")
			return
		case "doctor":
			runDoctor()
			return
		}
	}

	// When PORT is set explicitly (production: nginx proxies to a fixed port),
	// bind exactly that port and fail loudly if it's taken — silently drifting to
	// PORT+1 would leave the reverse proxy pointing at nothing. Port hunting is a
	// dev-only convenience for when PORT is unset.
	port, portPinned, host, err := configuredListenAddress()
	if err != nil {
		log.Fatalf("invalid listen configuration: %v", err)
	}

	// Find an available port without killing existing processes (dev only)
	if !portPinned {
		port = findAvailablePort(host, port)
	}

	// Validate every environment-controlled security setting before touching
	// account state or starting any goroutines.
	origins, turnCfg, err := validateRuntimeEnvironment(port)
	if err != nil {
		log.Fatalf("invalid runtime configuration: %v", err)
	}
	signaling.AllowedOrigins = origins

	onionPort, onionEnabled, err := configuredOnionPort(port)
	if err != nil {
		log.Fatalf("invalid onion listener configuration: %v", err)
	}

	// Auth (username + password only, no email or identifying data)
	authH, err := auth.NewHandler("data")
	if err != nil {
		log.Fatalf("auth init: %v", err)
	}

	warnIfRegistrationIsOpen()

	hub := signaling.NewHub()
	go hub.Run()

	// Rate limiters: auth = 10 req/min burst 15, WS = 5 conn/min burst 8
	authRL := middleware.NewRateLimiter(10, 15, time.Minute)
	wsRL := middleware.NewRateLimiter(5, 8, time.Minute)

	mux := http.NewServeMux()

	mux.HandleFunc("/api/logout", authRL.Wrap(middleware.RequireSameOrigin(authH.Logout)))
	mux.HandleFunc("/api/me", authH.Me)

	// Liveness (no auth). A monitor that only fetches a page proves nginx is up
	// and the process has not exited; it proves nothing about the goroutine that
	// actually routes signaling. Answering here requires a round trip through
	// that goroutine, so a wedged hub fails this while the page still loads.
	//
	// It reports liveness and nothing else on purpose. Room and peer counts are
	// metadata about how many people are using the service and who might be
	// talking right now, and this endpoint is reachable by anyone.
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		done := make(chan struct{})
		go func() {
			hub.Snapshot()
			close(done)
		}()
		select {
		case <-done:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case <-time.After(5 * time.Second):
			// Never hang the monitor: a hub that cannot answer in five seconds is
			// exactly the failure this endpoint exists to report.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"hub unresponsive"}`))
		}
	})

	// Public client config (no auth) — lets the UI know whether to require an invite.
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"openRegistration":%t}`, auth.OpenRegistration())
	})

	// SRP-6a authentication — these routes receive a verifier or proofs. There is
	// no endpoint anywhere that accepts a password, so no server response can talk
	// a client into sending one.
	mux.HandleFunc("/api/srp/register", authRL.Wrap(middleware.RequireSameOrigin(authH.SRPRegister)))
	mux.HandleFunc("/api/srp/challenge", authRL.Wrap(middleware.RequireSameOrigin(authH.SRPChallenge)))
	mux.HandleFunc("/api/srp/authenticate", authRL.Wrap(middleware.RequireSameOrigin(authH.SRPAuthenticate)))

	// Account management (auth enforced inside the handlers).
	mux.HandleFunc("/api/account/verifier", authRL.Wrap(middleware.RequireSameOrigin(authH.SetVerifier)))
	mux.HandleFunc("/api/account/duress", authRL.Wrap(middleware.RequireSameOrigin(authH.SetDuress)))
	mux.HandleFunc("/api/account/delete", authRL.Wrap(middleware.RequireSameOrigin(authH.DeleteAccount)))

	// The network admin endpoint is disabled by default; the local `deaddrop
	// invite` CLI remains available without exposing an Internet attack surface.
	if os.Getenv("ENABLE_ADMIN_API") == "1" {
		mux.HandleFunc("/api/admin/invite", authRL.Wrap(middleware.RequireSameOrigin(authH.GenerateInvite)))
	}

	// Room code generation (server-side for stronger entropy, rate limited)
	mux.HandleFunc("/api/room", authRL.Wrap(middleware.RequireSameOrigin(authH.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		code, err := signaling.GenerateRoomCode()
		if err != nil {
			log.Printf("[room] code generation error: %v", err)
			http.Error(w, "could not create room", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":"` + code + `"}`))
	}))))

	// Ephemeral TURN/STUN credentials (auth required; never exposes the secret).
	if turnCfg.Enabled() {
		log.Printf("[turn] ephemeral TURN credentials enabled (%d url(s))", len(turnCfg.TurnURLs))
	} else {
		log.Printf("[turn] no TURN configured — clients use STUN/host candidates only")
	}
	mux.HandleFunc("/api/turn", authRL.Wrap(middleware.RequireSameOrigin(authH.RequireAuth(turnCfg.Handler()))))

	// WebSocket signaling — requires valid session + rate limited
	mux.HandleFunc("/ws", wsRL.Wrap(authH.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := authH.SessionPrincipal(r)
		signaling.HandleWebSocket(hub, w, r, signaling.ConnectionAccess{
			Principal: principal,
			Valid:     func() bool { return authH.SessionValid(r) },
		})
	})))

	// The audited browser bundle is compiled into the binary. Files edited in
	// the checkout after build time are never served by this process.
	mux.Handle("/", embeddedWebHandler(appassets.WebFS()))

	addr := listenAddress(host, port)
	fmt.Println("┌─────────────────────────────────────────┐")
	fmt.Println("│           💀 DEAD DROP v0.2.0           │")
	fmt.Println("├─────────────────────────────────────────┤")
	fmt.Printf("│  Listening on %-26s│\n", addr)
	fmt.Println("│  Behind nginx → https://dead.micutu.com │")
	fmt.Println("│  Ctrl+C to stop                         │")
	fmt.Println("└─────────────────────────────────────────┘")

	// Wrap entire mux with security headers
	handler := middleware.SecurityHeaders(mux)

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	servers := []*http.Server{server}

	// Dedicated loopback listener for the Tor hidden service. Tor connects from
	// loopback just like nginx, but relays client-written requests verbatim, so
	// this listener must never inherit the proxy-header trust the nginx port
	// gets — DirectClientBoundary pins that down per request.
	if onionEnabled {
		onionServer := &http.Server{
			Addr:              listenAddress("127.0.0.1", onionPort),
			Handler:           middleware.DirectClientBoundary("onion", handler),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    32 << 10,
		}
		servers = append(servers, onionServer)
		log.Printf("[onion] direct listener on %s (forwarded headers untrusted)", onionServer.Addr)
		go func() {
			if err := onionServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Onion listener failed: %v", err)
			}
		}()
	}

	// Graceful shutdown: drain in-flight requests on SIGINT/SIGTERM instead of
	// dropping connections mid-flight.
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		log.Printf("[server] shutdown signal received, draining…")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, s := range servers {
			if err := s.Shutdown(ctx); err != nil {
				log.Printf("[server] graceful shutdown error: %v", err)
			}
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}

func embeddedWebHandler(files fs.FS) http.Handler {
	server := http.FileServer(http.FS(files))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		requestPath := r.URL.Path
		cleanPath := path.Clean(requestPath)
		name := strings.TrimPrefix(cleanPath, "/")
		if requestPath == "/" {
			name = "."
		} else if requestPath == "" || cleanPath != requestPath || strings.HasSuffix(requestPath, "/") {
			http.NotFound(w, r)
			return
		}
		if !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		info, err := fs.Stat(files, name)
		if err != nil || (info.IsDir() && name != ".") {
			http.NotFound(w, r)
			return
		}
		server.ServeHTTP(w, r)
	})
}

// warnIfRegistrationIsOpen reports the disabled invite gate on every start, so a
// development flag left behind in an environment file cannot quietly become the
// production posture.
func warnIfRegistrationIsOpen() {
	if auth.OpenRegistration() {
		log.Printf("[auth] WARNING: OPEN_REGISTRATION=1 — anyone who can reach this server can create an account; invite codes are ignored")
	}
}

func checkRuntimeConfiguration() error {
	port, _, _, err := configuredListenAddress()
	if err != nil {
		return err
	}
	if _, _, err := configuredOnionPort(port); err != nil {
		return err
	}
	_, _, err = validateRuntimeEnvironment(port)
	return err
}

// configuredOnionPort reads ONION_PORT, the loopback-only listener the Tor
// hidden service should target instead of the nginx-facing PORT. It is
// loopback by construction (no HOST/ALLOW_PUBLIC_BIND override) because its
// whole purpose is separating local-forwarder traffic from proxied traffic.
func configuredOnionPort(mainPort int) (int, bool, error) {
	raw := strings.TrimSpace(os.Getenv("ONION_PORT"))
	if raw == "" {
		return 0, false, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 65535 {
		return 0, false, fmt.Errorf("invalid ONION_PORT %q", raw)
	}
	if value == mainPort {
		return 0, false, fmt.Errorf("ONION_PORT must differ from PORT (%d): the Tor listener exists to drop proxy-header trust", mainPort)
	}
	return value, true, nil
}

func configuredListenAddress() (port int, pinned bool, host string, err error) {
	port = 8088
	if raw := strings.TrimSpace(os.Getenv("PORT")); raw != "" {
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil || value < 1 || value > 65535 {
			return 0, false, "", fmt.Errorf("invalid PORT %q", raw)
		}
		port, pinned = value, true
	}
	host = "127.0.0.1"
	if raw := strings.TrimSpace(os.Getenv("HOST")); raw != "" {
		host = raw
	}
	if !strings.EqualFold(host, "localhost") && net.ParseIP(unbracketHost(host)) == nil {
		return 0, false, "", fmt.Errorf("HOST must be an IP literal or localhost")
	}
	if !isLoopbackHost(host) && os.Getenv("ALLOW_PUBLIC_BIND") != "1" {
		return 0, false, "", fmt.Errorf("refusing non-loopback HOST=%q without ALLOW_PUBLIC_BIND=1", host)
	}
	return port, pinned, host, nil
}

func validateRuntimeEnvironment(port int) ([]string, turn.Config, error) {
	for _, name := range []string{"ALLOW_PUBLIC_BIND", "ALLOW_LOCAL_ORIGINS", "ENABLE_ADMIN_API", "OPEN_REGISTRATION"} {
		if raw := strings.TrimSpace(os.Getenv(name)); raw != "" && raw != "0" && raw != "1" {
			return nil, turn.Config{}, fmt.Errorf("%s must be 0 or 1", name)
		}
	}
	if strings.TrimSpace(os.Getenv("TRUST_PROXY_HEADERS")) != "" {
		return nil, turn.Config{}, fmt.Errorf("TRUST_PROXY_HEADERS is unsupported; only loopback proxies are trusted")
	}
	if os.Getenv("ENABLE_ADMIN_API") == "1" && len(strings.TrimSpace(os.Getenv("ADMIN_TOKEN"))) < 32 {
		return nil, turn.Config{}, fmt.Errorf("ENABLE_ADMIN_API requires an ADMIN_TOKEN of at least 32 characters")
	}
	origins, err := allowedOrigins(port)
	if err != nil {
		return nil, turn.Config{}, fmt.Errorf("WebSocket origins: %w", err)
	}
	turnCfg := turn.FromEnv()
	if err := turnCfg.Validate(); err != nil {
		return nil, turn.Config{}, fmt.Errorf("TURN: %w", err)
	}
	return origins, turnCfg, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(unbracketHost(host))
	return ip != nil && ip.IsLoopback()
}

func unbracketHost(host string) string {
	host = strings.TrimSpace(host)
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

func listenAddress(host string, port int) string {
	return net.JoinHostPort(unbracketHost(host), strconv.Itoa(port))
}

func allowedOrigins(port int) ([]string, error) {
	candidates := []string{"https://dead.micutu.com"}
	if os.Getenv("ALLOW_LOCAL_ORIGINS") == "1" {
		candidates = []string{
			fmt.Sprintf("http://localhost:%d", port),
			fmt.Sprintf("http://127.0.0.1:%d", port),
		}
	}
	if raw := strings.TrimSpace(os.Getenv("ALLOWED_ORIGINS")); raw != "" {
		candidates = strings.Split(raw, ",")
	}
	if len(candidates) == 0 || len(candidates) > 16 {
		return nil, fmt.Errorf("expected between 1 and 16 origins")
	}
	origins := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	hasLoopback := false
	hasNonLoopback := false
	for _, candidate := range candidates {
		origin, err := normalizeOrigin(strings.TrimSpace(candidate))
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[origin]; duplicate {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
		if isLoopbackOrigin(origin) {
			hasLoopback = true
		} else {
			hasNonLoopback = true
		}
	}
	if len(origins) == 0 {
		return nil, fmt.Errorf("origin list is empty")
	}
	if hasLoopback && hasNonLoopback {
		return nil, fmt.Errorf("loopback development origins cannot be mixed with deployed origins")
	}
	return origins, nil
}

func isLoopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	hostname := strings.ToLower(u.Hostname())
	if hostname == "localhost" {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

func normalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("%q is not an origin", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	hostname := strings.ToLower(u.Hostname())
	ip := net.ParseIP(hostname)
	if hostname == "" || strings.Contains(hostname, "%") || (ip == nil && !dnsname.Valid(hostname)) {
		return "", fmt.Errorf("%q has an invalid host", raw)
	}
	secureHTTPHost := hostname == "localhost" || strings.HasSuffix(hostname, ".onion")
	if ip != nil && ip.IsLoopback() {
		secureHTTPHost = true
	}
	if scheme != "https" && !(scheme == "http" && secureHTTPHost) {
		return "", fmt.Errorf("%q must use HTTPS (HTTP is limited to loopback/.onion)", raw)
	}
	// url.Parse has already validated a numeric port when Port is accessed.
	if port := u.Port(); port != "" {
		if value, err := strconv.Atoi(port); err != nil || value < 1 || value > 65535 {
			return "", fmt.Errorf("%q has an invalid port", raw)
		}
	}
	return scheme + "://" + strings.ToLower(u.Host), nil
}

// findAvailablePort tries the preferred port, then increments up to 100 times.
// Falls back to OS-assigned port if none found. Never kills existing processes.
func findAvailablePort(host string, preferred int) int {
	for port := preferred; port < preferred+100; port++ {
		ln, err := net.Listen("tcp", listenAddress(host, port))
		if err == nil {
			_ = ln.Close()
			return port
		}
	}
	// Let the OS assign a port
	ln, err := net.Listen("tcp", listenAddress(host, 0))
	if err != nil {
		log.Fatal("cannot find any available port")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}
