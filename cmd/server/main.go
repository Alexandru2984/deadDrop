package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"deaddrop/internal/auth"
	"deaddrop/internal/middleware"
	"deaddrop/internal/signaling"
	"deaddrop/internal/turn"
)

// inviteDataDir is where invite codes (and other state) live, relative to the
// working directory — the same "data" dir the server uses.
const inviteDataDir = "data"

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
				log.Fatalf("invite: expected a positive count, got %q", sub)
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
			if err := os.WriteFile(args[2], data, 0600); err != nil {
				log.Fatalf("invites export: %v", err)
			}
			fmt.Fprintf(os.Stderr, "exported %d code(s) to %s\n", len(codes), args[2])
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
			raw, err = io.ReadAll(os.Stdin)
		} else {
			raw, err = os.ReadFile(args[2])
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
		log.Fatalf("unknown invites subcommand %q (use: list, export, import)", sub)
	}
}

func main() {
	// CLI subcommands (invite management) run and exit; anything else starts the server.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "invite", "invites":
			runInviteCLI(os.Args[1:])
			return
		}
	}

	// When PORT is set explicitly (production: nginx proxies to a fixed port),
	// bind exactly that port and fail loudly if it's taken — silently drifting to
	// PORT+1 would leave the reverse proxy pointing at nothing. Port hunting is a
	// dev-only convenience for when PORT is unset.
	port := 8088
	portPinned := false
	if p := os.Getenv("PORT"); p != "" {
		v, err := strconv.Atoi(p)
		if err != nil || v < 1 || v > 65535 {
			log.Fatalf("invalid PORT %q", p)
		}
		port = v
		portPinned = true
	}

	// Bind to loopback by default so the Go server is only reachable through the
	// reverse proxy (nginx/Cloudflare). Binding to 0.0.0.0 would let anyone who
	// knows the origin IP bypass the proxy, defeating origin-hiding and the WAF.
	// Override with HOST=0.0.0.0 only for direct local testing.
	host := "127.0.0.1"
	if h := strings.TrimSpace(os.Getenv("HOST")); h != "" {
		host = h
	}
	if !isLoopbackHost(host) && os.Getenv("ALLOW_PUBLIC_BIND") != "1" {
		log.Fatalf("refusing non-loopback HOST=%q without ALLOW_PUBLIC_BIND=1", host)
	}

	// Find an available port without killing existing processes (dev only)
	if !portPinned {
		port = findAvailablePort(host, port)
	}

	// Auth (username + password only, no email or identifying data)
	authH, err := auth.NewHandler("data")
	if err != nil {
		log.Fatalf("auth init: %v", err)
	}

	// Restrict WebSocket origins to prevent CSRF.
	origins, err := allowedOrigins(port)
	if err != nil {
		log.Fatalf("invalid WebSocket origin configuration: %v", err)
	}
	signaling.AllowedOrigins = origins

	hub := signaling.NewHub()
	go hub.Run()

	// Rate limiters: auth = 10 req/min burst 15, WS = 5 conn/min burst 8
	authRL := middleware.NewRateLimiter(10, 15, time.Minute)
	wsRL := middleware.NewRateLimiter(5, 8, time.Minute)

	mux := http.NewServeMux()

	// Legacy bcrypt login — kept ONLY so pre-SRP accounts are not locked out; the
	// client auto-upgrades them to SRP on first login. Open bcrypt registration is
	// gone; new accounts use SRP + an invite code.
	mux.HandleFunc("/api/login", authRL.Wrap(middleware.RequireSameOrigin(authH.Login)))
	mux.HandleFunc("/api/logout", authRL.Wrap(middleware.RequireSameOrigin(authH.Logout)))
	mux.HandleFunc("/api/me", authH.Me)

	// Public client config (no auth) — lets the UI know whether to require an invite.
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"openRegistration":%t}`, auth.OpenRegistration())
	})

	// SRP-6a zero-knowledge auth — the password never reaches the server.
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
		if len(strings.TrimSpace(os.Getenv("ADMIN_TOKEN"))) < 32 {
			log.Fatal("ENABLE_ADMIN_API requires an ADMIN_TOKEN of at least 32 characters")
		}
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
		w.Write([]byte(`{"code":"` + code + `"}`))
	}))))

	// Ephemeral TURN/STUN credentials (auth required; never exposes the secret).
	turnCfg := turn.FromEnv()
	if err := turnCfg.Validate(); err != nil {
		log.Fatalf("invalid TURN configuration: %v", err)
	}
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

	// Static files (always served — auth enforced by JS + WebSocket guard)
	fs := http.FileServer(http.Dir("web"))
	mux.Handle("/", fs)

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

	// Graceful shutdown: drain in-flight requests on SIGINT/SIGTERM instead of
	// dropping connections mid-flight.
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		log.Printf("[server] shutdown signal received, draining…")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("[server] graceful shutdown error: %v", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
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
		candidates = append(candidates,
			fmt.Sprintf("http://localhost:%d", port),
			fmt.Sprintf("http://127.0.0.1:%d", port),
		)
	}
	if raw := strings.TrimSpace(os.Getenv("ALLOWED_ORIGINS")); raw != "" {
		candidates = strings.Split(raw, ",")
	}
	if len(candidates) == 0 || len(candidates) > 16 {
		return nil, fmt.Errorf("expected between 1 and 16 origins")
	}
	origins := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
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
	}
	if len(origins) == 0 {
		return nil, fmt.Errorf("origin list is empty")
	}
	return origins, nil
}

func normalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("%q is not an origin", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	hostname := strings.ToLower(u.Hostname())
	ip := net.ParseIP(hostname)
	if hostname == "" || strings.Contains(hostname, "%") || (ip == nil && !validOriginDNSHostname(hostname)) {
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

func validOriginDNSHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	numeric := true
	for _, c := range host {
		if c < '0' || c > '9' {
			if c != '.' {
				numeric = false
			}
		}
	}
	if numeric { // avoid ambiguous non-canonical IPv4-looking names
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || !isOriginAlphaNum(label[0]) || !isOriginAlphaNum(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !isOriginAlphaNum(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func isOriginAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// findAvailablePort tries the preferred port, then increments up to 100 times.
// Falls back to OS-assigned port if none found. Never kills existing processes.
func findAvailablePort(host string, preferred int) int {
	for port := preferred; port < preferred+100; port++ {
		ln, err := net.Listen("tcp", listenAddress(host, port))
		if err == nil {
			ln.Close()
			return port
		}
	}
	// Let the OS assign a port
	ln, err := net.Listen("tcp", listenAddress(host, 0))
	if err != nil {
		log.Fatal("cannot find any available port")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}
