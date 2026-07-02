package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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
		if err != nil {
			log.Fatalf("invalid PORT %q: %v", p, err)
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
	signaling.AllowedOrigins = allowedOrigins(port)

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

	// Admin: issue single-use invite codes (X-Admin-Token header).
	mux.HandleFunc("/api/admin/invite", authRL.Wrap(authH.GenerateInvite))

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
	if turnCfg.Enabled() {
		log.Printf("[turn] ephemeral TURN credentials enabled (%d url(s))", len(turnCfg.TurnURLs))
	} else {
		log.Printf("[turn] no TURN configured — clients use STUN/host candidates only")
	}
	mux.HandleFunc("/api/turn", authRL.Wrap(middleware.RequireSameOrigin(authH.RequireAuth(turnCfg.Handler()))))

	// WebSocket signaling — requires valid session + rate limited
	mux.HandleFunc("/ws", wsRL.Wrap(authH.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		signaling.HandleWebSocket(hub, w, r)
	})))

	// Static files (always served — auth enforced by JS + WebSocket guard)
	fs := http.FileServer(http.Dir("web"))
	mux.Handle("/", fs)

	addr := fmt.Sprintf("%s:%d", host, port)
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

func allowedOrigins(port int) []string {
	origins := []string{
		"https://dead.micutu.com",
		"http://dead.micutu.com",
		fmt.Sprintf("http://localhost:%d", port),
		fmt.Sprintf("http://127.0.0.1:%d", port),
	}
	if raw := os.Getenv("ALLOWED_ORIGINS"); raw != "" {
		origins = origins[:0]
		for _, part := range strings.Split(raw, ",") {
			if origin := strings.TrimSpace(part); origin != "" {
				origins = append(origins, origin)
			}
		}
	}
	return origins
}

// findAvailablePort tries the preferred port, then increments up to 100 times.
// Falls back to OS-assigned port if none found. Never kills existing processes.
func findAvailablePort(host string, preferred int) int {
	for port := preferred; port < preferred+100; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
		if err == nil {
			ln.Close()
			return port
		}
	}
	// Let the OS assign a port
	ln, err := net.Listen("tcp", host+":0")
	if err != nil {
		log.Fatal("cannot find any available port")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}
