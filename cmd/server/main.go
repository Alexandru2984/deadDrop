package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"deaddrop/internal/auth"
	"deaddrop/internal/middleware"
	"deaddrop/internal/signaling"
)

func main() {
	port := 8088
	if p := os.Getenv("PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}

	// Find an available port without killing existing processes
	port = findAvailablePort(port)

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

	// Auth API (rate limited)
	mux.HandleFunc("/api/register", authRL.Wrap(middleware.RequireSameOrigin(authH.Register)))
	mux.HandleFunc("/api/login", authRL.Wrap(middleware.RequireSameOrigin(authH.Login)))
	mux.HandleFunc("/api/logout", authRL.Wrap(middleware.RequireSameOrigin(authH.Logout)))
	mux.HandleFunc("/api/me", authH.Me)

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

	// WebSocket signaling — requires valid session + rate limited
	mux.HandleFunc("/ws", wsRL.Wrap(authH.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		signaling.HandleWebSocket(hub, w, r)
	})))

	// Static files (always served — auth enforced by JS + WebSocket guard)
	fs := http.FileServer(http.Dir("web"))
	mux.Handle("/", fs)

	addr := fmt.Sprintf(":%d", port)
	fmt.Println("┌─────────────────────────────────────────┐")
	fmt.Println("│           💀 DEAD DROP v0.1.0           │")
	fmt.Println("├─────────────────────────────────────────┤")
	fmt.Printf("│  Server: http://localhost%-15s │\n", addr)
	fmt.Println("│  Open in two browser tabs to chat       │")
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

	if err := server.ListenAndServe(); err != nil {
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
func findAvailablePort(preferred int) int {
	for port := preferred; port < preferred+100; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err == nil {
			ln.Close()
			return port
		}
	}
	// Let the OS assign a port
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatal("cannot find any available port")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}
