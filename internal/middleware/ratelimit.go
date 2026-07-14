package middleware

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// RateLimiter provides per-IP token-bucket rate limiting.
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*bucket
	rate     int           // tokens added per interval
	burst    int           // max tokens
	interval time.Duration // refill interval
}

type bucket struct {
	tokens   int
	lastSeen time.Time
}

// NewRateLimiter creates a limiter that allows `rate` requests per `interval`,
// with a burst capacity of `burst`.
func NewRateLimiter(rate, burst int, interval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*bucket),
		rate:     rate,
		burst:    burst,
		interval: interval,
	}
	go rl.cleanup()
	return rl
}

// Allow checks whether the IP has tokens remaining.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, exists := rl.visitors[ip]
	now := time.Now()

	if !exists {
		rl.visitors[ip] = &bucket{tokens: rl.burst - 1, lastSeen: now}
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastSeen)
	refill := int(elapsed/rl.interval) * rl.rate
	if refill > 0 {
		b.tokens += refill
		if b.tokens > rl.burst {
			b.tokens = rl.burst
		}
		b.lastSeen = now
	}

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// Wrap returns HTTP middleware that rejects over-limit requests with 429.
func (rl *RateLimiter) Wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := ExtractIP(r)
		if !rl.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"too many requests"}`))
			return
		}
		next(w, r)
	}
}

// ExtractIP returns the client IP from the request.
//
// The reverse proxy is expected to overwrite X-Real-IP with its normalized
// client address. In production nginx does this after applying its trusted
// Cloudflare real-ip list. We deliberately do not consume CF-Connecting-IP
// here: a client reaching the origin directly can supply that header itself.
// As a safe fallback, use the right-most X-Forwarded-For hop (the one appended
// by the nearest proxy), never the attacker-controlled left-most hop.
func ExtractIP(r *http.Request) string {
	if isTrustedProxyRequest(r) {
		if ip := r.Header.Get("X-Real-IP"); validIP(ip) {
			return strings.TrimSpace(ip)
		}
		if ip := lastForwardedFor(r.Header.Get("X-Forwarded-For")); validIP(ip) {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isTrustedProxyRequest(r *http.Request) bool {
	if os.Getenv("TRUST_PROXY_HEADERS") == "1" {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	// The supported production layout has nginx on the same host. Deployments
	// with a separate/container proxy must opt in explicitly after ensuring that
	// proxy overwrites, rather than appends, the normalized client header.
	return ip.IsLoopback()
}

func lastForwardedFor(value string) string {
	parts := strings.Split(value, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if ip := strings.TrimSpace(parts[i]); ip != "" {
			return ip
		}
	}
	return ""
}

func validIP(ip string) bool {
	return net.ParseIP(strings.TrimSpace(ip)) != nil
}

// cleanup removes stale entries every 5 minutes.
func (rl *RateLimiter) cleanup() {
	for range time.NewTicker(5 * time.Minute).C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for ip, b := range rl.visitors {
			if b.lastSeen.Before(cutoff) {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}
