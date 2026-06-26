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
// Reverse proxy headers are trusted only when the direct peer is local/private
// or TRUST_PROXY_HEADERS=1 is set. This prevents public clients from spoofing
// X-Forwarded-For to bypass rate limits if the Go port is reachable directly.
func ExtractIP(r *http.Request) string {
	if isTrustedProxyRequest(r) {
		if ip := r.Header.Get("CF-Connecting-IP"); validIP(ip) {
			return strings.TrimSpace(ip)
		}
		if ip := firstForwardedFor(r.Header.Get("X-Forwarded-For")); validIP(ip) {
			return ip
		}
		if ip := r.Header.Get("X-Real-IP"); validIP(ip) {
			return strings.TrimSpace(ip)
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
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func firstForwardedFor(value string) string {
	for _, part := range strings.Split(value, ",") {
		if ip := strings.TrimSpace(part); ip != "" {
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
