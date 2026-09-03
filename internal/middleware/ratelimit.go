package middleware

import (
	"log"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxRateLimitVisitors = 50_000

// RateLimiter provides per-IP token-bucket rate limiting.
// saturationNotice keeps a degraded security control from being a silent one,
// without letting the reporting become its own flood: at most one line a minute.
type saturationNotice struct {
	mu   sync.Mutex
	last time.Time
}

func (n *saturationNotice) report(format string, args ...any) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if time.Since(n.last) < time.Minute {
		return
	}
	n.last = time.Now()
	log.Printf(format, args...)
}

type RateLimiter struct {
	saturated         *saturationNotice
	mu                sync.Mutex
	visitors          map[string]*bucket
	rate              int           // tokens added per interval
	burst             int           // max tokens
	interval          time.Duration // refill interval
	lastCapacitySweep time.Time
}

type bucket struct {
	tokens   int
	lastSeen time.Time
}

// NewRateLimiter creates a limiter that allows `rate` requests per `interval`,
// with a burst capacity of `burst`.
func NewRateLimiter(rate, burst int, interval time.Duration) *RateLimiter {
	if rate <= 0 || burst <= 0 || interval <= 0 {
		panic("rate limiter values must be positive")
	}
	rl := &RateLimiter{
		saturated: &saturationNotice{},
		visitors:  make(map[string]*bucket),
		rate:      rate,
		burst:     burst,
		interval:  interval,
	}
	go rl.cleanup()
	return rl
}

// Allow checks whether the given client key has tokens remaining. Callers pass
// an opaque ClientTag, not an address — see clienttag.go.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, exists := rl.visitors[ip]
	now := time.Now()

	if !exists {
		if len(rl.visitors) >= maxRateLimitVisitors {
			if now.Sub(rl.lastCapacitySweep) >= time.Minute {
				rl.cleanupLocked(now)
				rl.lastCapacitySweep = now
			}
			if len(rl.visitors) >= maxRateLimitVisitors {
				// Fail closed, but say so. Turning away every new client is the
				// safe answer and an outage; an operator should not have to
				// infer it from complaints. No key is logged: the table is
				// keyed by an HMAC of the address, and writing those to disk
				// would build the record this service exists not to keep.
				rl.saturated.report("[ratelimit] visitor table full (%d) — refusing all new clients", maxRateLimitVisitors)
				return false
			}
		}
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
		if !rl.Allow(ClientTag(r)) {
			w.Header().Set("Content-Type", "application/json")
			retryAfter := int(math.Ceil(rl.interval.Seconds()))
			if retryAfter < 1 {
				retryAfter = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"too many requests"}`))
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
//
// Requests behind DirectClientBoundary (the Tor listener) share that
// boundary's label instead: their loopback peer is an anonymizing forwarder,
// so neither forwarded headers nor RemoteAddr identify the client.
func ExtractIP(r *http.Request) string {
	if label, ok := directClientLabel(r); ok {
		return label
	}
	if isTrustedProxyRequest(r) {
		if ip, ok := canonicalIP(r.Header.Get("X-Real-IP")); ok {
			return ip
		}
		if ip, ok := canonicalIP(lastForwardedFor(r.Header.Get("X-Forwarded-For"))); ok {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if ip, ok := canonicalIP(r.RemoteAddr); ok {
			return ip
		}
		return r.RemoteAddr
	}
	if ip, ok := canonicalIP(host); ok {
		return ip
	}
	return host
}

func isTrustedProxyRequest(r *http.Request) bool {
	if _, ok := directClientLabel(r); ok {
		return false
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
	// with a separate/container proxy should bind that proxy through loopback or
	// add an explicit CIDR-aware trust policy instead of trusting every peer.
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

func canonicalIP(raw string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

// cleanup removes stale entries every 5 minutes.
func (rl *RateLimiter) cleanup() {
	for range time.NewTicker(5 * time.Minute).C {
		rl.mu.Lock()
		rl.cleanupLocked(time.Now())
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) cleanupLocked(now time.Time) {
	cutoff := now.Add(-10 * time.Minute)
	for ip, b := range rl.visitors {
		if b.lastSeen.Before(cutoff) {
			delete(rl.visitors, ip)
		}
	}
}
