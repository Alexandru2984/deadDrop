package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRateLimiterAllows(t *testing.T) {
	rl := NewRateLimiter(5, 5, time.Minute)

	for i := 0; i < 5; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied
	if rl.Allow("1.2.3.4") {
		t.Fatal("6th request should be denied")
	}
}

func TestRateLimiterDifferentIPs(t *testing.T) {
	rl := NewRateLimiter(2, 2, time.Minute)

	// IP A uses all tokens
	rl.Allow("1.1.1.1")
	rl.Allow("1.1.1.1")
	if rl.Allow("1.1.1.1") {
		t.Fatal("IP A should be exhausted")
	}

	// IP B should still work
	if !rl.Allow("2.2.2.2") {
		t.Fatal("IP B should have tokens")
	}
}

func TestRateLimiterRefill(t *testing.T) {
	rl := NewRateLimiter(1, 1, 50*time.Millisecond)

	// Use the token
	rl.Allow("1.1.1.1")
	if rl.Allow("1.1.1.1") {
		t.Fatal("should be denied immediately")
	}

	// Wait for refill
	time.Sleep(60 * time.Millisecond)
	if !rl.Allow("1.1.1.1") {
		t.Fatal("should be allowed after refill")
	}
}

func TestRateLimiterWrap429(t *testing.T) {
	rl := NewRateLimiter(1, 1, time.Minute)

	handler := rl.Wrap(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First request succeeds
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first request expected 200, got %d", w.Code)
	}

	// Second request gets 429
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request expected 429, got %d", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "60" {
		t.Fatalf("Retry-After = %q, want 60", got)
	}
}

func TestRateLimiterVisitorMapIsBounded(t *testing.T) {
	rl := NewRateLimiter(1, 1, time.Minute)
	now := time.Now()
	rl.mu.Lock()
	for i := 0; i < maxRateLimitVisitors; i++ {
		rl.visitors[strconv.Itoa(i)] = &bucket{tokens: 1, lastSeen: now}
	}
	rl.lastCapacitySweep = now
	rl.mu.Unlock()
	if rl.Allow("new-visitor") {
		t.Fatal("limiter accepted a new visitor beyond its memory cap")
	}

	rl.mu.Lock()
	rl.visitors["0"].lastSeen = now.Add(-11 * time.Minute)
	rl.lastCapacitySweep = time.Time{}
	rl.mu.Unlock()
	if !rl.Allow("new-visitor") {
		t.Fatal("limiter did not reclaim stale capacity")
	}
}

func TestRateLimiterRejectsInvalidConfiguration(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("invalid limiter configuration did not panic")
		}
	}()
	_ = NewRateLimiter(0, 1, time.Minute)
}

func TestSecurityHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	expected := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
		"Cache-Control":             "no-store, no-transform",
	}
	for k, v := range expected {
		if got := w.Header().Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("expected Content-Security-Policy header")
	}
	// Privacy-first CSP must not leak to external origins or allow inline scripts.
	if strings.Contains(csp, "http://") || strings.Contains(csp, "https://") {
		t.Errorf("CSP should not reference external origins: %q", csp)
	}
	if strings.Contains(csp, "'unsafe-inline'") {
		t.Errorf("CSP must not allow inline scripts or styles: %q", csp)
	}
	if !strings.Contains(csp, "style-src 'self';") {
		t.Errorf("CSP should restrict styles to same-origin stylesheets: %q", csp)
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name      string
		xReal     string
		xFwd      string
		cfConnect string
		remote    string
		expected  string
	}{
		{"normalized X-Real-IP", "10.0.0.1", "", "203.0.113.99", "127.0.0.1:1234", "10.0.0.1"},
		{"right-most X-Forwarded-For", "", "198.51.100.10, 10.0.0.3", "", "127.0.0.1:1234", "10.0.0.3"},
		{"CF header never trusted directly", "", "", "203.0.113.99", "127.0.0.1:1234", "127.0.0.1"},
		{"RemoteAddr", "", "", "", "192.168.1.1:5678", "192.168.1.1"},
		{"Untrusted public proxy header ignored", "", "10.0.0.2", "", "8.8.8.8:5678", "8.8.8.8"},
		{"Private peer is not implicitly trusted", "10.0.0.2", "", "", "192.168.1.7:5678", "192.168.1.7"},
		{"IPv4-mapped address is canonicalized", "::ffff:192.0.2.9", "", "", "127.0.0.1:1234", "192.0.2.9"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TRUST_PROXY_HEADERS", "")
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remote
			if tt.xReal != "" {
				req.Header.Set("X-Real-IP", tt.xReal)
			}
			if tt.xFwd != "" {
				req.Header.Set("X-Forwarded-For", tt.xFwd)
			}
			if tt.cfConnect != "" {
				req.Header.Set("CF-Connecting-IP", tt.cfConnect)
			}
			got := ExtractIP(req)
			if got != tt.expected {
				t.Errorf("ExtractIP = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestDirectClientBoundaryNeutralizesForwardedHeaders(t *testing.T) {
	var gotIP string
	var gotSecure bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP = ExtractIP(r)
		gotSecure = IsSecureRequest(r)
	})

	// A Tor visitor writes the request themselves: loopback peer plus fully
	// attacker-chosen forwarded headers.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	req.Header.Set("X-Real-IP", "203.0.113.7")
	req.Header.Set("X-Forwarded-For", "198.51.100.20, 203.0.113.8")
	req.Header.Set("X-Forwarded-Proto", "https")
	DirectClientBoundary("onion", inner).ServeHTTP(httptest.NewRecorder(), req)

	if gotIP != "onion" {
		t.Errorf("ExtractIP behind boundary = %q, want label %q", gotIP, "onion")
	}
	if gotSecure {
		t.Error("spoofed X-Forwarded-Proto was trusted behind the direct-client boundary")
	}
}

func TestDirectClientBoundarySharesOneRateBucket(t *testing.T) {
	rl := NewRateLimiter(1, 1, time.Minute)
	limited := DirectClientBoundary("onion", rl.Wrap(func(w http.ResponseWriter, r *http.Request) {}))

	// Rotating spoofed identities must not mint fresh buckets on this listener.
	for i, spoofed := range []string{"203.0.113.1", "203.0.113.2"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:4321"
		req.Header.Set("X-Real-IP", spoofed)
		rec := httptest.NewRecorder()
		limited.ServeHTTP(rec, req)
		if i == 0 && rec.Code != http.StatusOK {
			t.Fatalf("first request = %d, want 200", rec.Code)
		}
		if i == 1 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("second request with rotated X-Real-IP = %d, want 429", rec.Code)
		}
	}
}

func TestRequireSameOrigin(t *testing.T) {
	called := false
	handler := RequireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "https://dead.micutu.com/api/logout", nil)
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if called {
		t.Fatal("handler should not be called for cross-origin request")
	}

	called = false
	req = httptest.NewRequest(http.MethodPost, "https://dead.micutu.com/api/logout", nil)
	req.Header.Set("Origin", "https://dead.micutu.com")
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if !called {
		t.Fatal("handler should be called for same-origin request")
	}

	// Same host over a different scheme is cross-origin and must not pass.
	called = false
	req = httptest.NewRequest(http.MethodPost, "https://dead.micutu.com/api/logout", nil)
	req.Header.Set("Origin", "http://dead.micutu.com")
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusForbidden || called {
		t.Fatal("scheme-mismatched origin must be rejected")
	}

	// nginx terminates TLS and supplies the external scheme from loopback.
	called = false
	req = httptest.NewRequest(http.MethodPost, "http://dead.micutu.com/api/logout", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Origin", "https://dead.micutu.com")
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusNoContent || !called {
		t.Fatal("trusted proxy HTTPS origin should be accepted")
	}

	// A public client cannot spoof the forwarded scheme.
	called = false
	req = httptest.NewRequest(http.MethodPost, "http://dead.micutu.com/api/logout", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Origin", "https://dead.micutu.com")
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusForbidden || called {
		t.Fatal("untrusted forwarded scheme must be ignored")
	}
}
