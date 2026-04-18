package middleware

import (
	"net/http"
	"net/http/httptest"
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
		"X-Frame-Options":          "DENY",
		"Referrer-Policy":          "no-referrer",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
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
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name     string
		xReal    string
		xFwd     string
		remote   string
		expected string
	}{
		{"X-Real-IP", "10.0.0.1", "", "127.0.0.1:1234", "10.0.0.1"},
		{"X-Forwarded-For", "", "10.0.0.2", "127.0.0.1:1234", "10.0.0.2"},
		{"RemoteAddr", "", "", "192.168.1.1:5678", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remote
			if tt.xReal != "" {
				req.Header.Set("X-Real-IP", tt.xReal)
			}
			if tt.xFwd != "" {
				req.Header.Set("X-Forwarded-For", tt.xFwd)
			}
			got := ExtractIP(req)
			if got != tt.expected {
				t.Errorf("ExtractIP = %q, want %q", got, tt.expected)
			}
		})
	}
}
