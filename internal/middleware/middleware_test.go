package middleware

import (
	"net"
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

// Sec-Fetch-Site is written by the browser and is unreachable from page script,
// so it must be able to refuse a cross-site state change on its own — even when
// Origin and Referer look agreeable.
func TestRequireSameOriginHonoursSecFetchMetadata(t *testing.T) {
	newReq := func(site, mode, origin string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://dead.micutu.com/api/logout", nil)
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		if mode != "" {
			r.Header.Set("Sec-Fetch-Mode", mode)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}

	cases := []struct {
		name             string
		site, mode, orig string
		want             int
	}{
		{"same-origin fetch passes", "same-origin", "cors", "https://dead.micutu.com", http.StatusNoContent},
		{"cross-site is refused", "cross-site", "cors", "https://dead.micutu.com", http.StatusForbidden},
		{"same-site is refused", "same-site", "cors", "https://dead.micutu.com", http.StatusForbidden},
		{"none is refused", "none", "cors", "https://dead.micutu.com", http.StatusForbidden},
		{"navigate mode is refused", "same-origin", "navigate", "https://dead.micutu.com", http.StatusForbidden},
		{"no-cors mode is refused", "same-origin", "no-cors", "https://dead.micutu.com", http.StatusForbidden},
		{"absent metadata falls back to Origin", "", "", "https://dead.micutu.com", http.StatusNoContent},
		{"absent metadata still rejects a foreign Origin", "", "", "https://evil.example", http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := RequireSameOrigin(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})
			w := httptest.NewRecorder()
			handler(w, newReq(tc.site, tc.mode, tc.orig))
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d", w.Code, tc.want)
			}
		})
	}
}

// The rate limiter and login lockout must be able to tell clients apart without
// their maps becoming a standing list of who used the service.
func TestClientTagIsStableOpaqueAndPerSource(t *testing.T) {
	req := func(remote, realIP string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if realIP != "" {
			r.Header.Set("X-Real-IP", realIP)
		}
		return r
	}

	a := ClientTag(req("203.0.113.7:1111", ""))
	again := ClientTag(req("203.0.113.7:2222", ""))
	if a != again {
		t.Fatal("tag is not stable for the same source address")
	}
	if b := ClientTag(req("203.0.113.8:1111", "")); a == b {
		t.Fatal("two different sources share a tag")
	}
	if strings.Contains(a, "203.0.113") || strings.Contains(a, "113.7") {
		t.Fatalf("tag leaks the address it was derived from: %q", a)
	}
	if len(a) != 32 {
		t.Fatalf("tag length = %d, want 32 hex chars", len(a))
	}

	// The proxy boundary still decides which address is tagged.
	viaProxy := ClientTag(req("127.0.0.1:9", "198.51.100.4"))
	direct := ClientTag(req("198.51.100.4:9", ""))
	if viaProxy != direct {
		t.Fatal("a trusted proxy's forwarded address produced a different tag")
	}

	// One IPv6 subscriber holds a whole /64; rotating through it must not
	// mint fresh rate-limit and lockout identities.
	v6a := ClientTag(req("[2001:db8:1:2::1]:1", ""))
	v6b := ClientTag(req("[2001:db8:1:2:ffff:abcd:1234:9]:1", ""))
	if v6a != v6b {
		t.Fatal("two addresses in one IPv6 /64 received different tags")
	}
	if v6c := ClientTag(req("[2001:db8:1:3::1]:1", "")); v6c == v6a {
		t.Fatal("neighbouring IPv6 /64s share a tag")
	}
	if mapped := ClientTag(req("127.0.0.1:9", "::ffff:198.51.100.4")); mapped != direct {
		t.Fatal("an IPv4-mapped address was not treated as its IPv4 address")
	}

	// Requests behind the onion boundary share one tag by design.
	onionReq := req("127.0.0.1:9", "203.0.113.99")
	var onionA, onionB string
	DirectClientBoundary("onion", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		onionA = ClientTag(r)
	})).ServeHTTP(httptest.NewRecorder(), onionReq)
	other := req("127.0.0.1:9", "203.0.113.1")
	DirectClientBoundary("onion", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		onionB = ClientTag(r)
	})).ServeHTTP(httptest.NewRecorder(), other)
	if onionA != onionB {
		t.Fatal("onion clients did not share a single tag")
	}
}

func TestOnionLocationAdvertisesSamePath(t *testing.T) {
	onion := "http://" + strings.Repeat("a", 56) + ".onion"
	h := OnionLocation(onion, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/about.html?x=1", nil))
	if got := rec.Header().Get("Onion-Location"); got != onion+"/about.html?x=1" {
		t.Fatalf("Onion-Location = %q", got)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/logout", nil))
	if got := rec.Header().Get("Onion-Location"); got != "" {
		t.Fatalf("a state-changing request was advertised: %q", got)
	}
}

func TestParseProxyLineAcceptsOnlyTorCircuits(t *testing.T) {
	id, err := parseProxyLine("PROXY TCP6 fc00:dead:beef:4dad::1:2 ::1 65535 42\r\n")
	if err != nil || id != "65538" {
		t.Fatalf("tor header: id=%q err=%v", id, err)
	}
	for _, bad := range []string{
		"PROXY TCP6 fc00:dead:beef:4dad::1:2 ::1 65535 42\n", // no CR
		"PROXY TCP4 127.0.0.1 127.0.0.1 1 2\r\n",             // not tor's form
		"PROXY TCP6 2001:db8::1 ::1 65535 42\r\n",            // outside the circuit range
		"PROXY TCP6 fc00:dead:beef:4dad::1 ::1 65536 42\r\n", // port out of range
		"PROXY TCP6 fc00:dead:beef:4dad::1 ::1 0080 42\r\n",  // non-canonical port
		"PROXY TCP6 fc00:dead:beef:4dad::1  ::1 1 42\r\n",    // double space
		"PROXY UNKNOWN\r\n",
		"GET / HTTP/1.1\r\n",
		"",
	} {
		if _, err := parseProxyLine(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestProxyListenerSeparatesCircuits(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tags := make(chan string, 4)
	srv := &http.Server{
		Handler: DirectClientBoundary("onion", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tags <- ClientTag(r)
		})),
		ConnContext:       OnionConnContext,
		ReadHeaderTimeout: 2 * time.Second,
	}
	go func() { _ = srv.Serve(ProxyProtocolListener(ln)) }()
	defer srv.Close()

	send := func(header string) (string, bool) {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(header + "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 200") {
			return "", false
		}
		select {
		case tag := <-tags:
			return tag, true
		case <-time.After(time.Second):
			return "", false
		}
	}
	a, okA := send("PROXY TCP6 fc00:dead:beef:4dad::1 ::1 65535 42\r\n")
	b, okB := send("PROXY TCP6 fc00:dead:beef:4dad::2 ::1 65535 42\r\n")
	again, okAgain := send("PROXY TCP6 fc00:dead:beef:4dad::1 ::1 65535 42\r\n")
	if !okA || !okB || !okAgain {
		t.Fatal("a well-formed tor connection was not served")
	}
	if a == b {
		t.Fatal("two circuits shared a rate-limit tag")
	}
	if a != again {
		t.Fatal("one circuit received two different tags")
	}
	if _, served := send(""); served {
		t.Fatal("a connection without a PROXY header was served")
	}
}

func TestOnionCeilingCapsUnsafeRequestsOnly(t *testing.T) {
	h := OnionCeiling(NewRateLimiter(1, 1, time.Hour), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	codes := []int{}
	for _, method := range []string{http.MethodPost, http.MethodPost, http.MethodGet} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/api/srp/challenge", nil))
		codes = append(codes, rec.Code)
	}
	if codes[0] != 200 || codes[1] != 429 || codes[2] != 200 {
		t.Fatalf("codes = %v, want [200 429 200]", codes)
	}
}
