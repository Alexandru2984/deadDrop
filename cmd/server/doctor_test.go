package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// An edge that rewrites the page has replaced the cryptography, and the origin
// cannot tell. The whole value of the check is that it notices — so it has to be
// watched noticing.
func TestCompareDeliveryDetectsARewrittenPage(t *testing.T) {
	page := `<!doctype html><script src="js/app.js" integrity="sha256-abc"></script>`
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	defer origin.Close()

	// One extra script tag: the whole attack, and invisible to anything that
	// only checks that the site is up.
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(page + `<script src="//cdn.example/analytics.js"></script>`))
	}))
	defer edge.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	same := compareDelivery(client, origin.URL, origin.URL, []string{"/"})
	if same.err != nil {
		t.Fatalf("identical responses reported a problem: %v", same.err)
	}

	rewritten := compareDelivery(client, origin.URL, edge.URL, []string{"/"})
	if rewritten.err == nil {
		t.Fatal("a rewritten page was not detected")
	}
	if rewritten.warn {
		t.Fatal("a rewritten page must fail, not warn")
	}
	if !strings.Contains(rewritten.err.Error(), "rewriting") {
		t.Fatalf("unhelpful message: %v", rewritten.err)
	}
}

// Being unable to reach the public URL is ordinary — split-horizon DNS, an
// egress firewall — and must not be reported as tampering.
func TestCompareDeliveryWarnsWhenTheEdgeIsUnreachable(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer origin.Close()

	got := compareDelivery(&http.Client{Timeout: time.Second},
		origin.URL, "http://127.0.0.1:1", []string{"/"})
	if got.err == nil || !got.warn {
		t.Fatalf("expected a warning, got err=%v warn=%v", got.err, got.warn)
	}
}

func TestPublicOriginSkipsLoopbackAndOnion(t *testing.T) {
	for _, tc := range []struct{ env, want string }{
		{"https://dead.example.com,http://abc.onion", "https://dead.example.com"},
		{"http://abc.onion,https://dead.example.com", "https://dead.example.com"},
		{"http://127.0.0.1:8100", ""},
		{"http://abc.onion", ""},
		{"", ""},
		{"https://dead.example.com/", "https://dead.example.com"},
	} {
		t.Setenv("ALLOWED_ORIGINS", tc.env)
		if got := publicOrigin(); got != tc.want {
			t.Errorf("publicOrigin(%q) = %q, want %q", tc.env, got, tc.want)
		}
	}
	_ = os.Unsetenv("ALLOWED_ORIGINS")
}
