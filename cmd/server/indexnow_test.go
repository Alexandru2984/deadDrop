package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestIndexNowKeyIsWellFormedOrAbsent(t *testing.T) {
	for _, bad := range []string{"short", "../../etc/passwd", "key with spaces", strings.Repeat("a", 129)} {
		t.Setenv("INDEXNOW_KEY", bad)
		if _, err := indexNowKey(); err == nil {
			t.Errorf("INDEXNOW_KEY %q accepted", bad)
		}
	}
	t.Setenv("INDEXNOW_KEY", "")
	if key, err := indexNowKey(); key != "" || err != nil {
		t.Fatalf("unset key = %q, %v", key, err)
	}
	t.Setenv("INDEXNOW_KEY", " sample-indexnow-key ")
	if key, err := indexNowKey(); key != "sample-indexnow-key" || err != nil {
		t.Fatalf("valid key = %q, %v", key, err)
	}
}

func TestIndexNowKeyFileHoldsOnlyTheKey(t *testing.T) {
	handler := indexNowKeyHandler("test-indexnow-key")
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/test-indexnow-key.txt", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "test-indexnow-key" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("key file = %d %q %q", rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
	}
	rec = httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, "/test-indexnow-key.txt", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST to the key file = %d", rec.Code)
	}
}

// The site and the IndexNow endpoint, played by one server: it serves whatever
// key file it is given and records what was submitted.
func TestSubmitIndexNowSendsOnlyThePublicPages(t *testing.T) {
	const key = "test-indexnow-key"
	served := key
	status := http.StatusAccepted
	var submitted []map[string]any
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/"+key+".txt":
			_, _ = io.WriteString(w, served)
		case r.URL.Path == "/indexnow" && r.Method == http.MethodPost:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("submission is not JSON: %v", err)
			}
			submitted = append(submitted, body)
			w.WriteHeader(status)
		default:
			http.NotFound(w, r)
		}
	}))
	defer site.Close()
	client := site.Client()
	endpoint := site.URL + "/indexnow"

	if err := submitIndexNow(client, endpoint, site.URL, key, []string{"/", "/about.ro.html"}); err != nil {
		t.Fatalf("submission failed: %v", err)
	}
	if len(submitted) != 1 {
		t.Fatalf("%d submissions", len(submitted))
	}
	got := submitted[0]
	urls, _ := got["urlList"].([]any)
	if got["host"] != strings.TrimPrefix(site.URL, "https://") || got["key"] != key ||
		got["keyLocation"] != site.URL+"/"+key+".txt" ||
		!slices.Equal(urls, []any{site.URL + "/", site.URL + "/about.ro.html"}) || len(got) != 4 {
		t.Fatalf("submitted %v", got)
	}

	if err := submitIndexNow(client, endpoint, site.URL, key, []string{"/verify.html"}); err == nil {
		t.Error("a page that is not public was submitted")
	}
	served = "someone else's key"
	if err := submitIndexNow(client, endpoint, site.URL, key, publicPages); err == nil {
		t.Error("submitted with a key the site does not serve")
	}
	served = key
	status = http.StatusForbidden
	if err := submitIndexNow(client, endpoint, site.URL, key, publicPages); err == nil {
		t.Error("a refused submission was reported as sent")
	}
	if len(submitted) != 2 {
		t.Fatalf("%d submissions; only the first and the refused one should have been sent", len(submitted))
	}
}
