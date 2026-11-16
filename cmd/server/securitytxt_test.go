package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecurityContactAcceptsOnlyAReachableURI(t *testing.T) {
	t.Setenv("SECURITY_CONTACT", "")
	if contact, err := securityContact(); contact != "" || err != nil {
		t.Fatalf("unset contact = %q, %v; want none and no error", contact, err)
	}
	for _, good := range []string{"mailto:security@example.org", "https://example.org/security", " mailto:a.b+c@example.co.uk "} {
		t.Setenv("SECURITY_CONTACT", good)
		if contact, err := securityContact(); err != nil || contact != strings.TrimSpace(good) {
			t.Errorf("%q = %q, %v; want accepted", good, contact, err)
		}
	}
	for _, bad := range []string{
		"security@example.org",        // no scheme: a reader cannot tell what it is
		"http://example.org/security", // a report sent in the clear
		"mailto:security",             // nowhere to deliver
		"mailto:@example.org",         //
		"mailto:a@b@example.org",      //
		"mailto:a@example.org\nContact: mailto:evil@example.net", // a second field smuggled in
		"mailto:a@example.org https://x",                         // two values
		"javascript:alert(1)",
		"https://",
		"mailto:" + strings.Repeat("a", 250) + "@example.org",
	} {
		t.Setenv("SECURITY_CONTACT", bad)
		if contact, err := securityContact(); err == nil {
			t.Errorf("%q accepted as %q", bad, contact)
		}
	}
}

func TestSecurityTxtIsWellFormed(t *testing.T) {
	expires := time.Date(2027, 11, 16, 4, 5, 6, 0, time.UTC)
	body := string(securityTxtBody("mailto:security@example.org", "https://chat.example.org", expires))
	want := "Contact: mailto:security@example.org\n" +
		"Expires: 2027-11-16T04:05:06Z\n" +
		"Preferred-Languages: en, ro\n" +
		"Canonical: https://chat.example.org/.well-known/security.txt\n"
	if body != want {
		t.Fatalf("body =\n%s\nwant\n%s", body, want)
	}
	if strings.Contains(string(securityTxtBody("mailto:a@example.org", "", expires)), "Canonical") {
		t.Fatal("a deployment without a public https origin must not claim a canonical address")
	}

	handler := securityTxtHandler([]byte(want))
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != want ||
		rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("GET = %d %q (%s)", rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
	}
	rec = httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, "/.well-known/security.txt", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", rec.Code)
	}
}

func TestSecurityTxtExpiryIsInTheFutureAndBounded(t *testing.T) {
	now := time.Now()
	expires := securityTxtExpiry(now)
	if !expires.After(now.AddDate(0, 0, -1)) || expires.After(now.AddDate(1, 0, 1)) {
		t.Fatalf("expiry %s is not within a year of %s", expires, now)
	}
}
