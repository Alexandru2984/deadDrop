package dnsname

import (
	"net/url"
	"strings"
	"testing"
)

// Both callers use this verdict to decide whether a host is safe to put in a
// URL — an allowed origin, or a STUN/TURN endpoint. A name this accepts that a
// URL parser then reads as something else would mean the check and the use
// disagree about the destination.
func FuzzValid(f *testing.F) {
	for _, seed := range []string{
		"dead.micutu.com", "example.com", "127.0.0.1", "a.b", "-x.com", "x-.com",
		"", ".", "a..b", "xn--80ak6aa92e.com", "UPPER.CASE", "host:8080",
		"host/path", "host?q", "host#f", "host@evil", "[::1]", "a\u00ad.com",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, host string) {
		if !Valid(host) {
			return
		}
		// An accepted name must survive being placed in a URL and come back
		// unchanged, case aside. Anything else means the string carries
		// authority, path or port that the caller never checked.
		u, err := url.Parse("https://" + host + "/")
		if err != nil {
			t.Fatalf("accepted %q, but it does not parse as a URL host: %v", host, err)
		}
		if !strings.EqualFold(u.Hostname(), host) {
			t.Fatalf("accepted %q, but a URL reads its host as %q", host, u.Hostname())
		}
		if u.Port() != "" || u.User != nil || u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
			t.Fatalf("accepted %q, which smuggles URL structure: %+v", host, u)
		}
		if Valid(strings.ToUpper(host)) != Valid(host) {
			t.Fatalf("case changes the verdict for %q", host)
		}
	})
}
