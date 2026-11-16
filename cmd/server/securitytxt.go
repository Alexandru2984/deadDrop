package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

// /.well-known/security.txt (RFC 9116): where to report a vulnerability in
// this deployment.
//
// The address belongs to whoever runs the service, not to the code, so it is a
// setting rather than a file in the bundle: SECURITY_CONTACT, a mailto: or
// https: URI. Unset, the path answers 404 — a made-up or inherited contact is
// worse than none, because a report sent to it is lost and looks delivered.

// securityContact reads SECURITY_CONTACT. Unset is not an error.
func securityContact() (string, error) {
	contact := strings.TrimSpace(os.Getenv("SECURITY_CONTACT"))
	if contact == "" {
		return "", nil
	}
	if len(contact) > 254 || strings.ContainsAny(contact, " \t\r\n<>\"") {
		return "", errors.New("SECURITY_CONTACT must be one mailto: or https: URI without spaces")
	}
	u, err := url.Parse(contact)
	if err != nil {
		return "", errors.New("SECURITY_CONTACT must be one mailto: or https: URI without spaces")
	}
	switch u.Scheme {
	case "mailto":
		local, domain, found := strings.Cut(u.Opaque, "@")
		if !found || local == "" || !strings.Contains(domain, ".") || strings.Contains(domain, "@") {
			return "", errors.New("SECURITY_CONTACT mailto: needs an address such as mailto:security@example.org")
		}
	case "https":
		if u.Host == "" {
			return "", errors.New("SECURITY_CONTACT https: needs a host")
		}
	default:
		return "", errors.New("SECURITY_CONTACT must start with mailto: or https://")
	}
	return contact, nil
}

// securityTxtExpiry is one year after the commit this binary was built from.
// RFC 9116 wants a date after which the file should not be trusted. Tying it
// to the build says something true: a deployment nobody has updated in a year
// is one whose contact may no longer be read. Without build information — a
// test binary, `go run` — it falls back to a year from start.
func securityTxtExpiry(started time.Time) time.Time {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.time" {
				if built, err := time.Parse(time.RFC3339, setting.Value); err == nil {
					return built.AddDate(1, 0, 0).UTC()
				}
			}
		}
	}
	return started.AddDate(1, 0, 0).UTC()
}

func securityTxtBody(contact, origin string, expires time.Time) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "Contact: %s\n", contact)
	fmt.Fprintf(&b, "Expires: %s\n", expires.Format("2006-01-02T15:04:05Z"))
	b.WriteString("Preferred-Languages: en, ro\n")
	if origin != "" {
		fmt.Fprintf(&b, "Canonical: %s/.well-known/security.txt\n", origin)
	}
	return []byte(b.String())
}

func securityTxtHandler(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}
}
