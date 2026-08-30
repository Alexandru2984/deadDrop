package middleware

import (
	"net/http"
	"net/url"
	"strings"
)

// RequireSameOrigin rejects unsafe browser requests from other origins.
func RequireSameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isUnsafeMethod(r.Method) {
			next(w, r)
			return
		}
		if !sameOrigin(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden origin"}`))
			return
		}
		next(w, r)
	}
}

func isUnsafeMethod(method string) bool {
	return method != http.MethodGet &&
		method != http.MethodHead &&
		method != http.MethodOptions &&
		method != http.MethodTrace
}

func sameOrigin(r *http.Request) bool {
	// Sec-Fetch-Site is set by the browser itself and cannot be written by page
	// script, so it holds even where an attacker can influence Origin/Referer.
	// Checking it first makes CSRF protection independent of header reflection
	// quirks in any proxy ahead of us.
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin":
		// Keep going: still confirm Origin/Referer agree with the request host.
	case "":
		// Absent: an older browser or a non-browser client. Fall through to the
		// Origin/Referer checks below.
	default:
		// cross-site, same-site, or none — never a legitimate state change here.
		return false
	}
	// A state-changing API call is a fetch, never a top-level navigation. A
	// navigate-mode POST is a cross-document form submission.
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode == "navigate" || mode == "no-cors" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		return originHostMatches(r, origin)
	}
	referer := r.Header.Get("Referer")
	if referer != "" {
		return originHostMatches(r, referer)
	}
	// Non-browser clients may omit all of these. Browsers send Origin on fetch
	// POSTs, which are the CSRF-sensitive requests this app uses.
	return true
}

func originHostMatches(r *http.Request, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	if !strings.EqualFold(u.Scheme, requestScheme(r)) {
		return false
	}
	originHost := strings.ToLower(u.Host)
	return originHost == strings.ToLower(r.Host)
}

// IsSecureRequest reports whether the browser-facing request used HTTPS. A
// forwarded scheme is accepted only from the same trusted proxy boundary used
// for client IP extraction.
func IsSecureRequest(r *http.Request) bool {
	return requestScheme(r) == "https"
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if isTrustedProxyRequest(r) {
		proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
		if proto == "https" || proto == "http" {
			return proto
		}
	}
	return "http"
}
