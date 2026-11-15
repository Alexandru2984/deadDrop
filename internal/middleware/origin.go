package middleware

import (
	"net/http"
	"net/url"
	"strings"
)

// RefuseForeignRequests turns away API and signaling requests that a browser
// sent on another site's behalf, before any limiter or handler counts them.
//
// The limiters are keyed by the visitor's address or account, and they used to
// run first. A page on any other site could therefore spend them: fifteen
// forged POSTs to the sign-in route were each refused with 403, and the
// sixteenth — the visitor's own sign-in — was answered 429. Repeated ten times
// a minute from a tab left open, that kept a person, and everyone sharing
// their address, out of the service without ever touching their account. A
// sibling subdomain could do the same to the per-account signaling and TURN
// allowances, since SameSite cookies travel within one site.
//
// Nothing here is a credential check. It only decides whose request this is,
// so that a request made by somebody else is not billed to the visitor.
// Static pages stay reachable from anywhere: links to them are the point.
func RefuseForeignRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isProgrammaticPath(r.URL.Path) && foreignBrowserRequest(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden origin"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isProgrammaticPath(path string) bool {
	return path == "/ws" || strings.HasPrefix(path, "/api/")
}

// foreignBrowserRequest reports whether a browser says another site caused
// this request. Clients that send neither header — monitors, the CLI, the
// e2e suites — are not browsers acting for a third party and pass through to
// the per-route checks.
func foreignBrowserRequest(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin":
		return false
	case "none":
		// The user typed the address or used a bookmark. No page can cause it.
		return false
	case "":
		// Older browsers, and WebSocket handshakes in some current ones, send no
		// fetch metadata. Every WebSocket handshake and every CORS or POST
		// request still carries Origin.
		if origin := r.Header.Get("Origin"); origin != "" {
			return !originHostMatches(r, origin)
		}
		return false
	default:
		// cross-site, same-site, or a value no browser sends.
		return true
	}
}

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
