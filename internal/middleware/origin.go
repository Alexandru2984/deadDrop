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
			w.Write([]byte(`{"error":"forbidden origin"}`))
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
	origin := r.Header.Get("Origin")
	if origin != "" {
		return originHostMatches(r, origin)
	}
	referer := r.Header.Get("Referer")
	if referer != "" {
		return originHostMatches(r, referer)
	}
	// Non-browser clients may omit both headers. Browsers send Origin on fetch POSTs,
	// which are the CSRF-sensitive requests this app uses.
	return true
}

func originHostMatches(r *http.Request, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	originHost := strings.ToLower(u.Host)
	for _, h := range requestHosts(r) {
		if originHost == strings.ToLower(h) {
			return true
		}
	}
	return false
}

func requestHosts(r *http.Request) []string {
	hosts := []string{r.Host}
	if h := r.Header.Get("X-Forwarded-Host"); h != "" && isTrustedProxyRequest(r) {
		for _, part := range strings.Split(h, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				hosts = append(hosts, trimmed)
			}
		}
	}
	return hosts
}
