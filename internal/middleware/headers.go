package middleware

import (
	"net/http"
	"os"
	"strings"
)

// SecurityHeaders adds standard security headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()")
		// CSP: allow self, inline styles (for dynamic UI), blob: for file previews.
		// External analytics is opt-in via ANALYTICS_ORIGIN.
		// connect-src 'self' covers same-origin WebSocket (wss:) in modern browsers
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"base-uri 'none'; "+
				"object-src 'none'; "+
				"script-src "+cspSources("'self'", analyticsOrigins())+"; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src "+cspSources("'self'", []string{"blob:", "data:"}, analyticsOrigins())+"; "+
				"media-src 'self' blob:; "+
				"connect-src "+cspSources("'self'", analyticsOrigins())+"; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'")
		// HSTS — 1 year
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

func analyticsOrigins() []string {
	raw := os.Getenv("ANALYTICS_ORIGIN")
	if raw == "" {
		return nil
	}
	var origins []string
	for _, part := range strings.Split(raw, ",") {
		if origin := strings.TrimSpace(part); origin != "" {
			origins = append(origins, origin)
		}
	}
	return origins
}

func cspSources(parts ...any) string {
	var sources []string
	for _, part := range parts {
		switch v := part.(type) {
		case string:
			if v != "" {
				sources = append(sources, v)
			}
		case []string:
			sources = append(sources, v...)
		}
	}
	return strings.Join(sources, " ")
}
