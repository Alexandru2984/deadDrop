package middleware

import "net/http"

// SecurityHeaders adds standard security headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()")
		// CSP: allow self, inline styles (for dynamic UI), blob: for file previews
		// connect-src 'self' covers same-origin WebSocket (wss:) in modern browsers
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' blob: data:; "+
				"media-src 'self' blob:; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'")
		// HSTS — 1 year
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}
