package middleware

import (
	"net/http"
)

// SecurityHeaders adds strict security headers to every response. The app owns
// these headers exclusively — the nginx vhost must NOT also emit them, or the
// browser sees duplicate/conflicting policies (it then enforces the most
// restrictive intersection, which is fragile and surprising).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy",
			"camera=(self), microphone=(self), display-capture=(), geolocation=(), "+
				"browsing-topics=(), interest-cohort=(), payment=(), usb=(), "+
				"accelerometer=(), gyroscope=(), magnetometer=()")
		// Privacy-first CSP: no external origins, no inline scripts. The whole app
		// is same-origin ES modules. 'unsafe-inline' stays only for style attributes
		// injected via innerHTML (progress bars etc.). blob:/data: cover file
		// previews and the inline SVG favicon.
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"base-uri 'none'; "+
				"object-src 'none'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' blob: data:; "+
				"media-src 'self' blob:; "+
				"font-src 'self'; "+
				"connect-src 'self'; "+
				"manifest-src 'self'; "+
				"worker-src 'self' blob:; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'")
		// HSTS — 2 years, preload-eligible.
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		next.ServeHTTP(w, r)
	})
}
