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
		h.Set("X-Permitted-Cross-Domain-Policies", "none")
		// Code and API responses must arrive byte-for-byte. Besides preventing
		// sensitive API caching, no-transform stops CDN bot products from
		// injecting JavaScript into HTML and invalidating the published hashes.
		h.Set("Cache-Control", "no-store, no-transform")
		// Deny every capability the app does not use. camera/microphone stay
		// self-enabled for calls and QR scanning; everything else is a sensor,
		// tracking surface, or device bridge this app has no business touching.
		h.Set("Permissions-Policy",
			"camera=(self), microphone=(self), fullscreen=(self), autoplay=(self), "+
				"display-capture=(), geolocation=(), payment=(), usb=(), serial=(), "+
				"bluetooth=(), hid=(), midi=(), accelerometer=(), gyroscope=(), "+
				"magnetometer=(), ambient-light-sensor=(), idle-detection=(), "+
				"local-fonts=(), compute-pressure=(), screen-wake-lock=(), "+
				"browsing-topics=(), interest-cohort=(), attribution-reporting=(), "+
				"otp-credentials=(), publickey-credentials-get=(), storage-access=()")
		// Privacy-first CSP: no external origins, no inline scripts OR styles. The
		// whole app is same-origin ES modules + stylesheets; dynamic styling goes
		// through the CSSOM (element.style.x = …), which CSP does not block.
		// blob:/data: cover file previews and the inline SVG favicon.
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"base-uri 'none'; "+
				"object-src 'none'; "+
				"script-src 'self'; "+
				"style-src 'self'; "+
				"img-src 'self' blob: data:; "+
				"media-src 'self' blob:; "+
				"font-src 'self'; "+
				"connect-src 'self'; "+
				"manifest-src 'self'; "+
				"worker-src 'self'; "+
				"child-src 'none'; "+
				"frame-src 'none'; "+
				// Inline event handlers and style="" attributes are not used
				// anywhere; refusing them removes the injection sinks that
				// script-src/style-src alone still permit.
				"script-src-attr 'none'; "+
				"style-src-attr 'none'; "+
				// Every render path builds DOM nodes and appends strings as text,
				// so no code needs the innerHTML sink. Declaring no policy makes
				// any future assignment to it a runtime error rather than a
				// silently reintroduced XSS sink.
				"require-trusted-types-for 'script'; "+
				"trusted-types 'none'; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'")
		// HSTS — 2 years, preload-eligible.
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		next.ServeHTTP(w, r)
	})
}
