package middleware

import (
	"context"
	"net/http"
)

type directClientKey struct{}

// DirectClientBoundary marks every request on this handler chain as arriving
// straight from an untrusted client, with no reverse proxy in between.
//
// It exists for the Tor hidden-service listener: the tor daemon connects from
// loopback exactly like nginx does, but unlike nginx it forwards client bytes
// verbatim — an onion visitor writes the HTTP request themselves and can send
// any X-Real-IP / X-Forwarded-* values they like. Without this marker such a
// request would pass isTrustedProxyRequest and mint a fresh spoofed identity
// per request, walking past per-IP rate limits and the login lockout.
//
// Marked requests never have forwarded headers honored; ExtractIP groups them
// all under the given label (e.g. "onion") instead of an address.
func DirectClientBoundary(label string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), directClientKey{}, label)))
	})
}

func directClientLabel(r *http.Request) (string, bool) {
	label, ok := r.Context().Value(directClientKey{}).(string)
	return label, ok
}

// OnionLocation advertises the same page on an onion service. Tor Browser reads
// the header and offers to switch, which takes Cloudflare, public DNS and the
// TLS terminator in front of this origin out of the path for page loads, API
// calls and signalling. Ordinary browsers ignore it.
//
// Only the path and query are carried over. The fragment — where a room
// invite lives — never reaches the server, so it cannot be copied here; the
// switch lands on the same page without it.
func OnionLocation(onionOrigin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			w.Header().Set("Onion-Location", onionOrigin+r.URL.RequestURI())
		}
		next.ServeHTTP(w, r)
	})
}
