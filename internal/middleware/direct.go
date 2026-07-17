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
