package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
)

// clientTagSecret is generated once per process and never written to disk, so
// the tags below cannot be correlated across restarts or with any other system.
var clientTagSecret = newClientTagSecret()

func newClientTagSecret() []byte {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		// Without a secret every tag would be predictable, which would let an
		// attacker collide with someone else's rate-limit bucket. Fail closed.
		panic("middleware: cannot seed the client tag secret: " + err.Error())
	}
	return secret
}

// ClientTag returns a stable, opaque identifier for the request's source,
// suitable as a rate-limiting or lockout key.
//
// Rate limiting needs to tell clients apart; it does not need to know who they
// are. Keying the in-memory maps on an HMAC rather than the address itself means
// the limiter's key space is not a standing list of who used the service, so a
// crash dump, a stray struct print, or a debug handler cannot spill one. It is
// not a defence against an attacker who already has full process memory — the
// secret is in there too — and an attacker who suspects a specific address can
// still confirm it if they can reach the secret. The point is that the addresses
// are never materialised in the first place.
func ClientTag(r *http.Request) string {
	mac := hmac.New(sha256.New, clientTagSecret)
	mac.Write([]byte(sourceKey(ExtractIP(r))))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// sourceKey collapses an IPv6 address to its /64.
//
// An IPv4 address is roughly one subscriber. An IPv6 address is not: every
// customer is handed at least a /64 — 2^64 addresses — and picking a fresh one
// per request is a configuration flag, not an effort. Keyed per address, the
// login lockout and the rate limits would each see an endless stream of
// first-time visitors. The /64 is the unit a provider actually assigns, so it is
// the unit a limit can hold to.
func sourceKey(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() != nil {
		return addr
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
