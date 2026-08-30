package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	mac.Write([]byte(ExtractIP(r)))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}
