// Package srp implements the server half of SRP-6a (RFC 5054 2048-bit group,
// SHA-256). It lets a client prove knowledge of a password without ever sending
// the password — not to the server, and not to any TLS-terminating middlebox
// (Cloudflare). The server only ever stores a salt and a verifier v = g^x mod N,
// from which the password cannot be recovered.
//
// All group elements are zero-padded to the byte length of N before hashing so the
// client (web/js/srp.js) and server agree byte-for-byte; the two implementations
// are cross-checked with deterministic vectors in the tests.
package srp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math/big"
)

// RFC 5054 Appendix A — 2048-bit group.
const nHex = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
	"A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
	"E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
	"55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
	"CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
	"54523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6A" +
	"F874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB69" +
	"4B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

var (
	N    = mustHex(nHex)
	g    = big.NewInt(2)
	nLen = (N.BitLen() + 7) / 8

	// k = H(PAD(N) | PAD(g)) — multiplier parameter, fixed for the group.
	k = hashInt(pad(N), pad(g))

	ErrBadParam = errors.New("srp: invalid protocol parameter")
	ErrProof    = errors.New("srp: bad client proof")
)

// Verifier computes (salt, v) for registration. The client does this; the server
// uses it only in tests. salt is the caller-provided random salt.
func Verifier(username, password string, salt []byte) *big.Int {
	x := computeX(salt, username, password)
	return new(big.Int).Exp(g, x, N)
}

// DecodeVerifier parses a stored hex verifier and checks 0 < v < N.
func DecodeVerifier(h string) (*big.Int, error) {
	v, ok := new(big.Int).SetString(h, 16)
	if !ok || v.Sign() <= 0 || v.Cmp(N) >= 0 {
		return nil, ErrBadParam
	}
	return v, nil
}

// DecodePublic parses a client public ephemeral A (hex) and checks A mod N != 0.
func DecodePublic(h string) (*big.Int, error) {
	a, ok := new(big.Int).SetString(h, 16)
	if !ok || new(big.Int).Mod(a, N).Sign() == 0 {
		return nil, ErrBadParam
	}
	return a, nil
}

// Challenge is the server's ephemeral state for one login attempt.
type Challenge struct {
	b    *big.Int // server private ephemeral
	Bpub *big.Int // server public ephemeral B (sent to the client)
	v    *big.Int // the account's verifier
}

// NewChallenge picks b and computes B = (k*v + g^b) mod N for a known verifier.
func NewChallenge(v *big.Int) (*Challenge, error) {
	for i := 0; i < 16; i++ {
		b, err := randInt()
		if err != nil {
			return nil, err
		}
		B := new(big.Int).Mod(
			new(big.Int).Add(new(big.Int).Mul(k, v), new(big.Int).Exp(g, b, N)),
			N,
		)
		if B.Sign() != 0 { // B % N must not be zero
			return &Challenge{b: b, Bpub: B, v: v}, nil
		}
	}
	return nil, errors.New("srp: could not generate B")
}

// Verify checks the client's A and proof M1. On success it returns the server
// proof M2 (to send back so the client can authenticate the server) and the shared
// session key K.
func (c *Challenge) Verify(A *big.Int, M1 []byte) (M2, K []byte, err error) {
	if A == nil || new(big.Int).Mod(A, N).Sign() == 0 {
		return nil, nil, ErrBadParam // A % N == 0 → reject
	}
	u := hashInt(pad(A), pad(c.Bpub))
	if u.Sign() == 0 {
		return nil, nil, ErrBadParam
	}
	// S = (A * v^u)^b mod N
	S := new(big.Int).Exp(
		new(big.Int).Mod(new(big.Int).Mul(A, new(big.Int).Exp(c.v, u, N)), N),
		c.b, N,
	)
	Kb := hashBytes(pad(S))
	expectM1 := hashBytes(pad(A), pad(c.Bpub), pad(S))
	if subtle.ConstantTimeCompare(expectM1, M1) != 1 {
		return nil, nil, ErrProof
	}
	M2 = hashBytes(pad(A), M1, pad(S))
	return M2, Kb, nil
}

/* ── shared math (must mirror web/js/srp.js) ── */

// computeX = H(salt | H(username | ":" | password)).
func computeX(salt []byte, username, password string) *big.Int {
	inner := sha256.Sum256([]byte(username + ":" + password))
	h := sha256.New()
	h.Write(salt)
	h.Write(inner[:])
	return new(big.Int).SetBytes(h.Sum(nil))
}

func pad(x *big.Int) []byte {
	b := x.Bytes()
	if len(b) >= nLen {
		return b
	}
	out := make([]byte, nLen)
	copy(out[nLen-len(b):], b)
	return out
}

func hashBytes(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func hashInt(parts ...[]byte) *big.Int {
	return new(big.Int).SetBytes(hashBytes(parts...))
}

func randInt() (*big.Int, error) {
	b := make([]byte, 32) // 256-bit ephemeral
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func mustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("srp: bad hex constant")
	}
	return n
}
