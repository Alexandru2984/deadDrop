package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"deaddrop/internal/srp"
)

// A minimal SRP-6a client for the handler tests. It mirrors web/js/srp.js (and
// clientProof in internal/srp) so a test can drive /api/srp/challenge and
// /api/srp/authenticate the way a real browser does, rather than reaching past
// the HTTP layer into the store.
//
// The stretch that a real client applies before x is deliberately skipped: the
// server never runs the KDF, so these tests only need both sides to agree.

var testG = big.NewInt(2)

func testPad(x *big.Int) []byte {
	nLen := len(srp.N.Bytes())
	b := x.Bytes()
	if len(b) >= nLen {
		return b
	}
	out := make([]byte, nLen)
	copy(out[nLen-len(b):], b)
	return out
}

func testHash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func testHashInt(parts ...[]byte) *big.Int {
	return new(big.Int).SetBytes(testHash(parts...))
}

func testComputeX(salt []byte, username, password string) *big.Int {
	inner := sha256.Sum256([]byte(username + ":" + password))
	return testHashInt(salt, inner[:])
}

// testClientA returns a client ephemeral pair (a, A = g^a mod N).
func testClientA(t *testing.T) (*big.Int, *big.Int) {
	t.Helper()
	a, ok := new(big.Int).SetString("f3a1c0de5eed", 16)
	if !ok {
		t.Fatal("bad test scalar")
	}
	return a, new(big.Int).Exp(testG, a, srp.N)
}

// testClientProof computes M1 for the given challenge, plus the M2 the client
// expects back so a test can also check that the server authenticated itself.
func testClientProof(t *testing.T, a *big.Int, A *big.Int, username, password, saltHex, bHex string) (m1Hex, expectM2Hex string) {
	t.Helper()
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		t.Fatalf("challenge salt is not hex: %v", err)
	}
	B, ok := new(big.Int).SetString(bHex, 16)
	if !ok {
		t.Fatalf("challenge B is not hex: %q", bHex)
	}
	k := testHashInt(testPad(srp.N), testPad(testG))
	x := testComputeX(salt, username, password)
	u := testHashInt(testPad(A), testPad(B))

	// S = (B - k*g^x)^(a + u*x) mod N
	kgx := new(big.Int).Mul(k, new(big.Int).Exp(testG, x, srp.N))
	base := new(big.Int).Mod(new(big.Int).Sub(B, kgx), srp.N)
	exp := new(big.Int).Add(a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(base, exp, srp.N)

	sp := testPad(S)
	m1 := testHash(testPad(A), testPad(B), sp)
	return hex.EncodeToString(m1), hex.EncodeToString(testHash(testPad(A), m1, sp))
}
