package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	"deaddrop/internal/srp"
)

const (
	// A browser answers its challenge within seconds; a minute is room for a
	// slow phone over Tor, and half the time a flood gets to hold each slot.
	challengeTTL  = time.Minute
	maxChallenges = 4096
	// Pending challenges one source may hold. A sign-in needs one at a time,
	// but behind a shared address — carrier NAT, an onion listener without
	// circuit tags — several people may be signing in at once.
	maxChallengesPerSource = 8
)

/* ── pending SRP challenges (one-time, short-lived) ── */

type pendingChallenge struct {
	username        string
	A               *big.Int
	ch              *srp.Challenge // real verifier
	real            bool           // a real account exists
	chDuress        *srp.Challenge // duress verifier (or a deterministic dummy)
	realDuress      bool           // a real duress verifier exists
	expiry          time.Time
	source          string // ClientTag of the requester, for the per-source bound
	primaryRevision uint64
	duressRevision  uint64
}

type challengeStore struct {
	mu sync.Mutex
	m  map[string]*pendingChallenge
	// bySource lists each source's pending tokens, oldest first. Every
	// challenge lives the same TTL, so insertion order is expiry order.
	bySource map[string][]string
	secret   []byte // for deterministic fake verifiers (anti-enumeration)
}

func newChallengeStore(dataDir string) (*challengeStore, error) {
	secret, err := loadOrCreateSecret(filepath.Join(dataDir, "srp_dummy.key"), 32)
	if err != nil {
		return nil, fmt.Errorf("initialize SRP dummy secret: %w", err)
	}
	cs := &challengeStore{m: make(map[string]*pendingChallenge), secret: secret}
	go cs.reap()
	return cs, nil
}

func (cs *challengeStore) put(p *pendingChallenge) (string, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	now := time.Now()
	cs.removeExpiredLocked(now)
	cs.makeRoomLocked(p.source)
	if len(cs.m) >= maxChallenges {
		return "", errors.New("too many pending authentication challenges")
	}
	var tok string
	for {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		tok = hex.EncodeToString(b)
		if _, exists := cs.m[tok]; !exists {
			break
		}
	}
	p.expiry = now.Add(challengeTTL)
	cs.m[tok] = p
	if cs.bySource == nil {
		cs.bySource = make(map[string][]string)
	}
	cs.bySource[p.source] = append(cs.bySource[p.source], tok)
	return tok, nil
}

func (cs *challengeStore) deleteLocked(tok string) {
	p, ok := cs.m[tok]
	if !ok {
		return
	}
	delete(cs.m, tok)
	list := cs.bySource[p.source]
	for i, t := range list {
		if t == tok {
			list = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(cs.bySource, p.source)
	} else {
		cs.bySource[p.source] = list
	}
}

// makeRoomLocked keeps a flood of challenges from turning every sign-in away.
//
// Refusing new challenges once the table was full let anyone with enough
// addresses — an IPv6 /48 is 65,536 rate-limit sources — keep it full and
// lock everyone out without an account. Instead a source over its own bound
// loses its oldest challenge, and a full table sheds the oldest challenge of
// whichever source holds the most. A real sign-in, one challenge answered in
// seconds, then always finds a slot: what gets pushed out is the flood.
func (cs *challengeStore) makeRoomLocked(source string) {
	if list := cs.bySource[source]; len(list) >= maxChallengesPerSource {
		cs.deleteLocked(list[0])
		return
	}
	if len(cs.m) < maxChallenges {
		return
	}
	heaviest, most := "", 0
	for src, list := range cs.bySource {
		if len(list) > most {
			heaviest, most = src, len(list)
		}
	}
	if most > 1 {
		cs.deleteLocked(cs.bySource[heaviest][0])
		return
	}
	// Every source holds one: the oldest overall has had the longest to be
	// answered.
	var oldestTok string
	for tok, p := range cs.m {
		if oldestTok == "" || p.expiry.Before(cs.m[oldestTok].expiry) {
			oldestTok = tok
		}
	}
	cs.deleteLocked(oldestTok)
}

func (cs *challengeStore) take(tok string) (*pendingChallenge, bool) {
	if len(tok) != 64 {
		return nil, false
	}
	if _, err := hex.DecodeString(tok); err != nil {
		return nil, false
	}
	cs.mu.Lock()
	defer cs.mu.Unlock()
	p, ok := cs.m[tok]
	if !ok {
		return nil, false
	}
	cs.deleteLocked(tok) // one-time use
	if time.Now().After(p.expiry) {
		return nil, false
	}
	return p, true
}

func (cs *challengeStore) reap() {
	for range time.NewTicker(time.Minute).C {
		now := time.Now()
		cs.mu.Lock()
		cs.removeExpiredLocked(now)
		cs.mu.Unlock()
	}
}

func (cs *challengeStore) removeExpiredLocked(now time.Time) {
	for token, p := range cs.m {
		if now.After(p.expiry) {
			cs.deleteLocked(token)
		}
	}
}

// fakeSaltAndVerifier deterministically derives a plausible salt+verifier for an
// unknown username (or a missing duress slot) so the challenge step is
// indistinguishable from a real account. kind separates the real vs duress dummies.
func (cs *challengeStore) fakeSaltAndVerifier(kind, username string) (string, *srp.Challenge, error) {
	salt := hmacSum(cs.secret, kind+":salt:"+username)[:16]
	verifierBytes := hmacSum(cs.secret, kind+":verifier:"+username)
	// Any 256-bit non-zero integer is a valid member of the 2048-bit verifier
	// range. This avoids an extra modular exponentiation only on dummy accounts.
	allZero := true
	for _, b := range verifierBytes {
		allZero = allZero && b == 0
	}
	if allZero {
		verifierBytes[len(verifierBytes)-1] = 1
	}
	v, err := srp.DecodeVerifier(hex.EncodeToString(verifierBytes))
	if err != nil {
		return "", nil, err
	}
	ch, err := srp.NewChallenge(v)
	return hex.EncodeToString(salt), ch, err
}
