package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"deaddrop/internal/middleware"
	"deaddrop/internal/srp"
	"deaddrop/internal/strictjson"
)

const (
	srpMaxBody        = 8192
	challengeTTL      = 2 * time.Minute
	maxChallenges     = 4096
	maxLockoutEntries = 100_000
	lockoutThreshold  = 5
	lockoutWindow     = 15 * time.Minute
)

/* ── store: SRP-aware methods ── */

func (s *store) getUser(username string) (user, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	return u, ok
}

func validSalt(h string) bool { b, err := hex.DecodeString(h); return err == nil && len(b) == 16 }

// defaultKdf is what fresh clients use and what anti-enumeration dummies
// advertise; it must stay in sync with DEFAULT_KDF in web/js/srp.js.
const defaultKdf = "pbkdf2:600000"

const minimumWritableKdfIterations = 600_000

var kdfRe = regexp.MustCompile(`^pbkdf2:(\d{1,9})$`)

// validKdf accepts the empty string (legacy, no stretch) or a pbkdf2 label with a
// sane iteration count. The server never executes the KDF — bounds only stop a
// poisoned label from freezing some future client for minutes at login.
func validKdf(kdf string) bool {
	if kdf == "" {
		return true
	}
	n, ok := parseKdfIterations(kdf)
	return ok && n >= 10_000 && n <= 5_000_000
}

func parseKdfIterations(kdf string) (int, bool) {
	m := kdfRe.FindStringSubmatch(kdf)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

func validateSRPCredential(saltHex, verifierHex, kdf string) error {
	if !validSalt(saltHex) {
		return errors.New("invalid salt")
	}
	if _, err := srp.DecodeVerifier(verifierHex); err != nil {
		return errors.New("invalid verifier")
	}
	if !validKdf(kdf) {
		return errors.New("invalid kdf")
	}
	return nil
}

func validateWritableSRPCredential(saltHex, verifierHex, kdf string) error {
	if err := validateSRPCredential(saltHex, verifierHex, kdf); err != nil {
		return err
	}
	iterations, ok := parseKdfIterations(kdf)
	if !ok || iterations < minimumWritableKdfIterations {
		return errors.New("kdf is below the current security minimum")
	}
	return nil
}

func (s *store) registerSRP(username, saltHex, verifierHex, kdf string) error {
	if !usernameRe.MatchString(username) {
		return errors.New("username: 3–20 chars, letters/numbers/underscores")
	}
	if err := validateWritableSRPCredential(saltHex, verifierHex, kdf); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[username]; exists {
		return errors.New("username already taken")
	}
	if len(s.users) >= maxUsers {
		return errors.New("account limit reached")
	}
	next := cloneUsers(s.users)
	next[username] = user{Salt: saltHex, Verifier: verifierHex, Kdf: kdf}
	return s.commit(next)
}

// setVerifier installs a new SRP salt+verifier for an existing account (password
// change, or a KDF hardening upgrade). Keeps the duress credential.
func (s *store) setVerifier(username, saltHex, verifierHex, kdf string) error {
	if err := validateWritableSRPCredential(saltHex, verifierHex, kdf); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return errors.New("no such account")
	}
	next := cloneUsers(s.users)
	next[username] = user{
		Salt: saltHex, Verifier: verifierHex, Kdf: kdf,
		DuressSalt: u.DuressSalt, DuressVerifier: u.DuressVerifier, DuressKdf: u.DuressKdf,
	}
	return s.commit(next)
}

func (s *store) deleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; !ok {
		return errors.New("no such account")
	}
	next := cloneUsers(s.users)
	delete(next, username)
	return s.commit(next)
}

// setDuress sets (or clears, when salt/verifier are empty) the duress credential
// for an existing account.
func (s *store) setDuress(username, saltHex, verifierHex, kdf string) error {
	if err := validateDuressUpdate(saltHex, verifierHex, kdf); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return errors.New("no such account")
	}
	u.DuressSalt, u.DuressVerifier, u.DuressKdf = saltHex, verifierHex, kdf
	next := cloneUsers(s.users)
	next[username] = u
	return s.commit(next)
}

/* ── pending SRP challenges (one-time, short-lived) ── */

type pendingChallenge struct {
	username   string
	A          *big.Int
	ch         *srp.Challenge // real verifier
	real       bool           // a real account exists
	chDuress   *srp.Challenge // duress verifier (or a deterministic dummy)
	realDuress bool           // a real duress verifier exists
	expiry     time.Time
}

type challengeStore struct {
	mu     sync.Mutex
	m      map[string]*pendingChallenge
	secret []byte // for deterministic fake verifiers (anti-enumeration)
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
	return tok, nil
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
	delete(cs.m, tok) // one-time use
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
			delete(cs.m, token)
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

/* ── login lockout, keyed by username + client tag ──
 * Keying by username alone would let anyone lock a victim's account with a few
 * deliberately wrong proofs. Including the client's tag means an attacker only
 * locks *their own* view of the account; the per-client rate limiter throttles
 * anything distributed. The tag is an HMAC of the source address, so this map
 * never holds the addresses themselves. */

type lockEntry struct {
	fails    int
	until    time.Time
	lastSeen time.Time
}

type lockout struct {
	mu sync.Mutex
	m  map[string]*lockEntry
	// A saturated table stops recording failures, which quietly removes the
	// per-account throttle for everyone not already in it. At most one line a
	// minute, and no key: the table is keyed by username and an HMAC of the
	// address, and writing those to disk would build the record this service
	// exists not to keep.
	lastSaturationLog time.Time
}

func newLockout() *lockout {
	l := &lockout{m: make(map[string]*lockEntry)}
	go l.reap()
	return l
}

// noteSaturationLocked reports a degraded throttle without letting the report
// become its own flood. The caller holds l.mu.
func (l *lockout) noteSaturationLocked(now time.Time) {
	if now.Sub(l.lastSaturationLog) < time.Minute {
		return
	}
	l.lastSaturationLog = now
	log.Printf("[auth] lockout table full (%d) — failed-login throttling is degraded", maxLockoutEntries)
}

func lockKey(username, ip string) string { return username + "|" + ip }

func (l *lockout) allowed(username, ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[lockKey(username, ip)]
	if e == nil {
		return true, 0
	}
	if time.Now().Before(e.until) {
		return false, time.Until(e.until)
	}
	return true, 0
}

func (l *lockout) fail(username, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := lockKey(username, ip)
	e := l.m[key]
	if e == nil {
		if len(l.m) >= maxLockoutEntries {
			now := time.Now()
			l.removeStaleLocked(now)
			if len(l.m) >= maxLockoutEntries {
				// Refuse to record rather than evict: evicting would let an
				// attacker clear a victim's active lockout by filling the table.
				l.noteSaturationLocked(now)
				return
			}
		}
		e = &lockEntry{}
		l.m[key] = e
	}
	e.fails++
	e.lastSeen = time.Now()
	if e.fails >= lockoutThreshold {
		e.until = time.Now().Add(lockoutWindow)
		e.fails = 0
	}
}

func (l *lockout) reset(username, ip string) {
	l.mu.Lock()
	delete(l.m, lockKey(username, ip))
	l.mu.Unlock()
}

// reap drops entries idle past the lockout window so the map cannot grow unbounded.
func (l *lockout) reap() {
	for range time.NewTicker(10 * time.Minute).C {
		l.mu.Lock()
		l.removeStaleLocked(time.Now())
		l.mu.Unlock()
	}
}

func (l *lockout) removeStaleLocked(now time.Time) {
	cutoff := now.Add(-lockoutWindow)
	for key, entry := range l.m {
		if entry.lastSeen.Before(cutoff) && now.After(entry.until) {
			delete(l.m, key)
		}
	}
}

/* ── invite codes (file-backed, single-use) ── */

type invites struct {
	mu   sync.Mutex
	path string
}

const (
	maxInvites       = 100_000
	maxInviteBatch   = 10_000
	maxInviteFileLen = 8 << 20
	defaultInviteTTL = 14 * 24 * time.Hour
)

// invite is one stored code. ExpiresAt is a Unix timestamp; zero means the code
// never expires, which is what every code minted before expiry existed becomes.
type invite struct {
	Code      string `json:"code"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

func (i invite) expired(now time.Time) bool {
	return i.ExpiresAt != 0 && now.Unix() > i.ExpiresAt
}

// inviteTTL is how long a freshly minted code stays usable. INVITE_TTL_DAYS
// overrides it; 0 disables expiry for new codes.
func inviteTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv("INVITE_TTL_DAYS"))
	if raw == "" {
		return defaultInviteTTL
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days < 0 || days > 3650 {
		return defaultInviteTTL
	}
	return time.Duration(days) * 24 * time.Hour
}

func newInviteExpiry(now time.Time) int64 {
	ttl := inviteTTL()
	if ttl == 0 {
		return 0
	}
	return now.Add(ttl).Unix()
}

// UnmarshalJSON accepts both the current object form and the bare string the
// store used before codes could expire, so invites already issued in production
// keep working (as non-expiring) across the upgrade.
func (i *invite) UnmarshalJSON(data []byte) error {
	var code string
	if err := json.Unmarshal(data, &code); err == nil {
		i.Code, i.ExpiresAt = code, 0
		return nil
	}
	var raw struct {
		Code      string `json:"code"`
		ExpiresAt int64  `json:"exp"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	i.Code, i.ExpiresAt = raw.Code, raw.ExpiresAt
	return nil
}

// OpenRegistration reports whether registration is open to everyone (no invite).
func OpenRegistration() bool { return os.Getenv("OPEN_REGISTRATION") == "1" }

func newInvites(dir string) *invites { return &invites{path: filepath.Join(dir, "invites.json")} }

// inviteRe accepts current 20-character codes and the previous 12-character
// format so already-issued production invites remain usable. Imports cannot
// introduce shorter, lower-entropy strings or ambiguous characters.
const inviteAlphabetClass = `[ABCDEFGHJKMNPQRSTUVWXYZ23456789]`

var inviteRe = regexp.MustCompile(`^DD-(?:` + inviteAlphabetClass + `{4}-){2}` + inviteAlphabetClass + `{4}(?:-` + inviteAlphabetClass + `{4}-` + inviteAlphabetClass + `{4})?$`)

// validInviteCode reports whether s (once trimmed/uppercased) is a plausible
// invite code — used to keep junk out of an import.
func validInviteCode(s string) bool {
	return inviteRe.MatchString(strings.ToUpper(strings.TrimSpace(s)))
}

// GenerateInviteForDir creates and stores a new invite code in dataDir. For the
// `deaddrop invite` CLI subcommand. The running server reads invites fresh on each
// registration, so a code minted here is immediately usable.
func GenerateInviteForDir(dataDir string) (string, error) {
	return newInvites(dataDir).Generate()
}

// GenerateInvitesForDir mints n invite codes at once and returns them (bulk form
// of GenerateInviteForDir). n must be >= 1.
func GenerateInvitesForDir(dataDir string, n int) ([]string, error) {
	if n < 1 {
		return nil, errors.New("count must be at least 1")
	}
	return newInvites(dataDir).generateN(n)
}

// ListInvitesForDir returns the current unused invite codes in dataDir.
func ListInvitesForDir(dataDir string) ([]string, error) {
	return newInvites(dataDir).list()
}

// ImportInvitesForDir merges codes (already parsed) into dataDir's invite store,
// skipping malformed ones and duplicates. Returns how many were newly added.
func ImportInvitesForDir(dataDir string, codes []string) (added, skipped int, err error) {
	return newInvites(dataDir).importCodes(codes)
}

// ParseInviteCodes reads invite codes from raw input in either form: a JSON
// array (["DD-…", …], as produced by export) or plain whitespace/newline
// separated tokens.
//
// It returns the well-formed codes and how many tokens it discarded, so an
// operator can tell "there was nothing to import" from "none of that was an
// invite code". The store validates again on the way in — this is not the last
// line of defence — but a parser that hands back tokens it has already judged
// malformed makes every count downstream of it a guess.
//
// Input that opens with '[' must be a JSON array. Falling back to whitespace
// splitting would read a truncated export as a pile of junk tokens and report
// them as ordinary malformed input, hiding the fact that the file is damaged.
func ParseInviteCodes(raw []byte) (codes []string, dropped int, err error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, 0, nil
	}

	var tokens []string
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &tokens); err != nil {
			return nil, 0, fmt.Errorf("input starts as a JSON array but does not parse: %w", err)
		}
	} else {
		tokens = strings.Fields(trimmed)
	}

	for _, token := range tokens {
		code := strings.ToUpper(strings.TrimSpace(token))
		if !validInviteCode(code) {
			dropped++
			continue
		}
		codes = append(codes, code)
	}
	return codes, dropped, nil
}

func (iv *invites) load(root *os.Root, name string) ([]invite, error) {
	pathInfo, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("invite store is not a regular file")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("invite store is not a regular file")
	}
	if err := f.Chmod(0600); err != nil {
		return nil, err
	}
	if info.Size() > maxInviteFileLen {
		return nil, errors.New("invite store exceeds size limit")
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, err
	}
	var codes []invite
	if err := json.Unmarshal(data, &codes); err != nil {
		return nil, err
	}
	if len(codes) > maxInvites {
		return nil, errors.New("invite store exceeds code limit")
	}
	seen := make(map[string]struct{}, len(codes))
	live := make([]invite, 0, len(codes))
	now := time.Now()
	for _, entry := range codes {
		if !validInviteCode(entry.Code) {
			return nil, errors.New("invite store contains an invalid code")
		}
		normalized := strings.ToUpper(strings.TrimSpace(entry.Code))
		if _, duplicate := seen[normalized]; duplicate {
			return nil, errors.New("invite store contains a duplicate code")
		}
		seen[normalized] = struct{}{}
		if entry.expired(now) {
			continue // pruned here, persisted on the next save under the same lock
		}
		live = append(live, entry)
	}
	return live, nil
}

func (iv *invites) save(root *os.Root, name string, codes []invite) error {
	if len(codes) > maxInvites {
		return errors.New("invite store exceeds code limit")
	}
	return atomicWriteJSONAt(root, name, codes)
}

// withLock serializes both goroutines and separate CLI/server processes that
// operate on the same invite file. The lock file is intentionally persistent.
func (iv *invites) withLock(fn func(root *os.Root, name string) error) (err error) {
	iv.mu.Lock()
	defer iv.mu.Unlock()
	root, name, err := openPrivateRoot(iv.path)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.OpenFile(name+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lock.Chmod(0600); err != nil {
		return err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() {
		if unlockErr := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err == nil && unlockErr != nil {
			err = unlockErr
		}
	}()
	return fn(root, name)
}

// consume removes a code if present. Persistence failures are returned rather
// than silently treating a code as consumed.
func (iv *invites) consume(code string) (consumed bool, err error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if !validInviteCode(code) {
		return false, nil
	}
	err = iv.withLock(func(root *os.Root, name string) error {
		codes, loadErr := iv.load(root, name)
		if loadErr != nil {
			return loadErr
		}
		for i, entry := range codes {
			if subtleEqual(strings.ToUpper(entry.Code), code) {
				next := append(append([]invite(nil), codes[:i]...), codes[i+1:]...)
				if saveErr := iv.save(root, name, next); saveErr != nil {
					return saveErr
				}
				consumed = true
				break
			}
		}
		return nil
	})
	return consumed, err
}

// restore puts back a consumed invite when the account write fails.
func (iv *invites) restore(code string) error {
	code = strings.ToUpper(strings.TrimSpace(code))
	if !validInviteCode(code) {
		return errors.New("invalid invite code")
	}
	return iv.withLock(func(root *os.Root, name string) error {
		codes, err := iv.load(root, name)
		if err != nil {
			return err
		}
		for _, existing := range codes {
			if subtleEqual(strings.ToUpper(existing.Code), code) {
				return nil
			}
		}
		// A restored code keeps a fresh window: the registration it was consumed
		// for failed, so the invite is effectively unused again.
		codes = append(codes, invite{Code: code, ExpiresAt: newInviteExpiry(time.Now())})
		return iv.save(root, name, codes)
	})
}

// Generate creates, stores and returns a new single-use invite code.
func (iv *invites) Generate() (string, error) {
	codes, err := iv.generateN(1)
	if err != nil {
		return "", err
	}
	return codes[0], nil
}

// list returns the current unused, unexpired codes.
func (iv *invites) list() (codes []string, err error) {
	err = iv.withLock(func(root *os.Root, name string) error {
		entries, loadErr := iv.load(root, name)
		if loadErr != nil {
			return loadErr
		}
		codes = make([]string, 0, len(entries))
		for _, entry := range entries {
			codes = append(codes, entry.Code)
		}
		return nil
	})
	return codes, err
}

// generateN mints n fresh codes in a single load/save, avoiding collisions with
// codes already stored or minted in this batch.
func (iv *invites) generateN(n int) ([]string, error) {
	if n < 1 || n > maxInviteBatch {
		return nil, fmt.Errorf("count must be between 1 and %d", maxInviteBatch)
	}
	minted := make([]string, 0, n)
	err := iv.withLock(func(root *os.Root, name string) error {
		codes, err := iv.load(root, name)
		if err != nil {
			return err
		}
		if len(codes)+n > maxInvites {
			return errors.New("invite store exceeds code limit")
		}
		seen := make(map[string]bool, len(codes)+n)
		for _, entry := range codes {
			seen[strings.ToUpper(entry.Code)] = true
		}
		expiry := newInviteExpiry(time.Now())
		for len(minted) < n {
			code, err := newInviteCode()
			if err != nil {
				return err
			}
			if seen[strings.ToUpper(code)] {
				continue // astronomically unlikely, but never emit a dup
			}
			seen[strings.ToUpper(code)] = true
			codes = append(codes, invite{Code: code, ExpiresAt: expiry})
			minted = append(minted, code)
		}
		return iv.save(root, name, codes)
	})
	return minted, err
}

// importCodes merges the given codes into the store, skipping anything malformed
// or already present (case-insensitively). Returns counts of added and skipped.
func (iv *invites) importCodes(in []string) (added, skipped int, err error) {
	if len(in) > maxInviteBatch {
		return 0, 0, fmt.Errorf("cannot import more than %d codes at once", maxInviteBatch)
	}
	err = iv.withLock(func(root *os.Root, name string) error {
		codes, loadErr := iv.load(root, name)
		if loadErr != nil {
			return loadErr
		}
		seen := make(map[string]bool, len(codes)+len(in))
		for _, entry := range codes {
			seen[strings.ToUpper(strings.TrimSpace(entry.Code))] = true
		}
		expiry := newInviteExpiry(time.Now())
		for _, raw := range in {
			code := strings.ToUpper(strings.TrimSpace(raw))
			if !validInviteCode(code) || seen[code] || len(codes) >= maxInvites {
				skipped++
				continue
			}
			seen[code] = true
			codes = append(codes, invite{Code: code, ExpiresAt: expiry})
			added++
		}
		if added > 0 {
			return iv.save(root, name, codes)
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return added, skipped, nil
}

func newInviteCode() (string, error) {
	const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789" // no I,L,O,0,1
	const chars = 20                                   // ~99 bits from a 31-character alphabet
	const unbiasedLimit = 256 - (256 % len(alphabet))
	var sb strings.Builder
	sb.Grow(3 + chars + (chars-1)/4)
	sb.WriteString("DD-")
	random := make([]byte, 32)
	for i := 0; i < chars; {
		if _, err := rand.Read(random); err != nil {
			return "", err
		}
		for _, x := range random {
			if int(x) >= unbiasedLimit {
				continue
			}
			if i > 0 && i%4 == 0 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(x)%len(alphabet)])
			i++
			if i == chars {
				break
			}
		}
	}
	return sb.String(), nil
}

/* ── HTTP handlers ── */

type srpRegisterReq struct {
	Username string `json:"username"`
	Salt     string `json:"salt"`
	Verifier string `json:"verifier"`
	Kdf      string `json:"kdf"`
	Invite   string `json:"invite"`
}

func (h *Handler) SRPRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, srpMaxBody)
	var body srpRegisterReq
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if !usernameRe.MatchString(body.Username) {
		jsonErr(w, "username: 3–20 chars, letters/numbers/underscores", http.StatusBadRequest)
		return
	}
	if err := validateWritableSRPCredential(body.Salt, body.Verifier, body.Kdf); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Registration is invite-only unless OPEN_REGISTRATION=1 is set (then anyone can
	// register and the invite field is ignored).
	consumed := false
	if !OpenRegistration() {
		var err error
		consumed, err = h.invites.consume(body.Invite)
		if err != nil {
			log.Printf("[auth] invite store error: %v", err)
			jsonErr(w, "registration temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if !consumed {
			jsonErr(w, "invalid or used invite code", http.StatusForbidden)
			return
		}
	}
	if err := h.store.registerSRP(body.Username, body.Salt, body.Verifier, body.Kdf); err != nil {
		if consumed {
			if restoreErr := h.invites.restore(body.Invite); restoreErr != nil {
				log.Printf("[auth] could not restore invite after failed registration: %v", restoreErr)
				jsonErr(w, "registration temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("[auth] new SRP account registered")
	h.startSession(w, r, body.Username)
}

type srpChallengeReq struct {
	Username string `json:"username"`
	A        string `json:"A"`
}

func (h *Handler) SRPChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, srpMaxBody)
	var body srpChallengeReq
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if !usernameRe.MatchString(body.Username) {
		jsonErr(w, "invalid parameter", http.StatusBadRequest)
		return
	}
	if ok, wait := h.lockout.allowed(body.Username, middleware.ClientTag(r)); !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())))
		jsonErr(w, "too many attempts — try again later", http.StatusTooManyRequests)
		return
	}
	A, err := srp.DecodePublic(body.A)
	if err != nil {
		jsonErr(w, "invalid parameter", http.StatusBadRequest)
		return
	}

	u, ok := h.store.getUser(body.Username)
	if ok && !u.isSRP() {
		// A stored credential with no verifier cannot answer a proof. Treat it as
		// unknown so it receives the same dummy challenge — never a distinct reply
		// that would confirm the handle exists.
		ok = false
	}

	// Build the real challenge (real verifier, or an anti-enumeration dummy).
	// Dummies advertise the current default KDF — the same thing a fresh real
	// account would — so the response shape and timing stay indistinguishable.
	var ch *srp.Challenge
	var saltHex string
	kdf := defaultKdf
	real := false
	if ok {
		v, derr := srp.DecodeVerifier(u.Verifier)
		if derr != nil {
			jsonErr(w, "account error", http.StatusInternalServerError)
			return
		}
		ch, err = srp.NewChallenge(v)
		if err != nil {
			jsonErr(w, "account error", http.StatusInternalServerError)
			return
		}
		saltHex, kdf, real = u.Salt, u.Kdf, true
	} else {
		saltHex, ch, err = h.challenges.fakeSaltAndVerifier("real", body.Username)
		if err != nil {
			jsonErr(w, "server error", http.StatusInternalServerError)
			return
		}
	}

	// Always also emit a SECOND (duress) challenge — a real one if the account has a
	// duress credential, otherwise a deterministic dummy. Because the response shape
	// never changes, an observer cannot tell whether a duress password is configured.
	var chD *srp.Challenge
	var saltD string
	kdfD := defaultKdf
	realDuress := false
	if ok && u.hasDuress() {
		if vd, derr := srp.DecodeVerifier(u.DuressVerifier); derr == nil {
			chD, err = srp.NewChallenge(vd)
			if err != nil {
				jsonErr(w, "account error", http.StatusInternalServerError)
				return
			}
			saltD, kdfD, realDuress = u.DuressSalt, u.DuressKdf, true
		}
	}
	if chD == nil {
		saltD, chD, err = h.challenges.fakeSaltAndVerifier("duress", body.Username)
		if err != nil {
			jsonErr(w, "server error", http.StatusInternalServerError)
			return
		}
	}
	if ch == nil || chD == nil {
		jsonErr(w, "server error", http.StatusInternalServerError)
		return
	}

	token, err := h.challenges.put(&pendingChallenge{
		username: body.Username, A: A,
		ch: ch, real: real, chDuress: chD, realDuress: realDuress,
	})
	if err != nil {
		jsonErr(w, "authentication temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	jsonOK(w, map[string]any{
		"token": token,
		"salt":  saltHex, "B": ch.Bpub.Text(16), "kdf": kdf,
		"salt2": saltD, "B2": chD.Bpub.Text(16), "kdf2": kdfD,
	})
}

type srpAuthReq struct {
	Token string `json:"token"`
	M1    string `json:"M1"`
	M1d   string `json:"M1d"`
}

func (h *Handler) SRPAuthenticate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, srpMaxBody)
	var body srpAuthReq
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	p, ok := h.challenges.take(body.Token)
	if !ok {
		jsonErr(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	ip := middleware.ClientTag(r)
	if allowed, _ := h.lockout.allowed(p.username, ip); !allowed {
		jsonErr(w, "too many attempts — try again later", http.StatusTooManyRequests)
		return
	}
	primaryOK, duressOK, M2, M2d := verifyChallengeProofs(p, body.M1, body.M1d)

	if primaryOK {
		if err := h.setCookieSession(w, r, p.username, false); err != nil {
			jsonErr(w, "could not create session", http.StatusInternalServerError)
			return
		}
		h.lockout.reset(p.username, ip)
		jsonOK(w, map[string]any{"username": p.username, "M2": hex.EncodeToString(M2), "features": sessionFeatures(false)})
		return
	}
	if duressOK {
		if err := h.setCookieSession(w, r, p.username, true); err != nil {
			jsonErr(w, "could not create session", http.StatusInternalServerError)
			return
		}
		h.lockout.reset(p.username, ip)
		jsonOK(w, map[string]any{"username": p.username, "M2": hex.EncodeToString(M2d), "features": sessionFeatures(true)})
		return
	}
	h.lockout.fail(p.username, ip)
	jsonErr(w, "invalid credentials", http.StatusUnauthorized)
}

// requireLiveSession is the preamble every credential-changing endpoint shares:
// POST only, a session cookie, and a session that is still live. It writes the
// error response itself and reports whether the caller should continue.
//
// The three handlers below had these lines copied between them. The risk is not
// the repetition: it is that a check added to one and missed in another looks
// like nothing at all in a diff.
//
// The fresh-proof check is deliberately *not* folded in. Each handler calls it
// on its own line, where it can be seen.
func (h *Handler) requireLiveSession(w http.ResponseWriter, r *http.Request) (username string, duress bool, cookie *http.Cookie, ok bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return "", false, nil, false
	}
	c, err := sessionCookie(r)
	if err != nil {
		jsonErr(w, "not authenticated", http.StatusUnauthorized)
		return "", false, nil, false
	}
	name, isDuress, live := h.sess.getMeta(c.Value)
	if !live {
		jsonErr(w, "not authenticated", http.StatusUnauthorized)
		return "", false, nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, srpMaxBody)
	return name, isDuress, c, true
}

// SetVerifier installs a new salt+verifier for the logged-in user. It requires a
// fresh SRP proof of the credential the session was opened with, so possession of
// a session cookie is not by itself enough to rekey the account.
//
// In a duress (decoy) session it updates the DURESS
// credential instead: "change password" behaves exactly as a coercer would expect
// (the password they know keeps working, with its new value), while the real
// verifier — derived from a password the decoy user never typed — stays untouched
// and the real owner is never locked out.
func (h *Handler) SetVerifier(w http.ResponseWriter, r *http.Request) {
	username, duress, c, ok := h.requireLiveSession(w, r)
	if !ok {
		return
	}
	var body struct {
		Salt     string `json:"salt"`
		Verifier string `json:"verifier"`
		Kdf      string `json:"kdf"`
		Token    string `json:"token"`
		M1       string `json:"M1"`
		M1d      string `json:"M1d"`
	}
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.requireFreshProof(r, username, duress, body.Token, body.M1, body.M1d) {
		jsonErr(w, "re-authentication required", http.StatusUnauthorized)
		return
	}
	if duress {
		if err := h.store.setDuress(username, body.Salt, body.Verifier, body.Kdf); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.sess.deleteUserKindExcept(username, true, c.Value)
		jsonOK(w, map[string]string{"status": "ok"})
		return
	}
	if err := h.store.setVerifier(username, body.Salt, body.Verifier, body.Kdf); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	// A primary password change is the account owner's revocation event: close
	// every other session, primary and decoy alike, and rotate this browser's own
	// token so the pre-change value stops being an authenticator too.
	h.sess.deleteUser(username)
	if err := h.setCookieSession(w, r, username, false); err != nil {
		jsonErr(w, "could not refresh session", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "ok"})
}

// SetDuress sets or clears the duress credential for the logged-in user, after a
// fresh SRP proof of the credential this session was opened with. The
// browser computes (salt, verifier) from the duress password — it never reaches
// the server. A duress session must not be allowed to change the duress credential.
func (h *Handler) SetDuress(w http.ResponseWriter, r *http.Request) {
	username, duress, _, ok := h.requireLiveSession(w, r)
	if !ok {
		return
	}
	var body struct {
		Salt     string `json:"salt"`
		Verifier string `json:"verifier"`
		Kdf      string `json:"kdf"`
		Token    string `json:"token"`
		M1       string `json:"M1"`
		M1d      string `json:"M1d"`
	}
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	// The proof is checked before the decoy branch below, and against whichever
	// credential opened this session, so a decoy still answers 200 for its own
	// password and never reveals which branch it took.
	if !h.requireFreshProof(r, username, duress, body.Token, body.M1, body.M1d) {
		jsonErr(w, "re-authentication required", http.StatusUnauthorized)
		return
	}
	if err := validateDuressUpdate(body.Salt, body.Verifier, body.Kdf); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	if duress {
		// A decoy session must not modify duress settings — but answering 403 would
		// announce "this is the decoy". Validate and report success without writing.
		jsonOK(w, map[string]string{"status": "ok"})
		return
	}
	if err := h.store.setDuress(username, body.Salt, body.Verifier, body.Kdf); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.sess.deleteUserKind(username, true)
	jsonOK(w, map[string]string{"status": "ok"})
}

// DeleteAccount requires a fresh SRP proof and removes an account only from a
// primary session. A duress session
// preserves the real account but consumes the duress credential, so the password
// the coerced user surrendered genuinely stops working: a coercer who watches the
// deletion and then retries that password must not find the account still alive.
func (h *Handler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	username, duress, _, ok := h.requireLiveSession(w, r)
	if !ok {
		return
	}
	var body struct {
		Token string `json:"token"`
		M1    string `json:"M1"`
		M1d   string `json:"M1d"`
	}
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	// Destroying an account is irreversible, so a borrowed session must not be
	// able to do it either. A decoy proves its own credential and still gets the
	// deletion theatre below.
	if !h.requireFreshProof(r, username, duress, body.Token, body.M1, body.M1d) {
		jsonErr(w, "re-authentication required", http.StatusUnauthorized)
		return
	}
	if duress {
		// A write failure here must not change the response. Reporting an error
		// where a primary session reports success would itself expose the decoy,
		// which is a worse outcome than a duress password that outlives the wipe.
		if err := h.store.setDuress(username, "", "", ""); err != nil {
			log.Printf("[auth] could not clear duress credential on decoy delete: %v", err)
		}
		h.sess.deleteUserKind(username, true)
	} else {
		if err := h.store.deleteUser(username); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.sess.deleteUser(username)
		log.Printf("[auth] account deleted")
	}
	h.clearCookie(w, r)
	jsonOK(w, map[string]string{"status": "ok"})
}

// GenerateInvite issues a new invite code. Protected by the ADMIN_TOKEN env secret.
func (h *Handler) GenerateInvite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	admin := strings.TrimSpace(os.Getenv("ADMIN_TOKEN"))
	if admin == "" || !subtleEqual(r.Header.Get("X-Admin-Token"), admin) {
		jsonErr(w, "forbidden", http.StatusForbidden)
		return
	}
	code, err := h.invites.Generate()
	if err != nil {
		jsonErr(w, "could not generate invite", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"invite": code})
}

/* ── helpers ── */

func (h *Handler) startSession(w http.ResponseWriter, r *http.Request, username string) {
	token, err := h.sess.create(username, false)
	if err != nil {
		jsonErr(w, "could not create session", http.StatusInternalServerError)
		return
	}
	h.setCookie(w, r, token)
	jsonOK(w, map[string]string{"username": username})
}

func (h *Handler) setCookieSession(w http.ResponseWriter, r *http.Request, username string, duress bool) error {
	token, err := h.sess.create(username, duress)
	if err != nil {
		return err
	}
	h.setCookie(w, r, token)
	return nil
}

func (h *Handler) clearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- flags are explicit; Secure is false only for local HTTP development
		Name: sessionCookieName(r), Value: "", Path: "/", MaxAge: -1,
		Expires: time.Unix(1, 0), HttpOnly: true,
		Secure: middleware.IsSecureRequest(r), SameSite: http.SameSiteStrictMode,
	})
}

// verifyChallengeProofs always executes both SRP verifications before deciding
// which credential won. Invalid encodings are normalized to a full-length zero
// proof, keeping the expensive path consistent and avoiding a primary-vs-duress
// timing oracle.
func verifyChallengeProofs(p *pendingChallenge, m1Hex, m1dHex string) (primaryOK, duressOK bool, m2, m2d []byte) {
	M1, primaryEncodingOK := decodeSRPProof(m1Hex)
	M1d, duressEncodingOK := decodeSRPProof(m1dHex)
	m2, _, primaryErr := p.ch.Verify(p.A, M1)
	m2d, _, duressErr := p.chDuress.Verify(p.A, M1d)
	encodingOK := primaryEncodingOK && duressEncodingOK
	primaryOK = encodingOK && primaryErr == nil && p.real
	duressOK = encodingOK && duressErr == nil && p.realDuress
	return primaryOK, duressOK, m2, m2d
}

// requireFreshProof re-authenticates the caller of a credential-changing
// endpoint. A session cookie alone must not be enough to rekey an account:
// otherwise a borrowed session — an unlocked browser, a hostile extension — is a
// permanent takeover. The proof has to match the session's own credential, so a
// decoy session can only re-prove the duress password.
func (h *Handler) requireFreshProof(r *http.Request, username string, duress bool, token, m1, m1d string) bool {
	p, ok := h.challenges.take(token)
	if !ok || p.username != username {
		return false
	}
	ip := middleware.ClientTag(r)
	if allowed, _ := h.lockout.allowed(username, ip); !allowed {
		return false
	}
	primaryOK, duressOK, _, _ := verifyChallengeProofs(p, m1, m1d)
	proved := primaryOK
	if duress {
		proved = duressOK
	}
	if !proved {
		h.lockout.fail(username, ip)
		return false
	}
	h.lockout.reset(username, ip)
	return true
}

func decodeSRPProof(encoded string) ([]byte, bool) {
	proof := make([]byte, sha256.Size)
	if len(encoded) != sha256.Size*2 {
		return proof, false
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size {
		return proof, false
	}
	return decoded, true
}

func validateDuressUpdate(salt, verifier, kdf string) error {
	if salt == "" && verifier == "" && kdf == "" {
		return nil
	}
	return validateWritableSRPCredential(salt, verifier, kdf)
}

func hmacSum(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}
