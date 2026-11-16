package auth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

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

// GenerateInvitesForDir mints n invite codes at once and returns them. n must be >= 1.
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
