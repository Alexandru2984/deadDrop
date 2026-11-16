// Package drop keeps messages left for someone who is not online.
//
// What it stores is opaque: a sealed box under a random-looking name, until
// the person it is for collects it or its time runs out. The keys never reach
// the server. Two people who have verified each other agree on them in a live,
// end-to-end encrypted session, and every message is sealed with a key of its
// own, ratcheted forward and forgotten once used, under a name derived from
// that key — so two messages for the same person do not share a name, and a
// device seized later cannot open what was already collected.
//
// What the server does learn, and cannot avoid learning: which account left a
// box and when, which account asked after it and collected it, its padded
// size, and how long it was to wait. The account that left a box is held in
// memory only, to cap how much one account can leave; nothing about who is
// written to disk.
package drop

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"deaddrop/internal/strictjson"
)

const (
	IDHexLen = 32
	// The sealed text, padded and base64-encoded. A drop is a message, not a
	// file: files go peer to peer and never touch the server.
	MaxBoxChars = 24 * 1024
	ivBytes     = 12
	minBoxBytes = 16 // an AES-GCM tag and nothing else

	MaxDrops      = 20000
	MaxTotalBytes = 256 << 20
	// Boxes one account may have waiting at once. Counted in memory, so a
	// restart forgets who left what; the boxes still expire on time.
	MaxPerAccount = 50
	// Names one check may ask about: every contact's next few boxes.
	MaxCheckIDs = 128

	maxBodyBytes = 64 * 1024
	maxFileBytes = MaxBoxChars + 1024
)

// TTLs a box may be given: an hour, a day, a week. A fixed menu, so the TTL
// says nothing finer about the sender than which of three they picked.
var allowedTTLs = map[int]time.Duration{
	3600:   time.Hour,
	86400:  24 * time.Hour,
	604800: 7 * 24 * time.Hour,
}

// MaxTTL is the longest a box can wait.
const MaxTTL = 7 * 24 * time.Hour

var (
	ErrExists   = errors.New("a box with this name is already waiting")
	ErrFull     = errors.New("drop storage is full")
	ErrTooMany  = errors.New("too many boxes waiting from this account")
	errNotFound = errors.New("not found")
)

type entry struct {
	Box     string `json:"box"`
	IV      string `json:"iv"`
	Expires int64  `json:"expires"`
	account string // memory only
}

func (e *entry) size() int { return len(e.Box) + len(e.IV) }

// Store holds waiting boxes in memory and, when given a directory, one file
// per box there, so a restart or a deploy does not lose them.
type Store struct {
	mu        sync.Mutex
	root      *os.Root
	drops     map[string]*entry
	total     int
	byAccount map[string]int
	now       func() time.Time
}

// Open loads the boxes waiting in dir, dropping any that expired meanwhile.
// An empty dir keeps everything in memory.
func Open(dir string) (*Store, error) {
	s := &Store{drops: make(map[string]*entry), byAccount: make(map[string]int), now: time.Now}
	if dir == "" {
		return s, nil
	}
	clean := filepath.Clean(dir)
	if err := os.MkdirAll(clean, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("drop directory is not a real directory")
	}
	root, err := os.OpenRoot(clean)
	if err != nil {
		return nil, err
	}
	if err := root.Chmod(".", 0700); err != nil { // #nosec G302 -- directories require execute permission
		_ = root.Close()
		return nil, err
	}
	s.root = root
	if err := s.load(); err != nil {
		_ = root.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	dir, err := s.root.Open(".")
	if err != nil {
		return err
	}
	names, err := dir.Readdirnames(-1)
	_ = dir.Close()
	if err != nil {
		return err
	}
	now := s.now().Unix()
	for _, name := range names {
		id, isBox := strings.CutSuffix(name, ".json")
		if !isBox || !ValidID(id) {
			// A temporary file left by a write that never finished.
			if strings.HasSuffix(name, ".tmp") {
				_ = s.root.Remove(name)
			}
			continue
		}
		e, err := s.readBox(name)
		if err != nil || e.Expires <= now || !validBox(e.Box, e.IV) {
			_ = s.root.Remove(name)
			continue
		}
		if len(s.drops) >= MaxDrops || s.total+e.size() > MaxTotalBytes {
			_ = s.root.Remove(name)
			continue
		}
		s.drops[id] = e
		s.total += e.size()
	}
	return nil
}

func (s *Store) readBox(name string) (*entry, error) {
	f, err := s.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFileBytes {
		return nil, errors.New("box file too large")
	}
	var e entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// writeBox writes the box beside its final name and renames it into place,
// so a crash leaves the old state or the new one, never half of one.
func (s *Store) writeBox(id string, e *entry) error {
	if s.root == nil {
		return nil
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	tmp := id + "." + hex.EncodeToString(random[:]) + ".tmp"
	f, err := s.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, werr := f.Write(raw)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = s.root.Remove(tmp)
		return err
	}
	if err := s.root.Rename(tmp, id+".json"); err != nil {
		_ = s.root.Remove(tmp)
		return err
	}
	return nil
}

func (s *Store) removeLocked(id string) {
	e, ok := s.drops[id]
	if !ok {
		return
	}
	delete(s.drops, id)
	s.total -= e.size()
	if e.account != "" {
		if s.byAccount[e.account] <= 1 {
			delete(s.byAccount, e.account)
		} else {
			s.byAccount[e.account]--
		}
	}
	if s.root != nil {
		_ = s.root.Remove(id + ".json")
	}
}

// Put leaves a box. A name already in use is refused rather than replaced:
// names come from the recipient's ratchet, and a second box under one would
// be either a mistake or someone trying to overwrite the first.
func (s *Store) Put(account, id, box, iv string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepLocked(now)
	if _, taken := s.drops[id]; taken {
		return ErrExists
	}
	if s.byAccount[account] >= MaxPerAccount {
		return ErrTooMany
	}
	e := &entry{Box: box, IV: iv, Expires: now.Add(ttl).Unix(), account: account}
	if len(s.drops) >= MaxDrops || s.total+e.size() > MaxTotalBytes {
		return ErrFull
	}
	if err := s.writeBox(id, e); err != nil {
		return err
	}
	s.drops[id] = e
	s.total += e.size()
	s.byAccount[account]++
	return nil
}

// Present reports which of ids have a box waiting.
func (s *Store) Present(ids []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Unix()
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if e, ok := s.drops[id]; ok && e.Expires > now {
			out = append(out, id)
		}
	}
	return out
}

// Take hands over a box and forgets it: collecting is the end of it.
func (s *Store) Take(id string) (box, iv string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.drops[id]
	if !ok {
		return "", "", errNotFound
	}
	s.removeLocked(id)
	if e.Expires <= s.now().Unix() {
		return "", "", errNotFound
	}
	return e.Box, e.IV, nil
}

// Sweep drops every box whose time is up.
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
}

func (s *Store) sweepLocked(now time.Time) {
	cutoff := now.Unix()
	for id, e := range s.drops {
		if e.Expires <= cutoff {
			s.removeLocked(id)
		}
	}
}

// Reap sweeps once a minute, for as long as the process runs.
func (s *Store) Reap() {
	for range time.NewTicker(time.Minute).C {
		s.Sweep()
	}
}

// Count is how many boxes are waiting, for the health check.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.drops)
}

// ValidID reports whether id is the shape of a box name.
func ValidID(id string) bool {
	if len(id) != IDHexLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validBox(box, iv string) bool {
	if len(box) == 0 || len(box) > MaxBoxChars {
		return false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(box)
	if err != nil || len(raw) < minBoxBytes {
		return false
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(iv)
	return err == nil && len(nonce) == ivBytes
}

// ── HTTP ──

// Principal says whose request this is: an account, or nobody. A guest is
// nobody here; it has no contacts to leave anything for.
type Principal func(*http.Request) (string, bool)

type putReq struct {
	ID  string `json:"id"`
	Box string `json:"box"`
	IV  string `json:"iv"`
	TTL int    `json:"ttl"`
}

type checkReq struct {
	IDs []string `json:"ids"`
}

type takeReq struct {
	ID string `json:"id"`
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := strictjson.DecodeObject(r.Body, v); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

func account(w http.ResponseWriter, r *http.Request, who Principal) (string, bool) {
	principal, ok := who(r)
	if !ok || principal == "" {
		jsonErr(w, "not available", http.StatusForbidden)
		return "", false
	}
	return principal, true
}

// PutHandler leaves a box: POST {id, box, iv, ttl}.
func (s *Store) PutHandler(who Principal) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body putReq
		if !decode(w, r, &body) {
			return
		}
		principal, ok := account(w, r, who)
		if !ok {
			return
		}
		ttl, allowed := allowedTTLs[body.TTL]
		if !ValidID(body.ID) || !validBox(body.Box, body.IV) || !allowed {
			jsonErr(w, "invalid parameter", http.StatusBadRequest)
			return
		}
		switch err := s.Put(principal, body.ID, body.Box, body.IV, ttl); {
		case err == nil:
			jsonOK(w, map[string]any{"ok": true})
		case errors.Is(err, ErrExists):
			jsonErr(w, "exists", http.StatusConflict)
		case errors.Is(err, ErrTooMany):
			jsonErr(w, "too many waiting", http.StatusTooManyRequests)
		default:
			w.Header().Set("Retry-After", "300")
			jsonErr(w, "drops are temporarily unavailable", http.StatusServiceUnavailable)
		}
	}
}

// CheckHandler says which names have a box waiting: POST {ids}.
func (s *Store) CheckHandler(who Principal) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body checkReq
		if !decode(w, r, &body) {
			return
		}
		if _, ok := account(w, r, who); !ok {
			return
		}
		if len(body.IDs) > MaxCheckIDs {
			jsonErr(w, "invalid parameter", http.StatusBadRequest)
			return
		}
		for _, id := range body.IDs {
			if !ValidID(id) {
				jsonErr(w, "invalid parameter", http.StatusBadRequest)
				return
			}
		}
		jsonOK(w, map[string]any{"present": s.Present(body.IDs)})
	}
}

// TakeHandler collects a box, which removes it: POST {id}.
func (s *Store) TakeHandler(who Principal) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body takeReq
		if !decode(w, r, &body) {
			return
		}
		if _, ok := account(w, r, who); !ok {
			return
		}
		if !ValidID(body.ID) {
			jsonErr(w, "invalid parameter", http.StatusBadRequest)
			return
		}
		box, iv, err := s.Take(body.ID)
		if err != nil {
			jsonErr(w, "not found", http.StatusNotFound)
			return
		}
		jsonOK(w, map[string]any{"box": box, "iv": iv})
	}
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
