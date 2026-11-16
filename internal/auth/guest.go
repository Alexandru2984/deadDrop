package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"deaddrop/internal/strictjson"
)

// Guests: one person, without an account, in one room.
//
// An account holder who is already in a room can mint a pass for it. Whoever
// presents the pass first gets a session that can do exactly one thing — join
// that room — and nothing an account can: no rooms of its own, no passes, no
// account settings. Nothing is written to disk and no name is asked for, so
// the server ends up knowing less about a guest than about anyone else.
//
// A pass is a bearer token. That is acceptable only because getting into a
// room proves nothing: every pair in it still compares a safety code before a
// word can be exchanged, and someone who took the link gets a locked screen
// and a host who can see the codes do not match.
const (
	guestPrincipalPrefix = "guest:"
	// Long enough to send a link and have it opened; short enough that one
	// forgotten in a chat history is dead by the time anyone finds it.
	guestPassTTL = 15 * time.Minute
	// A guest session cannot be renewed, so this bounds a conversation.
	guestSessionTTL = 2 * time.Hour

	maxGuestPasses = 2048
	// A newer pass replaces the oldest one past this: the latest link is the
	// one the host means.
	maxGuestPassesPerHost = 6
	// Guests an account can have signed in at once. A room holds six people.
	maxGuestSessionsPerHost = 12

	guestPassHexLen = 32
)

var errGuestCapacity = errors.New("guest capacity reached")

func isGuestPrincipal(principal string) bool {
	return strings.HasPrefix(principal, guestPrincipalPrefix)
}

type guestPass struct {
	room string
	host string
	// hostKey is the session that vouched. The pass dies with it, which is
	// how signing out, changing the password or deleting the account also
	// withdraws every link they handed out.
	hostKey string
	minted  time.Time
	expires time.Time
}

// guestPasses is keyed like sessions: by the hash of the token, so nothing in
// memory can be presented as a pass.
type guestPasses struct {
	mu sync.Mutex
	m  map[string]*guestPass
}

func newGuestPasses() *guestPasses {
	g := &guestPasses{m: make(map[string]*guestPass)}
	go g.reap()
	return g
}

func (g *guestPasses) reap() {
	for range time.NewTicker(time.Minute).C {
		g.mu.Lock()
		g.removeExpiredLocked(time.Now())
		g.mu.Unlock()
	}
}

func (g *guestPasses) removeExpiredLocked(now time.Time) {
	for key, pass := range g.m {
		if !now.Before(pass.expires) {
			delete(g.m, key)
		}
	}
}

func (g *guestPasses) mint(host, hostKey, room string) (string, error) {
	raw := make([]byte, guestPassHexLen/2)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()
	g.removeExpiredLocked(now)
	for {
		held := 0
		var oldestKey string
		var oldest time.Time
		for key, pass := range g.m {
			if pass.host != host {
				continue
			}
			held++
			if oldestKey == "" || pass.minted.Before(oldest) {
				oldestKey, oldest = key, pass.minted
			}
		}
		if held < maxGuestPassesPerHost {
			break
		}
		delete(g.m, oldestKey)
	}
	if len(g.m) >= maxGuestPasses {
		return "", errGuestCapacity
	}
	g.m[tokenKey(token)] = &guestPass{
		room: room, host: host, hostKey: hostKey,
		minted: now, expires: now.Add(guestPassTTL),
	}
	return token, nil
}

// redeem takes the pass out of the table whatever happens next: it works once.
func (g *guestPasses) redeem(token string) (*guestPass, bool) {
	if len(token) != guestPassHexLen || !isLowerHexString(token) {
		return nil, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	key := tokenKey(token)
	pass, ok := g.m[key]
	if !ok {
		return nil, false
	}
	delete(g.m, key)
	if !time.Now().Before(pass.expires) {
		return nil, false
	}
	return pass, true
}

func isLowerHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return s != ""
}

// createGuest opens a session for a redeemed pass. It cannot be renewed or
// widened: the room is fixed here and read back on every use.
func (sm *sessions) createGuest(room, host string) (string, error) {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	principal := guestPrincipalPrefix + hex.EncodeToString(id)
	for {
		tok, err := genToken()
		if err != nil {
			return "", err
		}
		sm.mu.Lock()
		now := time.Now()
		sm.removeExpiredLocked(now)
		if len(sm.m) >= maxSessions {
			sm.mu.Unlock()
			return "", errors.New("session limit reached")
		}
		if _, collision := sm.m[tokenKey(tok)]; collision {
			sm.mu.Unlock()
			continue
		}
		vouched := 0
		for _, s := range sm.m {
			if s.guestRoom != "" && s.host == host {
				vouched++
			}
		}
		if vouched >= maxGuestSessionsPerHost {
			sm.mu.Unlock()
			return "", errGuestCapacity
		}
		entry := &session{
			username: principal, guestRoom: room, host: host,
			expiresAt: now.Add(guestSessionTTL),
		}
		entry.lastSeen.Store(now.UnixNano())
		sm.m[tokenKey(tok)] = entry
		sm.mu.Unlock()
		return tok, nil
	}
}

// liveKey reports whether the session stored under key is still usable,
// without counting as activity on it.
func (sm *sessions) liveKey(key string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.m[key]
	return ok && s.live(time.Now())
}

// access is getMeta plus the room a guest session is confined to ("" for an
// account).
func (sm *sessions) access(token string) (principal string, guestRoom string, ok bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, found := sm.m[tokenKey(token)]
	now := time.Now()
	if !found || !s.live(now) {
		return "", "", false
	}
	s.lastSeen.Store(now.UnixNano())
	return s.username, s.guestRoom, true
}

// SessionGuestRoom returns the one room a guest session may join. ok is false
// for an account session and for no session at all.
func (h *Handler) SessionGuestRoom(r *http.Request) (room string, ok bool) {
	c, err := sessionCookie(r)
	if err != nil {
		return "", false
	}
	_, room, live := h.sess.access(c.Value)
	return room, live && room != ""
}

type guestPassReq struct {
	Room string `json:"room"`
}

type guestRedeemReq struct {
	Token string `json:"token"`
}

// GuestPass mints a one-time pass for one room. Only an account can: a guest
// who could mint passes would be an account in everything but name.
func (h *Handler) GuestPass(validRoom func(string) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		c, err := sessionCookie(r)
		if err != nil {
			jsonErr(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		principal, guestRoom, live := h.sess.access(c.Value)
		if !live {
			jsonErr(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		if guestRoom != "" {
			jsonErr(w, "not available to guests", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, srpMaxBody)
		var body guestPassReq
		if err := strictjson.DecodeObject(r.Body, &body); err != nil {
			jsonErr(w, "bad request", http.StatusBadRequest)
			return
		}
		if !validRoom(body.Room) {
			jsonErr(w, "invalid room code", http.StatusBadRequest)
			return
		}
		token, err := h.guests.mint(principal, tokenKey(c.Value), body.Room)
		if err != nil {
			w.Header().Set("Retry-After", "60")
			jsonErr(w, "guest links are temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		jsonOK(w, map[string]any{"token": token, "ttl": int(guestPassTTL.Seconds())})
	}
}

// GuestRedeem turns a pass into a guest session. Every failure reads the
// same: unknown, used, expired and withdrawn are not told apart, so a pass
// cannot be probed for which of those it is.
func (h *Handler) GuestRedeem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Somebody signed in to an account joins with it, and keeps it: a guest
	// cookie must never quietly replace an account's.
	if c, err := sessionCookie(r); err == nil {
		if _, guestRoom, live := h.sess.access(c.Value); live && guestRoom == "" {
			jsonErr(w, "already signed in", http.StatusConflict)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, srpMaxBody)
	var body guestRedeemReq
	if err := strictjson.DecodeObject(r.Body, &body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	pass, ok := h.guests.redeem(body.Token)
	if !ok || !h.sess.liveKey(pass.hostKey) {
		jsonErr(w, "invalid or used guest link", http.StatusForbidden)
		return
	}
	token, err := h.sess.createGuest(pass.room, pass.host)
	if err != nil {
		w.Header().Set("Retry-After", "60")
		jsonErr(w, "guest links are temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	// Replacing an earlier guest session of this browser: end it rather than
	// leave it to expire.
	if c, err := sessionCookie(r); err == nil {
		h.sess.delete(c.Value)
	}
	h.setCookie(w, r, token)
	jsonOK(w, map[string]any{"username": "guest", "guest": true, "room": pass.room})
}
