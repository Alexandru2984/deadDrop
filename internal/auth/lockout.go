package auth

import (
	"log"
	"sync"
	"time"
)

const (
	maxLockoutEntries = 100_000
	lockoutThreshold  = 5
	lockoutWindow     = 15 * time.Minute
	// Failures one account may take from all sources together per window
	// before new sign-ins for it are spaced out; the per-source lockout alone
	// let many addresses guess in parallel.
	accountFailBudget = 100
	accountFailWindow = time.Hour
	accountSlowGap    = 10 * time.Second
	// A source that signed in to the account recently is not spaced out, so
	// a flood of guesses cannot take every slot from the account's owner.
	knownSourceTTL = 24 * time.Hour
)

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

// accountBudget counts one account's failures from every source together.
type accountBudget struct {
	fails       int
	windowStart time.Time
	nextAllowed time.Time
}

type lockout struct {
	mu sync.Mutex
	m  map[string]*lockEntry
	// accounts and known are in memory only, like everything here, and keyed
	// the same way: username, and an HMAC of the address that cannot be
	// turned back into one.
	accounts map[string]*accountBudget
	known    map[string]time.Time // lockKey → when it stops counting as known
	// A saturated table stops recording failures, which quietly removes the
	// per-account throttle for everyone not already in it. At most one line a
	// minute, and no key: the table is keyed by username and an HMAC of the
	// address, and writing those to disk would build the record this service
	// exists not to keep.
	lastSaturationLog time.Time
}

func newLockout() *lockout {
	l := &lockout{m: make(map[string]*lockEntry), accounts: make(map[string]*accountBudget), known: make(map[string]time.Time)}
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

// admitChallenge is allowed plus the account-wide budget, for the step that
// starts a sign-in. Past its budget an account takes a new sign-in from an
// unfamiliar source once every accountSlowGap: guessing from a thousand
// addresses then goes as fast as from one, while a source the account
// signed in from recently is never held up.
func (l *lockout) admitChallenge(username, ip string) (bool, time.Duration) {
	if ok, wait := l.allowed(username, ip); !ok {
		return false, wait
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.accounts[username]
	if b == nil || now.Sub(b.windowStart) > accountFailWindow || b.fails < accountFailBudget {
		return true, 0
	}
	if until, ok := l.known[lockKey(username, ip)]; ok && now.Before(until) {
		return true, 0
	}
	if now.Before(b.nextAllowed) {
		return false, b.nextAllowed.Sub(now)
	}
	b.nextAllowed = now.Add(accountSlowGap)
	return true, 0
}

func (l *lockout) fail(username, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.noteAccountFailLocked(username)
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

func (l *lockout) noteAccountFailLocked(username string) {
	now := time.Now()
	b := l.accounts[username]
	if b == nil {
		if len(l.accounts) >= maxLockoutEntries {
			l.removeStaleLocked(now)
			if len(l.accounts) >= maxLockoutEntries {
				l.noteSaturationLocked(now)
				return
			}
		}
		b = &accountBudget{windowStart: now}
		l.accounts[username] = b
	}
	if now.Sub(b.windowStart) > accountFailWindow {
		b.fails, b.windowStart = 0, now
	}
	b.fails++
}

func (l *lockout) reset(username, ip string) {
	l.mu.Lock()
	key := lockKey(username, ip)
	delete(l.m, key)
	if len(l.known) < maxLockoutEntries {
		l.known[key] = time.Now().Add(knownSourceTTL)
	}
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
	for username, b := range l.accounts {
		if now.Sub(b.windowStart) > accountFailWindow && now.After(b.nextAllowed) {
			delete(l.accounts, username)
		}
	}
	for key, until := range l.known {
		if now.After(until) {
			delete(l.known, key)
		}
	}
}
