package auth

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"deaddrop/internal/srp"
)

func testSRPCredential(username, password string) (saltHex, verifierHex string) {
	salt := []byte("0123456789abcdef")
	verifier := srp.Verifier(username, password, salt)
	return hex.EncodeToString(salt), verifier.Text(16)
}

func TestSessionFeaturesDoNotRevealDuress(t *testing.T) {
	primary, _ := json.Marshal(sessionFeatures(false))
	duress, _ := json.Marshal(sessionFeatures(true))
	if !bytes.Equal(primary, duress) {
		t.Fatalf("session features reveal duress: primary=%s duress=%s", primary, duress)
	}
}

func TestLegacyFixtureUsesRequiredBcryptCost(t *testing.T) {
	const fixture = "$2a$12$tdjBzotGSk67bb6OGKGpkOtaOdt3yHNkO86tXY.xnZHnRQxhy7R1m"
	if err := validateStoredUser("Micu", user{Hash: fixture}); err != nil {
		t.Fatalf("CI legacy fixture rejected: %v", err)
	}
}

func TestDeleteAccountDuressPreservesPrimary(t *testing.T) {
	h := newTestHandler(t)
	salt, verifier := testSRPCredential("alice", "correct horse battery staple")
	if err := h.store.registerSRP("alice", salt, verifier, defaultKdf); err != nil {
		t.Fatal(err)
	}
	primaryToken, err := h.sess.create("alice", false)
	if err != nil {
		t.Fatal(err)
	}
	duressToken, err := h.sess.create("alice", true)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/account/delete", nil)
	req.AddCookie(&http.Cookie{Name: "dd_session", Value: duressToken})
	w := httptest.NewRecorder()
	h.DeleteAccount(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("duress delete: got %d: %s", w.Code, w.Body.String())
	}
	if _, ok := h.store.getUser("alice"); !ok {
		t.Fatal("duress delete removed the primary account")
	}
	if _, ok := h.sess.get(duressToken); ok {
		t.Fatal("duress delete did not close the decoy session")
	}
	if _, ok := h.sess.get(primaryToken); !ok {
		t.Fatal("duress delete invalidated a primary session")
	}

	secondToken, err := h.sess.create("alice", false)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/account/delete", nil)
	req.AddCookie(&http.Cookie{Name: "dd_session", Value: primaryToken})
	w = httptest.NewRecorder()
	h.DeleteAccount(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("primary delete: got %d: %s", w.Code, w.Body.String())
	}
	if _, ok := h.store.getUser("alice"); ok {
		t.Fatal("primary delete preserved the account")
	}
	if _, ok := h.sess.get(primaryToken); ok {
		t.Fatal("primary delete preserved its session")
	}
	if _, ok := h.sess.get(secondToken); ok {
		t.Fatal("primary delete did not invalidate all account sessions")
	}
}

func TestDummySecretStableAndPrivate(t *testing.T) {
	dir := t.TempDir()
	first, err := newChallengeStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newChallengeStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.secret, second.secret) {
		t.Fatal("dummy verifier secret changed across handler restarts")
	}
	info, err := os.Stat(filepath.Join(dir, "srp_dummy.key"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("dummy secret permissions = %o, want 600", got)
	}
}

func TestConcurrentSecretCreationPublishesOneCompleteValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	const workers = 12
	results := make(chan []byte, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			secret, err := loadOrCreateSecret(path, 32)
			if err != nil {
				errs <- err
				return
			}
			results <- secret
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Errorf("loadOrCreateSecret: %v", err)
	}
	var want []byte
	for got := range results {
		if want == nil {
			want = got
			continue
		}
		if !bytes.Equal(got, want) {
			t.Fatal("concurrent callers observed different secrets")
		}
	}
	if len(want) != 32 {
		t.Fatalf("published secret length = %d, want 32", len(want))
	}
}

func TestChallengeAndSessionCapsReapExpiredEntries(t *testing.T) {
	cs := &challengeStore{m: make(map[string]*pendingChallenge), secret: make([]byte, 32)}
	for i := 0; i < maxChallenges; i++ {
		cs.m[fmt.Sprintf("%064x", i)] = &pendingChallenge{expiry: time.Now().Add(time.Hour)}
	}
	if _, err := cs.put(&pendingChallenge{}); err == nil {
		t.Fatal("challenge store accepted an entry beyond its cap")
	}
	cs.m[fmt.Sprintf("%064x", 0)].expiry = time.Now().Add(-time.Second)
	if _, err := cs.put(&pendingChallenge{}); err != nil {
		t.Fatalf("challenge store did not reap an expired entry: %v", err)
	}

	sm := &sessions{m: make(map[string]*session)}
	for i := 0; i < maxSessions; i++ {
		sm.m[fmt.Sprintf("session-%d", i)] = &session{username: "alice", expiresAt: time.Now().Add(time.Hour)}
	}
	if _, err := sm.create("alice", false); err == nil {
		t.Fatal("session store accepted an entry beyond its cap")
	}
	sm.m["session-0"].expiresAt = time.Now().Add(-time.Second)
	if _, err := sm.create("alice", false); err != nil {
		t.Fatalf("session store did not reap an expired entry: %v", err)
	}
}

func TestDecodeSRPProofRequiresExactSHA256Encoding(t *testing.T) {
	good := hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if proof, ok := decodeSRPProof(good); !ok || len(proof) != 32 {
		t.Fatal("valid proof rejected")
	}
	for _, encoded := range []string{"", good[:62], good + "00", string(bytes.Repeat([]byte{'z'}, 64))} {
		proof, ok := decodeSRPProof(encoded)
		if ok || len(proof) != 32 || !bytes.Equal(proof, make([]byte, 32)) {
			t.Fatalf("malformed proof %q was not normalized", encoded)
		}
	}
}

func TestAtomicWriteJSONUsesPrivateFileAndNoPredictableTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := atomicWriteJSON(path, map[string]string{"state": "ok"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("state permissions = %o, want 600", got)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".state.json-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files left behind: %v", matches)
	}
}

func TestInviteIsNotConsumedBeforeCredentialValidation(t *testing.T) {
	t.Setenv("OPEN_REGISTRATION", "0")
	h := newTestHandler(t)
	code, err := h.invites.Generate()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(srpRegisterReq{
		Username: "alice", Salt: "00", Verifier: "not-hex", Kdf: defaultKdf, Invite: code,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/srp/register", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.SRPRegister(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid credential: got %d, want 400", w.Code)
	}
	remaining, err := h.invites.list()
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0] != code {
		t.Fatalf("invalid registration consumed invite: %v", remaining)
	}
}

func TestFailedRegistrationRestoresConsumedInvite(t *testing.T) {
	t.Setenv("OPEN_REGISTRATION", "0")
	h := newTestHandler(t)
	salt, verifier := testSRPCredential("alice", "primary password")
	if err := h.store.registerSRP("alice", salt, verifier, defaultKdf); err != nil {
		t.Fatal(err)
	}
	code, err := h.invites.Generate()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(srpRegisterReq{
		Username: "alice", Salt: salt, Verifier: verifier, Kdf: defaultKdf, Invite: code,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/srp/register", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.SRPRegister(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate registration: got %d, want 400", w.Code)
	}
	remaining, err := h.invites.list()
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0] != code {
		t.Fatalf("failed registration did not restore invite: %v", remaining)
	}
}
