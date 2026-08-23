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

// The bcrypt login path is gone. A users.json carrying one must stop the server
// rather than decode into an account that can never authenticate — and rather
// than reintroduce a credential the client could be told to send in the clear.
func TestStoredBcryptCredentialIsRejected(t *testing.T) {
	const fixture = "$2a$12$tdjBzotGSk67bb6OGKGpkOtaOdt3yHNkO86tXY.xnZHnRQxhy7R1m"
	if err := validateStoredUser("Micu", user{Hash: fixture}); err == nil {
		t.Fatal("a stored bcrypt credential was accepted")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "users.json"),
		[]byte(`{"Micu":{"hash":"`+fixture+`"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHandler(dir); err == nil {
		t.Fatal("NewHandler accepted a users.json with a bcrypt credential")
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
	secondDuressToken, err := h.sess.create("alice", true)
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
	if _, ok := h.sess.get(secondDuressToken); ok {
		t.Fatal("duress delete did not close every decoy session")
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

func TestCredentialChangesRevokeTheRightSessions(t *testing.T) {
	h := newTestHandler(t)
	salt, verifier := testSRPCredential("alice", "primary password")
	if err := h.store.registerSRP("alice", salt, verifier, defaultKdf); err != nil {
		t.Fatal(err)
	}
	duressSalt, duressVerifier := testSRPCredential("alice", "decoy password")
	if err := h.store.setDuress("alice", duressSalt, duressVerifier, defaultKdf); err != nil {
		t.Fatal(err)
	}
	primaryKeep := createTestSession(t, h, "alice", false)
	primaryOther := createTestSession(t, h, "alice", false)
	duressOther := createTestSession(t, h, "alice", true)

	newSalt, newVerifier := testSRPCredential("alice", "new primary password")
	callVerifierUpdate(t, h, primaryKeep, newSalt, newVerifier)
	assertSession(t, h, primaryKeep, true, "current primary session")
	assertSession(t, h, primaryOther, false, "other primary session")
	assertSession(t, h, duressOther, false, "existing duress session")

	primaryOther = createTestSession(t, h, "alice", false)
	duressKeep := createTestSession(t, h, "alice", true)
	duressOther = createTestSession(t, h, "alice", true)
	newDuressSalt, newDuressVerifier := testSRPCredential("alice", "new decoy password")
	callVerifierUpdate(t, h, duressKeep, newDuressSalt, newDuressVerifier)
	assertSession(t, h, duressKeep, true, "current duress session")
	assertSession(t, h, duressOther, false, "other duress session")
	assertSession(t, h, primaryKeep, true, "unrelated primary session")
	assertSession(t, h, primaryOther, true, "second unrelated primary session")

	duressOther = createTestSession(t, h, "alice", true)
	thirdSalt, thirdVerifier := testSRPCredential("alice", "third decoy password")
	body, _ := json.Marshal(map[string]string{
		"salt": thirdSalt, "verifier": thirdVerifier, "kdf": defaultKdf,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/account/duress", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "dd_session", Value: primaryKeep})
	w := httptest.NewRecorder()
	h.SetDuress(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("SetDuress status=%d: %s", w.Code, w.Body.String())
	}
	assertSession(t, h, duressKeep, false, "old current duress session")
	assertSession(t, h, duressOther, false, "old other duress session")
	assertSession(t, h, primaryKeep, true, "primary session after duress change")
}

func callVerifierUpdate(t *testing.T, h *Handler, token, salt, verifier string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"salt": salt, "verifier": verifier, "kdf": defaultKdf,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/account/verifier", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "dd_session", Value: token})
	w := httptest.NewRecorder()
	h.SetVerifier(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("SetVerifier status=%d: %s", w.Code, w.Body.String())
	}
}

func createTestSession(t *testing.T, h *Handler, username string, duress bool) string {
	t.Helper()
	token, err := h.sess.create(username, duress)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func assertSession(t *testing.T, h *Handler, token string, want bool, label string) {
	t.Helper()
	_, got := h.sess.get(token)
	if got != want {
		t.Fatalf("%s validity=%t, want %t", label, got, want)
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

func TestPrivatePersistenceRejectsEscapingSymlinks(t *testing.T) {
	dir := t.TempDir()
	outsideDir := t.TempDir()
	outsideSecret := filepath.Join(outsideDir, "outside.key")
	outsideValue := bytes.Repeat([]byte{0x42}, 32)
	if err := os.WriteFile(outsideSecret, outsideValue, 0600); err != nil {
		t.Fatal(err)
	}
	secretLink := filepath.Join(dir, "secret.key")
	if err := os.Symlink(outsideSecret, secretLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := loadOrCreateSecret(secretLink, 32); err == nil {
		t.Fatal("secret loader followed a link outside its data root")
	}

	outsideJSON := filepath.Join(outsideDir, "outside.json")
	if err := os.WriteFile(outsideJSON, []byte(`{"untouched":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	stateLink := filepath.Join(dir, "state.json")
	if err := os.Symlink(outsideJSON, stateLink); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteJSON(stateLink, map[string]bool{"inside": true}); err != nil {
		t.Fatal(err)
	}
	outsideAfter, err := os.ReadFile(outsideJSON)
	if err != nil || string(outsideAfter) != `{"untouched":true}` {
		t.Fatalf("outside target changed: %q, %v", outsideAfter, err)
	}
	info, err := os.Lstat(stateLink)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("state link was not atomically replaced by a regular file: %v", err)
	}
}

func TestPrivatePersistenceRejectsSymlinkDataRoot(t *testing.T) {
	realDir := t.TempDir()
	linkParent := t.TempDir()
	linkDir := filepath.Join(linkParent, "data")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := NewHandler(linkDir); err == nil {
		t.Fatal("symlink data root was accepted")
	}
	if _, err := GenerateInviteForDir(linkDir); err == nil {
		t.Fatal("invite store accepted a symlink data root")
	}
}

func TestPrivateStoresRejectSymlinkFiles(t *testing.T) {
	dir := t.TempDir()
	outsideDir := t.TempDir()
	outsideUsers := filepath.Join(outsideDir, "users.json")
	if err := os.WriteFile(outsideUsers, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideUsers, filepath.Join(dir, "users.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := NewHandler(dir); err == nil {
		t.Fatal("user store accepted a symlink file")
	}

	inviteDir := t.TempDir()
	outsideInvites := filepath.Join(outsideDir, "invites.json")
	if err := os.WriteFile(outsideInvites, []byte(`[]`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideInvites, filepath.Join(inviteDir, "invites.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := ListInvitesForDir(inviteDir); err == nil {
		t.Fatal("invite store accepted a symlink file")
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

// A coercer who watches the account get "deleted" from the decoy session will
// retry the password they were handed. It has to stop working, or the deletion
// is visibly theatre and the decoy is blown.
func TestDeleteAccountFromDecoyConsumesTheDuressCredential(t *testing.T) {
	h := newTestHandler(t)
	salt, verifier := testSRPCredential("alice", "the real password")
	if err := h.store.registerSRP("alice", salt, verifier, defaultKdf); err != nil {
		t.Fatal(err)
	}
	duressSalt, duressVerifier := testSRPCredential("alice", "the decoy password")
	if err := h.store.setDuress("alice", duressSalt, duressVerifier, defaultKdf); err != nil {
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
		t.Fatalf("decoy delete: got %d: %s", w.Code, w.Body.String())
	}

	u, ok := h.store.getUser("alice")
	if !ok {
		t.Fatal("decoy delete removed the real account")
	}
	if u.hasDuress() {
		t.Fatal("the surrendered duress password still works after a decoy delete")
	}
	if u.Verifier != verifier || u.Salt != salt {
		t.Fatal("decoy delete altered the primary credential")
	}
}
