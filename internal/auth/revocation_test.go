package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func authenticateProof(t *testing.T, h *Handler, proof map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.SRPAuthenticate(w, httptest.NewRequest(http.MethodPost, "/api/srp/authenticate", bytes.NewReader(body)))
	return w
}

// A challenge is an authorization against a particular account/credential,
// not a promise to authenticate that username for the next minute regardless
// of what the owner changes in the meantime.
func TestPendingProofRevocation(t *testing.T) {
	for _, test := range []struct {
		name       string
		duress     bool
		change     string
		wantStatus int
	}{
		{"primary password change", false, "primary", http.StatusUnauthorized},
		{"same primary verifier rewritten", false, "same-primary", http.StatusUnauthorized},
		{"primary change revokes pending decoy", true, "primary", http.StatusUnauthorized},
		{"decoy password change", true, "duress", http.StatusUnauthorized},
		{"decoy change preserves primary proof", false, "duress", http.StatusOK},
		{"cleared and restored decoy", true, "restore-duress", http.StatusUnauthorized},
		{"deleted account", false, "delete", http.StatusUnauthorized},
		{"deleted decoy account", true, "delete", http.StatusUnauthorized},
		{"decoy deletion consumes pending decoy", true, "delete-duress", http.StatusUnauthorized},
		{"decoy deletion preserves pending primary", false, "delete-duress", http.StatusOK},
		{"same username and verifier re-registered", false, "re-register", http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newTestHandler(t)
			salt, verifier := testSRPCredential("alice", "primary password")
			if err := h.store.registerSRP("alice", salt, verifier, defaultKdf); err != nil {
				t.Fatal(err)
			}
			dSalt, dVerifier := testSRPCredential("alice", "decoy password")
			if err := h.store.setDuress("alice", dSalt, dVerifier, defaultKdf); err != nil {
				t.Fatal(err)
			}
			password := "primary password"
			if test.duress {
				password = "decoy password"
			}
			proof := freshProof(t, h, "alice", password)
			owner := createTestSession(t, h, "alice", false)
			switch test.change {
			case "primary":
				nSalt, nVerifier := testSRPCredential("alice", "new primary password")
				callVerifierUpdate(t, h, owner, "alice", "primary password", nSalt, nVerifier)
			case "same-primary":
				callVerifierUpdate(t, h, owner, "alice", "primary password", salt, verifier)
			case "delete-duress":
				if w := deleteAccountRequest(t, h, createTestSession(t, h, "alice", true), "alice", "decoy password"); w.Code != http.StatusOK {
					t.Fatalf("decoy delete: %d %s", w.Code, w.Body.String())
				}
			case "duress":
				nSalt, nVerifier := testSRPCredential("alice", "new decoy password")
				if w := setDuressRequest(t, h, owner, "alice", "primary password", nSalt, nVerifier); w.Code != http.StatusOK {
					t.Fatalf("change duress: %d %s", w.Code, w.Body.String())
				}
			case "restore-duress":
				clear, _ := json.Marshal(freshProof(t, h, "alice", "primary password"))
				r := httptest.NewRequest(http.MethodPost, "/api/account/duress", bytes.NewReader(clear))
				r.AddCookie(&http.Cookie{Name: "dd_session", Value: owner})
				w := httptest.NewRecorder()
				h.SetDuress(w, r)
				if w.Code != http.StatusOK {
					t.Fatalf("clear duress: %d %s", w.Code, w.Body.String())
				}
				if w := setDuressRequest(t, h, owner, "alice", "primary password", dSalt, dVerifier); w.Code != http.StatusOK {
					t.Fatalf("restore duress: %d %s", w.Code, w.Body.String())
				}
			case "delete", "re-register":
				if w := deleteAccountRequest(t, h, owner, "alice", "primary password"); w.Code != http.StatusOK {
					t.Fatalf("delete: %d %s", w.Code, w.Body.String())
				}
				if test.change == "re-register" {
					// Even restoring the exact old verifier must create a new
					// account incarnation, not revive the pending authorization.
					if err := h.store.registerSRP("alice", salt, verifier, defaultKdf); err != nil {
						t.Fatal(err)
					}
				}
			}
			w := authenticateProof(t, h, proof)
			if w.Code != test.wantStatus {
				t.Fatalf("pending proof: got %d, want %d: %s", w.Code, test.wantStatus, w.Body.String())
			}
			if test.wantStatus == http.StatusUnauthorized && len(w.Result().Cookies()) != 0 {
				t.Fatal("revoked proof issued a session cookie")
			}
		})
	}
}

func TestConsumedChallengeCannotIssueSessionAfterCredentialChange(t *testing.T) {
	h := newTestHandler(t)
	registerTestAccount(t, h, "alice", "primary password")
	proof := freshProof(t, h, "alice", "primary password")
	raw, _ := json.Marshal(proof)
	r := httptest.NewRequest(http.MethodPost, "/api/srp/authenticate", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	done := make(chan struct{})
	// Keep authorization waiting after the challenge is consumed. Simulate the
	// owner's credential commit under the same lock before allowing it to resume.
	h.accountMu.Lock()
	locked := true
	defer func() {
		if locked {
			h.accountMu.Unlock()
		}
	}()
	go func() { defer close(done); h.SRPAuthenticate(w, r) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.challenges.mu.Lock()
		_, pending := h.challenges.m[proof["token"]]
		h.challenges.mu.Unlock()
		if !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("authenticate did not consume its challenge")
		}
		time.Sleep(time.Millisecond)
	}
	salt, verifier := testSRPCredential("alice", "replacement password")
	if err := h.store.setVerifier("alice", salt, verifier, defaultKdf); err != nil {
		t.Fatal(err)
	}
	h.sess.deleteUser("alice")
	h.accountMu.Unlock()
	locked = false
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("authenticate did not finish")
	}
	if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
		t.Fatalf("consumed old challenge issued access: %d %s", w.Code, w.Body.String())
	}
}

// Hold the request body after requireLiveSession succeeds. The account owner
// can revoke that cookie before the request resumes, even when its password
// proof remains valid (signing out other sessions does not change a password).
type pausedAuthBody struct {
	*bytes.Reader
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (b *pausedAuthBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.resume })
	return b.Reader.Read(p)
}

func TestAccountActionRechecksRevokedSessionAfterBodyRead(t *testing.T) {
	for _, action := range []string{"verifier", "duress", "delete", "signout-others"} {
		t.Run(action, func(t *testing.T) {
			h := newTestHandler(t)
			registerTestAccount(t, h, "alice", "primary password")
			owner := createTestSession(t, h, "alice", false)
			borrowed := createTestSession(t, h, "alice", false)
			payload := freshProof(t, h, "alice", "primary password")
			payload["salt"], payload["verifier"] = testSRPCredential("alice", "replacement password")
			payload["kdf"] = defaultKdf
			if action == "delete" || action == "signout-others" {
				delete(payload, "salt")
				delete(payload, "verifier")
				delete(payload, "kdf")
			}
			raw, _ := json.Marshal(payload)
			body := &pausedAuthBody{Reader: bytes.NewReader(raw), entered: make(chan struct{}), resume: make(chan struct{})}
			var resume sync.Once
			t.Cleanup(func() { resume.Do(func() { close(body.resume) }) })
			r := httptest.NewRequest(http.MethodPost, "/api/account/"+action, body)
			r.AddCookie(&http.Cookie{Name: "dd_session", Value: borrowed})
			w := httptest.NewRecorder()
			done := make(chan struct{})
			handler := map[string]http.HandlerFunc{"verifier": h.SetVerifier, "duress": h.SetDuress, "delete": h.DeleteAccount, "signout-others": h.SignOutOthers}[action]
			go func() { defer close(done); handler(w, r) }()
			select {
			case <-body.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("action did not reach its body")
			}
			out, _ := json.Marshal(freshProof(t, h, "alice", "primary password"))
			ownerReq := httptest.NewRequest(http.MethodPost, "/api/account/signout-others", bytes.NewReader(out))
			ownerReq.AddCookie(&http.Cookie{Name: "dd_session", Value: owner})
			ownerResponse := httptest.NewRecorder()
			h.SignOutOthers(ownerResponse, ownerReq)
			if ownerResponse.Code != http.StatusOK {
				t.Fatalf("owner signout: %d %s", ownerResponse.Code, ownerResponse.Body.String())
			}
			resume.Do(func() { close(body.resume) })
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("action did not finish")
			}
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("revoked action: got %d, want 401: %s", w.Code, w.Body.String())
			}
			assertSession(t, h, owner, true, "owner after revoked request")
		})
	}
}

func TestStaleProofCannotRekeyWithANewSession(t *testing.T) {
	h := newTestHandler(t)
	salt, verifier := testSRPCredential("alice", "primary password")
	if err := h.store.registerSRP("alice", salt, verifier, defaultKdf); err != nil {
		t.Fatal(err)
	}
	proof := freshProof(t, h, "alice", "primary password")
	newSalt, newVerifier := testSRPCredential("alice", "new primary password")
	callVerifierUpdate(t, h, createTestSession(t, h, "alice", false), "alice", "primary password", newSalt, newVerifier)
	attackerSalt, attackerVerifier := testSRPCredential("alice", "attacker password")
	proof["salt"], proof["verifier"], proof["kdf"] = attackerSalt, attackerVerifier, defaultKdf
	body, _ := json.Marshal(proof)
	r := httptest.NewRequest(http.MethodPost, "/api/account/verifier", bytes.NewReader(body))
	r.AddCookie(&http.Cookie{Name: "dd_session", Value: createTestSession(t, h, "alice", false)})
	w := httptest.NewRecorder()
	h.SetVerifier(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("stale reauthentication: got %d, want 401: %s", w.Code, w.Body.String())
	}
	if u, _ := h.store.getUser("alice"); u.Verifier != newVerifier {
		t.Fatal("a stale proof changed the new password")
	}
}
