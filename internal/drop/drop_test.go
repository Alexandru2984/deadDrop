package drop

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	idA = "0123456789abcdef0123456789abcdef"
	idB = "fedcba9876543210fedcba9876543210"
)

var (
	testBox = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 64))
	testIV  = base64.StdEncoding.EncodeToString(make([]byte, ivBytes))
)

func asAccount(name string) Principal {
	return func(*http.Request) (string, bool) { return name, name != "" }
}

func call(t *testing.T, h http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodPost, "/api/drop", bytes.NewReader(raw)))
	return w
}

func TestABoxIsCollectedOnceAndThenGone(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	put := s.PutHandler(asAccount("alice"))
	if w := call(t, put, map[string]any{"id": idA, "box": testBox, "iv": testIV, "ttl": 3600}); w.Code != http.StatusOK {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	if w := call(t, put, map[string]any{"id": idA, "box": testBox, "iv": testIV, "ttl": 3600}); w.Code != http.StatusConflict {
		t.Fatalf("a second box under the same name: %d, want 409", w.Code)
	}

	check := s.CheckHandler(asAccount("bob"))
	w := call(t, check, map[string]any{"ids": []string{idA, idB}})
	var present struct{ Present []string }
	_ = json.Unmarshal(w.Body.Bytes(), &present)
	if len(present.Present) != 1 || present.Present[0] != idA {
		t.Fatalf("check = %s", w.Body.String())
	}

	take := s.TakeHandler(asAccount("bob"))
	w = call(t, take, map[string]any{"id": idA})
	var got struct{ Box, IV string }
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != http.StatusOK || got.Box != testBox || got.IV != testIV {
		t.Fatalf("take: %d %s", w.Code, w.Body.String())
	}
	if w := call(t, take, map[string]any{"id": idA}); w.Code != http.StatusNotFound {
		t.Fatalf("a box collected twice: %d, want 404", w.Code)
	}
	if s.Count() != 0 || s.total != 0 || len(s.byAccount) != 0 {
		t.Fatalf("collecting left state behind: %d boxes, %d bytes, %v", s.Count(), s.total, s.byAccount)
	}
	if strings.Contains(w.Header().Get("Cache-Control"), "store") == false {
		t.Fatal("drop answers must not be cached")
	}
}

func TestBoxesSurviveARestartAndExpire(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put("alice", idA, testBox, testIV, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("alice", idB, testBox, testIV, time.Hour); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, idA+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "alice") {
		t.Fatalf("who left a box was written to disk: %s", raw)
	}
	info, _ := os.Stat(filepath.Join(dir, idA+".json"))
	if info.Mode().Perm() != 0600 {
		t.Fatalf("box file mode %v, want 0600", info.Mode().Perm())
	}

	// One expires while the server is down.
	var e entry
	_ = json.Unmarshal(raw, &e)
	e.Expires = time.Now().Add(-time.Minute).Unix()
	raw, _ = json.Marshal(e)
	if err := os.WriteFile(filepath.Join(dir, idA+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, idA+".deadbeef.tmp"), []byte("half"), 0600); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.Present([]string{idA, idB}); len(got) != 1 || got[0] != idB {
		t.Fatalf("after a restart: %v, want only the box still in time", got)
	}
	if _, err := os.Stat(filepath.Join(dir, idA+".json")); !os.IsNotExist(err) {
		t.Fatal("an expired box was left on disk")
	}
	if _, err := os.Stat(filepath.Join(dir, idA+".deadbeef.tmp")); !os.IsNotExist(err) {
		t.Fatal("a half-written box was left on disk")
	}

	again.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	again.Sweep()
	if again.Count() != 0 {
		t.Fatal("a box outlived its time")
	}
	if _, err := os.Stat(filepath.Join(dir, idB+".json")); !os.IsNotExist(err) {
		t.Fatal("an expired box was swept from memory but left on disk")
	}
}

func TestDropRefusals(t *testing.T) {
	s, _ := Open("")
	put := s.PutHandler(asAccount("alice"))
	bad := []map[string]any{
		{"id": strings.ToUpper(idA), "box": testBox, "iv": testIV, "ttl": 3600},
		{"id": idA[:30], "box": testBox, "iv": testIV, "ttl": 3600},
		{"id": idA, "box": "not base64!", "iv": testIV, "ttl": 3600},
		{"id": idA, "box": base64.StdEncoding.EncodeToString([]byte("short")), "iv": testIV, "ttl": 3600},
		{"id": idA, "box": strings.Repeat("A", MaxBoxChars+4), "iv": testIV, "ttl": 3600},
		{"id": idA, "box": testBox, "iv": base64.StdEncoding.EncodeToString(make([]byte, 16)), "ttl": 3600},
		{"id": idA, "box": testBox, "iv": testIV, "ttl": 3601},
		{"id": idA, "box": testBox, "iv": testIV, "ttl": 30 * 86400},
	}
	for i, body := range bad {
		if w := call(t, put, body); w.Code != http.StatusBadRequest {
			t.Errorf("bad put %d: got %d, want 400", i, w.Code)
		}
	}
	if w := call(t, put, map[string]any{"id": idA, "box": testBox, "iv": testIV, "ttl": 3600, "from": "x"}); w.Code != http.StatusBadRequest {
		t.Errorf("an unknown field: got %d, want 400", w.Code)
	}
	nobody := s.PutHandler(asAccount(""))
	if w := call(t, nobody, map[string]any{"id": idA, "box": testBox, "iv": testIV, "ttl": 3600}); w.Code != http.StatusForbidden {
		t.Errorf("no account (a guest): got %d, want 403", w.Code)
	}
	if w := call(t, s.CheckHandler(asAccount("")), map[string]any{"ids": []string{idA}}); w.Code != http.StatusForbidden {
		t.Errorf("a guest checking: got %d, want 403", w.Code)
	}
	if w := call(t, s.TakeHandler(asAccount("")), map[string]any{"id": idA}); w.Code != http.StatusForbidden {
		t.Errorf("a guest collecting: got %d, want 403", w.Code)
	}
	many := make([]string, MaxCheckIDs+1)
	for i := range many {
		many[i] = idA
	}
	if w := call(t, s.CheckHandler(asAccount("bob")), map[string]any{"ids": many}); w.Code != http.StatusBadRequest {
		t.Errorf("checking too many names: got %d, want 400", w.Code)
	}
	if s.Count() != 0 {
		t.Fatal("a refused request stored something")
	}
}

func TestOneAccountCannotFillTheStore(t *testing.T) {
	s, _ := Open("")
	id := func(i int) string { return strings.Repeat("0", IDHexLen-4) + strings.ToLower(hex4(i)) }
	for i := 0; i < MaxPerAccount; i++ {
		if err := s.Put("alice", id(i), testBox, testIV, time.Hour); err != nil {
			t.Fatalf("box %d: %v", i, err)
		}
	}
	if err := s.Put("alice", id(MaxPerAccount), testBox, testIV, time.Hour); err != ErrTooMany {
		t.Fatalf("box past the account's allowance: %v, want ErrTooMany", err)
	}
	if err := s.Put("bob", id(MaxPerAccount), testBox, testIV, time.Hour); err != nil {
		t.Fatalf("another account was refused: %v", err)
	}
	if _, _, err := s.Take(id(0)); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("alice", id(MaxPerAccount+1), testBox, testIV, time.Hour); err != nil {
		t.Fatalf("a collected box still counted against its sender: %v", err)
	}
}

func hex4(i int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[i>>12&15], digits[i>>8&15], digits[i>>4&15], digits[i&15]})
}
