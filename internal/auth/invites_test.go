package auth

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestGenerateInvitesBulk(t *testing.T) {
	dir := t.TempDir()
	codes, err := GenerateInvitesForDir(dir, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 5 {
		t.Fatalf("want 5 minted, got %d", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate minted: %s", c)
		}
		seen[c] = true
		if !validInviteCode(c) {
			t.Fatalf("minted an invalid-looking code: %s", c)
		}
	}
	// Persisted and appends (does not overwrite) on a second batch.
	got, _ := ListInvitesForDir(dir)
	if len(got) != 5 {
		t.Fatalf("persisted want 5, got %d", len(got))
	}
	if _, err := GenerateInvitesForDir(dir, 2); err != nil {
		t.Fatal(err)
	}
	if got2, _ := ListInvitesForDir(dir); len(got2) != 7 {
		t.Fatalf("want 7 after appending, got %d", len(got2))
	}
	// n < 1 is an error.
	if _, err := GenerateInvitesForDir(dir, 0); err == nil {
		t.Fatal("expected error for count 0")
	}
}

func TestImportInvitesDedupAndValidate(t *testing.T) {
	dir := t.TempDir()
	existing, _ := GenerateInvitesForDir(dir, 1)

	in := []string{
		existing[0],         // duplicate of a stored code → skip
		"DD-ABCD-EFGH-JKMP", // new, valid
		"dd-abcd-efgh-jkmp", // same as above once uppercased → skip (within-batch dup)
		"DD-NEW2-3456-789A", // new, valid
		"garbage",           // malformed → skip
		"",                  // empty → skip
	}
	added, skipped, err := ImportInvitesForDir(dir, in)
	if err != nil {
		t.Fatal(err)
	}
	if added != 2 || skipped != 4 {
		t.Fatalf("want added=2 skipped=4, got added=%d skipped=%d", added, skipped)
	}
	if got, _ := ListInvitesForDir(dir); len(got) != 3 {
		t.Fatalf("want 3 total (1 seed + 2 imported), got %d", len(got))
	}
	// An imported code must be consumable by the real registration path.
	consumed, err := newInvites(dir).consume("DD-ABCD-EFGH-JKMP")
	if err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("imported code should be consumable at registration")
	}
}

func TestParseInviteCodes(t *testing.T) {
	// JSON array form (what `invites export` writes).
	if got := ParseInviteCodes([]byte(`["DD-AAAA-BBBB-CCCC", "DD-DDDD-EEEE-FFFF"]`)); len(got) != 2 {
		t.Fatalf("json form: want 2, got %d", len(got))
	}
	// Plain whitespace / newline form.
	if got := ParseInviteCodes([]byte("DD-AAAA-BBBB-CCCC\nDD-DDDD-EEEE-FFFF\n")); len(got) != 2 {
		t.Fatalf("line form: want 2, got %d", len(got))
	}
	// Whitespace-only input yields nothing (not a bogus one-element slice).
	if got := ParseInviteCodes([]byte("   \n\t")); len(got) != 0 {
		t.Fatalf("empty input: want 0, got %d", len(got))
	}
}

func TestValidInviteCode(t *testing.T) {
	good := []string{
		"DD-ABCD-EFGH-JKMP",
		"dd-abcd-efgh-jkmp",
		"DD-ABCD-EFGH-JKMP-NPQR-STUV",
	}
	for _, c := range good {
		if !validInviteCode(c) {
			t.Errorf("validInviteCode(%q) = false, want true", c)
		}
	}
	bad := []string{
		"", "garbage", "XX-ABCD", "DD-", "DD-@@@@", "not a code",
		"DD-2345-6789",              // too short
		"DD-ABCD-EFGH-IJKL",         // ambiguous I/L
		"DD-ABCD--EFGH-JKLM",        // malformed grouping
		"DD-ABCD-EFGH-JKLM-NPQR",    // neither legacy nor current format
		"DD-ABCD-EFGH-JKLM-NPQR-ST", // truncated final group
	}
	for _, c := range bad {
		if validInviteCode(c) {
			t.Errorf("validInviteCode(%q) = true, want false", c)
		}
	}
}

func TestInviteStoresCoordinateAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	const workers = 8
	const perWorker = 20
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := newInvites(dir).generateN(perWorker)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	codes, err := ListInvitesForDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != workers*perWorker {
		t.Fatalf("concurrent generation lost updates: got %d, want %d", len(codes), workers*perWorker)
	}
	seen := make(map[string]bool, len(codes))
	for _, code := range codes {
		if seen[code] {
			t.Fatalf("duplicate invite generated: %s", code)
		}
		seen[code] = true
	}
}

func TestInviteConsumeSurfacesStoreErrors(t *testing.T) {
	dir := t.TempDir()
	iv := newInvites(dir)
	iv.path = filepath.Join(dir, "store-directory")
	if err := os.Mkdir(iv.path, 0700); err != nil {
		t.Fatal(err)
	}
	if consumed, err := iv.consume("DD-ABCD-EFGH-JKMP"); err == nil || consumed {
		t.Fatalf("consume on invalid store: consumed=%v err=%v", consumed, err)
	}
}

func TestInviteRestoreIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	iv := newInvites(dir)
	code, err := iv.Generate()
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := iv.consume(code)
	if err != nil || !consumed {
		t.Fatalf("consume: consumed=%v err=%v", consumed, err)
	}
	if err := iv.restore(code); err != nil {
		t.Fatal(err)
	}
	if err := iv.restore(code); err != nil {
		t.Fatal(err)
	}
	codes, err := iv.list()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 1 || codes[0] != code {
		t.Fatalf("idempotent restore produced %v", codes)
	}
}
