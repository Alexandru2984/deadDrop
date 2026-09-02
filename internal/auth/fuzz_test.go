package auth

import "testing"

// ParseInviteCodes reads a file handed to `deaddrop invites import`, which is
// the one place codes enter the store without being minted. Anything it emits
// is merged into the invite pool, so a code it accepts but the validator would
// not is a way to put an unusable — or unexpected — entry in there.
func FuzzParseInviteCodes(f *testing.F) {
	f.Add([]byte("DD-FXAV-XKH6-JC22"))
	f.Add([]byte("DD-FXAV-XKH6-JC22\nDD-P6PJ-8G7R-9PPV-QJNM-A5Y2\n"))
	f.Add([]byte(`["DD-FXAV-XKH6-JC22"]`))
	f.Add([]byte(`[{"code":"DD-FXAV-XKH6-JC22"}]`))
	f.Add([]byte("  \n\t"))
	f.Add([]byte("["))
	f.Add([]byte("dd-fxav-xkh6-jc22"))
	f.Add([]byte("DD-FXAV-XKH6-JC22\x00"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, raw []byte) {
		codes, dropped, err := ParseInviteCodes(raw)
		if err != nil {
			if len(codes) != 0 || dropped != 0 {
				t.Fatalf("returned %d code(s) and %d dropped alongside an error", len(codes), dropped)
			}
			return
		}
		for _, code := range codes {
			if !validInviteCode(code) {
				t.Fatalf("emitted a code the validator rejects: %q from %q", code, raw)
			}
		}
		// Parsing is a pure read of the input; running it twice must not drift.
		again, againDropped, againErr := ParseInviteCodes(raw)
		if againErr != nil || len(again) != len(codes) || againDropped != dropped {
			t.Fatalf("not deterministic on %q", raw)
		}
	})
}
