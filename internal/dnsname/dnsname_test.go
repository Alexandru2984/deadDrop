package dnsname

import "strings"

import "testing"

func TestValid(t *testing.T) {
	for _, host := range []string{
		"dead.micutu.com", "example.com", "a.b", "xn--80ak6aa92e.com",
		"host-with-dashes.example", "DEAD.MICUTU.COM", "MiXeD.Case.Example",
		strings.Repeat("a", 63) + ".com",
	} {
		if !Valid(host) {
			t.Errorf("Valid(%q) = false, want true", host)
		}
	}

	for _, host := range []string{
		"", ".", "..", "a..b", "-lead.example", "trail-.example",
		"under_score.example", "space host.example", "has:colon.example",
		// All-numeric: an IPv4 address in disguise, which would give the same
		// destination two spellings and let one of them skip the caller's
		// literal-address handling.
		"127.0.0.1", "10.0.0.1", "8.8.8.8",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 200) + "com",
	} {
		if Valid(host) {
			t.Errorf("Valid(%q) = true, want false", host)
		}
	}
}

// The origin path lowercases before validating and the TURN path does not, so
// the shared rule has to accept both and leave canonicalisation to the caller.
func TestValidDNSIsCaseInsensitive(t *testing.T) {
	if Valid("Example.COM") != Valid("example.com") {
		t.Fatal("case changes the verdict")
	}
}
