package middleware

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

// A control that degrades silently is one nobody can act on. Filling the visitor
// table turns every new client away — the safe answer, and an outage — so it has
// to say so rather than leave an operator inferring it from complaints.
func TestRateLimiterReportsSaturation(t *testing.T) {
	var out bytes.Buffer
	log.SetOutput(&out)
	defer log.SetOutput(nil)

	rl := NewRateLimiter(10, 15, time.Minute)
	rl.mu.Lock()
	for i := 0; i < maxRateLimitVisitors; i++ {
		rl.visitors[string(rune(i))+"-filler"] = &bucket{tokens: 1, lastSeen: time.Now()}
	}
	rl.mu.Unlock()

	if rl.Allow("a-brand-new-client") {
		t.Fatal("a full table must refuse a client it cannot track")
	}
	if !strings.Contains(out.String(), "visitor table full") {
		t.Fatalf("saturation was not reported: %q", out.String())
	}

	// The report must not become the flood it is describing.
	before := strings.Count(out.String(), "visitor table full")
	for i := 0; i < 50; i++ {
		rl.Allow("another-new-client")
	}
	if got := strings.Count(out.String(), "visitor table full"); got != before {
		t.Fatalf("logged %d times for 50 refusals, want %d", got, before)
	}

	// Nothing identifying: the table is keyed by an HMAC of the address, and
	// this service exists not to keep that record.
	if strings.Contains(out.String(), "brand-new-client") {
		t.Fatal("the log named a client key")
	}
}
