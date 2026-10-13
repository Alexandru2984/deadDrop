package middleware

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"
)

// FuzzParseProxyLine feeds arbitrary first lines to the onion listener's PROXY
// parser. Anything it accepts must be exactly tor's form, and the circuit it
// returns must be the low 32 bits of a source inside tor's range.
func FuzzParseProxyLine(f *testing.F) {
	for _, seed := range []string{
		"PROXY TCP6 fc00:dead:beef:4dad::1:2 ::1 65535 42\r\n",
		"PROXY TCP6 fc00:dead:beef:4dad::ffff:ffff ::1 65535 80\r\n",
		"PROXY TCP4 127.0.0.1 127.0.0.1 1 2\r\n",
		"PROXY UNKNOWN\r\n",
		"GET / HTTP/1.1\r\n",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		circuit, err := parseProxyLine(line)
		if err != nil {
			return
		}
		if !strings.HasPrefix(line, "PROXY TCP6 ") || !strings.HasSuffix(line, "\r\n") {
			t.Fatalf("accepted a line not in tor's form: %q", line)
		}
		id, convErr := strconv.ParseUint(circuit, 10, 32)
		if convErr != nil {
			t.Fatalf("circuit %q is not a 32-bit number", circuit)
		}
		src := net.ParseIP(strings.Split(line, " ")[2]).To16()
		if src == nil || !bytes.Equal(src[:12], onionCircuitPrefix.To16()[:12]) {
			t.Fatalf("accepted a source outside tor's circuit range: %q", line)
		}
		got := uint64(src[12])<<24 | uint64(src[13])<<16 | uint64(src[14])<<8 | uint64(src[15])
		if got != id {
			t.Fatalf("circuit %d does not match source %v", id, src)
		}
	})
}
