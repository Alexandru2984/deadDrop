// Package dnsname validates DNS hostnames for the two places that accept one
// from configuration: the allowed-origin list and the STUN/TURN URLs.
//
// Both had their own copy, and the copies had already drifted — one accepted
// uppercase labels and the other did not. Neither was wrong for its own caller,
// because the origin path lowercases first, but that is precisely the kind of
// difference nobody notices until the fix goes into one copy and not the other.
package dnsname

import "strings"

const (
	maxHostLen  = 253
	maxLabelLen = 63
)

// ValidDNS reports whether host is a syntactically valid DNS hostname.
//
// Case-insensitive, because DNS is. Callers that need a canonical form should
// lowercase before comparing; this only judges shape.
//
// An all-numeric name is rejected: it would be an IPv4 address written in a
// non-canonical form, and letting one through means two spellings of the same
// destination — one of which skips whatever check the caller applies to
// literal addresses.
func Valid(host string) bool {
	if len(host) == 0 || len(host) > maxHostLen {
		return false
	}
	if isNumericOnly(host) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > maxLabelLen {
			return false
		}
		if !isAlphaNum(label[0]) || !isAlphaNum(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !isAlphaNum(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func isNumericOnly(host string) bool {
	for _, c := range host {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
