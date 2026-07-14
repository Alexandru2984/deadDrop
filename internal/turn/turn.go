// Package turn issues short-lived TURN/STUN credentials to authenticated clients
// using coturn's "TURN REST API" scheme (use-auth-secret): the username is an
// expiry timestamp and the credential is base64(HMAC-SHA1(secret, username)).
//
// The long-term secret is shared with coturn out of band (env TURN_SECRET) and is
// never sent to the browser — only the derived, time-limited credential is.
package turn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const credTTL = time.Hour

const maxICEURLs = 8

// Config holds the TURN/STUN advertisement for clients.
type Config struct {
	Secret   string
	TurnURLs []string
	StunURLs []string
}

// FromEnv reads TURN_SECRET, TURN_URLS and STUN_URLS (comma-separated).
func FromEnv() Config {
	return Config{
		Secret:   strings.TrimSpace(os.Getenv("TURN_SECRET")),
		TurnURLs: splitCSV(os.Getenv("TURN_URLS")),
		StunURLs: splitCSV(os.Getenv("STUN_URLS")),
	}
}

// Enabled reports whether a usable TURN secret + URLs are configured.
func (c Config) Enabled() bool {
	return c.Secret != "" && len(c.TurnURLs) > 0
}

// Validate fails closed on partial or malformed ICE configuration. Operators
// still choose the host and must supply a randomly generated shared secret; this
// enforces a baseline length and browser-supported STUN/TURN URL shapes.
func (c Config) Validate() error {
	if len(c.TurnURLs) > maxICEURLs || len(c.StunURLs) > maxICEURLs {
		return fmt.Errorf("at most %d TURN and STUN URLs are allowed", maxICEURLs)
	}
	if (c.Secret == "") != (len(c.TurnURLs) == 0) {
		return errors.New("TURN_SECRET and TURN_URLS must be configured together")
	}
	if c.Secret != "" && len(c.Secret) < 32 {
		return errors.New("TURN_SECRET must be at least 32 characters")
	}
	for _, raw := range c.TurnURLs {
		if err := validateICEURL(raw, true); err != nil {
			return fmt.Errorf("invalid TURN URL: %w", err)
		}
	}
	for _, raw := range c.StunURLs {
		if err := validateICEURL(raw, false); err != nil {
			return fmt.Errorf("invalid STUN URL: %w", err)
		}
	}
	return nil
}

type iceServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Handler returns an ICE-server list with a freshly minted ephemeral credential.
// It must be wrapped with auth + same-origin + rate limiting by the caller.
func (c Config) Handler() http.HandlerFunc {
	validationErr := c.Validate()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if validationErr != nil {
			http.Error(w, "TURN configuration unavailable", http.StatusInternalServerError)
			return
		}
		servers := []iceServer{}
		if len(c.StunURLs) > 0 {
			servers = append(servers, iceServer{URLs: c.StunURLs})
		}
		if c.Enabled() {
			expiry := time.Now().Add(credTTL).Unix()
			nonce := make([]byte, 8)
			if _, err := rand.Read(nonce); err != nil {
				http.Error(w, "could not issue TURN credential", http.StatusInternalServerError)
				return
			}
			username := strconv.FormatInt(expiry, 10) + ":" + hex.EncodeToString(nonce)
			mac := hmac.New(sha1.New, []byte(c.Secret))
			mac.Write([]byte(username))
			cred := base64.StdEncoding.EncodeToString(mac.Sum(nil))
			servers = append(servers, iceServer{URLs: c.TurnURLs, Username: username, Credential: cred})
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-transform")
		json.NewEncoder(w).Encode(map[string]any{
			"iceServers": servers,
			"ttl":        int(credTTL.Seconds()),
		})
	}
}

func splitCSV(raw string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, p := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(p); s != "" {
			if _, duplicate := seen[s]; duplicate {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func validateICEURL(raw string, turn bool) error {
	if raw == "" || len(raw) > 512 || strings.TrimSpace(raw) != raw {
		return errors.New("empty, padded, or oversized URL")
	}
	separator := strings.IndexByte(raw, ':')
	if separator <= 0 {
		return errors.New("missing scheme")
	}
	scheme := raw[:separator]
	if turn {
		if scheme != "turn" && scheme != "turns" {
			return errors.New("expected turn: or turns:")
		}
	} else if scheme != "stun" && scheme != "stuns" {
		return errors.New("expected stun: or stuns:")
	}
	rest := raw[separator+1:]
	if rest == "" || strings.HasPrefix(rest, "//") {
		return errors.New("expected scheme:host form")
	}
	u, err := url.Parse(scheme + "://" + rest)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.Fragment != "" || strings.Contains(rest, "#") || strings.HasSuffix(u.Host, ":") || u.ForceQuery {
		return errors.New("malformed ICE URL")
	}
	hostname := u.Hostname()
	if hostname == "" || strings.Contains(hostname, "%") || (net.ParseIP(hostname) == nil && !validDNSHostname(hostname)) {
		return errors.New("invalid ICE host")
	}
	if port := u.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return errors.New("invalid ICE port")
		}
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return errors.New("invalid ICE query")
	}
	if !turn {
		if len(query) != 0 {
			return errors.New("STUN URL must not have query parameters")
		}
		return nil
	}
	if len(query) == 0 {
		return nil
	}
	values, ok := query["transport"]
	if !ok || len(query) != 1 || len(values) != 1 || (values[0] != "udp" && values[0] != "tcp") {
		return errors.New("TURN query may only select udp or tcp transport")
	}
	return nil
}

func validDNSHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	numeric := true
	for _, c := range host {
		if c < '0' || c > '9' {
			if c != '.' {
				numeric = false
			}
		}
	}
	if numeric { // reject ambiguous non-canonical IPv4-looking hostnames
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || !isAlphaNum(label[0]) || !isAlphaNum(label[len(label)-1]) {
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

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
