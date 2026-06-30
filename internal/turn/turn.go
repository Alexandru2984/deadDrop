// Package turn issues short-lived TURN/STUN credentials to authenticated clients
// using coturn's "TURN REST API" scheme (use-auth-secret): the username is an
// expiry timestamp and the credential is base64(HMAC-SHA1(secret, username)).
//
// The long-term secret is shared with coturn out of band (env TURN_SECRET) and is
// never sent to the browser — only the derived, time-limited credential is.
package turn

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const credTTL = 12 * time.Hour

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

type iceServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Handler returns an ICE-server list with a freshly minted ephemeral credential.
// It must be wrapped with auth + same-origin + rate limiting by the caller.
func (c Config) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		servers := []iceServer{}
		if len(c.StunURLs) > 0 {
			servers = append(servers, iceServer{URLs: c.StunURLs})
		}
		if c.Enabled() {
			expiry := time.Now().Add(credTTL).Unix()
			username := strconv.FormatInt(expiry, 10)
			mac := hmac.New(sha1.New, []byte(c.Secret))
			mac.Write([]byte(username))
			cred := base64.StdEncoding.EncodeToString(mac.Sum(nil))
			servers = append(servers, iceServer{URLs: c.TurnURLs, Username: username, Credential: cred})
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]any{
			"iceServers": servers,
			"ttl":        int(credTTL.Seconds()),
		})
	}
}

func splitCSV(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
