package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	deaddrop "deaddrop"
)

// `deaddrop doctor` answers a different question from `check-config`.
//
// check-config reads the environment and says whether the settings are legal.
// That is a build-time question, and it stays true while the service is down,
// the backup silently stops running, or the binary is serving a bundle nobody
// recognises. Doctor asks what is actually true of the machine right now, which
// is the only question worth asking before letting anyone in.
//
// It exits non-zero if anything failed, so it can be a cron job or a
// pre-invite gate rather than something a human has to remember to read.

const backupDir = "/srv/backups/deaddrop"

type finding struct {
	name   string
	detail string
	err    error
	// warn marks something worth seeing that should not fail the run — a check
	// that could not be performed rather than one that came back bad.
	warn bool
}

func runDoctor() {
	checks := []func() finding{
		checkConfiguration,
		checkEmbeddedBundle,
		checkServiceLiveness,
		checkDeployedBundle,
		checkDeliveredBundle,
		checkBackupFreshness,
	}

	var failed, warned int
	for _, check := range checks {
		f := check()
		switch {
		case f.err != nil && f.warn:
			warned++
			fmt.Printf("  ?  %-22s %v\n", f.name, f.err)
		case f.err != nil:
			failed++
			fmt.Printf("  ✗  %-22s %v\n", f.name, f.err)
		default:
			fmt.Printf("  ✓  %-22s %s\n", f.name, f.detail)
		}
	}

	switch {
	case failed > 0:
		fmt.Printf("\n%d check(s) failed\n", failed)
		os.Exit(1)
	case warned > 0:
		fmt.Printf("\nall checks passed, %d could not be performed\n", warned)
	default:
		fmt.Println("\nall checks passed")
	}
}

func checkConfiguration() finding {
	if err := checkRuntimeConfiguration(); err != nil {
		return finding{name: "configuration", err: err}
	}
	return finding{name: "configuration", detail: "valid"}
}

func checkEmbeddedBundle() finding {
	if err := deaddrop.VerifyEmbeddedBundle(); err != nil {
		return finding{name: "served bundle", err: err}
	}
	return finding{name: "served bundle", detail: "matches its own manifest"}
}

// checkServiceLiveness talks to the running service, not to this process. The
// health route answers only after a round trip through the goroutine that
// routes signaling, so a wedged hub fails here while the page still loads.
func checkServiceLiveness() finding {
	port, _, host, err := configuredListenAddress()
	if err != nil {
		return finding{name: "service", err: err}
	}
	url := fmt.Sprintf("http://%s/api/health", joinHostPort(host, port))
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return finding{name: "service", err: fmt.Errorf("not answering on %s: %w", url, err)}
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	var payload struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(body, &payload)
	if resp.StatusCode != http.StatusOK || payload.Status != "ok" {
		return finding{name: "service", err: fmt.Errorf("unhealthy: HTTP %d %s",
			resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	return finding{name: "service", detail: "hub answering on " + url}
}

// checkDeployedBundle asks whether the service that is running is serving the
// client this checkout builds.
//
// checkEmbeddedBundle proves a binary is internally consistent, and it is happy
// to say so about a binary from months ago. Nothing noticed that production had
// been running a build from three days earlier while every fix since sat in the
// tree unshipped — and the fixes it was missing were the reason the tree had
// moved.
//
// The bundle is embedded, so the manifest the service hands out identifies the
// client inside the binary exactly. Comparing it with the one on disk costs a
// single request and answers the only version question that matters.
func checkDeployedBundle() finding {
	onDisk, err := os.ReadFile("web/SHA256SUMS")
	if err != nil {
		// Running from somewhere other than a checkout is legitimate.
		return finding{name: "deployed bundle", warn: true,
			err: fmt.Errorf("no checkout here to compare against: %v", err)}
	}
	port, _, host, err := configuredListenAddress()
	if err != nil {
		return finding{name: "deployed bundle", err: err}
	}
	url := fmt.Sprintf("http://%s/SHA256SUMS", joinHostPort(host, port))
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return finding{name: "deployed bundle", err: fmt.Errorf("cannot read %s: %w", url, err)}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return finding{name: "deployed bundle", err: fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)}
	}
	served, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return finding{name: "deployed bundle", err: err}
	}

	if string(served) == string(onDisk) {
		return finding{name: "deployed bundle", detail: "the running service serves this checkout's client"}
	}
	return finding{name: "deployed bundle", err: fmt.Errorf(
		"the running service serves a different client from this checkout "+
			"(served %s, on disk %s) — the source has moved on and the deploy has not",
		fmt.Sprintf("%x", sha256.Sum256(served))[:16],
		fmt.Sprintf("%x", sha256.Sum256(onDisk))[:16])}
}

// checkDeliveredBundle compares what the origin serves against what the public
// URL actually delivers.
//
// Every other check here is about this machine. This one is about everything
// between it and a browser — a CDN, a reverse proxy, anything that terminates
// TLS. The client is the entire security product: an edge that rewrites one
// script tag has replaced the cryptography, and the server would never know.
//
// The page is the important half. Its script tags carry subresource integrity
// hashes, so a module rewritten anywhere downstream fails in the browser — as
// long as the page itself is the one the origin sent. Checking the entry module
// too costs one request and catches an edge that rewrites assets while leaving
// the HTML alone.
//
// DEPLOY.md has asked for this comparison by hand after every deploy since the
// Cloudflare front went up. Nobody runs it by hand after every deploy.
func checkDeliveredBundle() finding {
	public := publicOrigin()
	if public == "" {
		return finding{name: "delivered bundle", warn: true,
			err: errors.New("no public origin in ALLOWED_ORIGINS — nothing to compare against")}
	}
	port, _, host, err := configuredListenAddress()
	if err != nil {
		return finding{name: "delivered bundle", err: err}
	}
	origin := "http://" + joinHostPort(host, port)

	client := &http.Client{Timeout: 20 * time.Second}
	return compareDelivery(client, origin, public, deliveryPaths)
}

// deliveryPaths is the minimal set worth comparing. The page carries the
// subresource-integrity hashes for everything else, so a module rewritten
// downstream fails in the browser as long as the page is the origin's. The entry
// module is checked too, for an edge that leaves HTML alone and rewrites assets.
var deliveryPaths = []string{"/", "/js/app.js"}

// compareDelivery is separated from the check so a test can watch it fail: a
// security check that has only ever been seen passing is not a check.
func compareDelivery(client *http.Client, origin, public string, paths []string) finding {
	for _, path := range paths {
		local, err := fetchDigest(client, origin+path)
		if err != nil {
			return finding{name: "delivered bundle", err: fmt.Errorf("origin %s: %w", path, err)}
		}
		remote, err := fetchDigest(client, public+path)
		if err != nil {
			// Being unable to reach the public URL from the box itself is
			// common and is not evidence of tampering.
			return finding{name: "delivered bundle", warn: true,
				err: fmt.Errorf("cannot reach %s%s from here: %v", public, path, err)}
		}
		if local != remote {
			return finding{name: "delivered bundle", err: fmt.Errorf(
				"%s differs between the origin and %s (%s vs %s) — something in front of "+
					"this server is rewriting what browsers receive",
				path, public, local[:16], remote[:16])}
		}
	}
	return finding{name: "delivered bundle", detail: public + " serves exactly what this origin does"}
}

// publicOrigin picks the first non-loopback, non-onion origin to compare against.
// An onion is reachable only through Tor, which this process has no client for.
func publicOrigin() string {
	for _, raw := range strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",") {
		candidate := strings.TrimSpace(raw)
		if candidate == "" || strings.Contains(candidate, ".onion") {
			continue
		}
		if strings.HasPrefix(candidate, "https://") {
			return strings.TrimRight(candidate, "/")
		}
	}
	return ""
}

func fetchDigest(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// Bounded: the bundle is small, and an edge that returns something enormous
	// is a finding in itself rather than a reason to fill memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(body)), nil
}

// checkBackupFreshness looks at the archives themselves rather than at whether
// the timer is enabled. A timer that runs daily and fails every time looks
// perfectly healthy from systemd's side.
func checkBackupFreshness() finding {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return finding{name: "backups", err: fmt.Errorf("%s does not exist — see DEPLOY.md", backupDir)}
		}
		// Doctor is useful to run as the service user, who cannot read a
		// root-only backup directory. Not knowing is not the same as bad news.
		return finding{name: "backups", warn: true,
			err: fmt.Errorf("cannot read %s (run as root to check): %v", backupDir, err)}
	}

	var newest time.Time
	var count int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		count++
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if count == 0 {
		return finding{name: "backups", err: fmt.Errorf("no archives in %s", backupDir)}
	}
	age := time.Since(newest)
	if age > 48*time.Hour {
		return finding{name: "backups",
			err: fmt.Errorf("newest is %s old — the daily timer is not running", age.Round(time.Hour))}
	}
	return finding{name: "backups",
		detail: fmt.Sprintf("%d archive(s), newest %s old", count, age.Round(time.Minute))}
}

func joinHostPort(host string, port int) string {
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s:%d", host, port)
}
