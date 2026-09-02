package main

import (
	"encoding/json"
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
