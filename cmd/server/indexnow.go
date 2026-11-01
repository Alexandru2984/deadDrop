package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

// `deaddrop indexnow [page…]` tells the search engines that share IndexNow —
// Bing, and those built on it such as DuckDuckGo and Ecosia; Yandex, Seznam,
// Naver — that public pages changed, rather than leaving them to notice when a
// crawler next happens by. Google is not one of them; it reads the sitemap.
//
// What it sends is the public origin, the pages' addresses and the key. The
// engines check the key against /<key>.txt on that origin, which the service
// answers only while INDEXNOW_KEY is set, so that is fetched first, the way
// they will: a submission whose key they cannot read is refused.

const indexNowEndpoint = "https://api.indexnow.org/indexnow"

// The pages robots.txt and the sitemap invite in; nothing else is worth naming.
var publicPages = []string{"/", "/about.html", "/about.ro.html"}

var indexNowKeyPattern = regexp.MustCompile(`^[A-Za-z0-9-]{8,128}$`)

// indexNowKey reads INDEXNOW_KEY, in the form the protocol allows. Unset is
// not an error: the service then answers no key file and sends nothing.
func indexNowKey() (string, error) {
	key := strings.TrimSpace(os.Getenv("INDEXNOW_KEY"))
	if key != "" && !indexNowKeyPattern.MatchString(key) {
		return "", errors.New("INDEXNOW_KEY must be 8 to 128 letters, digits or dashes")
	}
	return key, nil
}

func indexNowKeyHandler(key string) http.HandlerFunc {
	body := []byte(key)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}
}

func runIndexNow(pages []string) {
	key, err := indexNowKey()
	if err != nil {
		log.Fatalf("indexnow: %v", err)
	}
	if key == "" {
		fmt.Println("INDEXNOW_KEY is not set — nothing sent")
		return
	}
	public := publicOrigin()
	if public == "" {
		log.Fatal("indexnow: no public https origin in ALLOWED_ORIGINS")
	}
	if len(pages) == 0 {
		pages = publicPages
	}
	client := &http.Client{Timeout: 20 * time.Second}
	if err := submitIndexNow(client, indexNowEndpoint, public, key, pages); err != nil {
		log.Fatalf("indexnow: %v", err)
	}
	fmt.Printf("told IndexNow that %s changed on %s\n", strings.Join(pages, " "), public)
}

func submitIndexNow(client *http.Client, endpoint, public, key string, pages []string) error {
	for _, page := range pages {
		if !slices.Contains(publicPages, page) {
			return fmt.Errorf("%s is not one of the public pages %v", page, publicPages)
		}
	}
	origin, err := url.Parse(public)
	if err != nil || origin.Host == "" {
		return fmt.Errorf("public origin %q is not a URL", public)
	}
	keyLocation := public + "/" + key + ".txt"
	served, err := fetchBody(client, keyLocation)
	if err != nil {
		return fmt.Errorf("%s: %v — is the service running with this INDEXNOW_KEY?", keyLocation, err)
	}
	if strings.TrimSpace(string(served)) != key {
		return fmt.Errorf("%s does not hold this INDEXNOW_KEY", keyLocation)
	}

	urls := make([]string, len(pages))
	for i, page := range pages {
		urls[i] = public + page
	}
	body, err := json.Marshal(struct {
		Host        string   `json:"host"`
		Key         string   `json:"key"`
		KeyLocation string   `json:"keyLocation"`
		URLList     []string `json:"urlList"`
	}{origin.Host, key, keyLocation, urls})
	if err != nil {
		return err
	}
	resp, err := client.Post(endpoint, "application/json; charset=utf-8", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
		return nil
	case http.StatusForbidden:
		return fmt.Errorf("refused the key at %s (HTTP 403)", keyLocation)
	case http.StatusUnprocessableEntity:
		return fmt.Errorf("the pages do not belong to %s (HTTP 422)", origin.Host)
	case http.StatusTooManyRequests:
		return errors.New("too many submissions; try again later (HTTP 429)")
	default:
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, endpoint)
	}
}
