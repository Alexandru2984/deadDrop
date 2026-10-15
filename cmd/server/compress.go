package main

import (
	"bytes"
	"compress/gzip"
	"io/fs"
	"mime"
	"path"
	"strconv"
	"strings"
)

// The client is a few hundred kilobytes of text that every visit downloads in
// full: pages and modules are sent no-store so nothing about the visit stays in
// the browser's disk cache, and no-transform keeps the CDN from rewriting them.
// That leaves compression to this server. The bundle is embedded and fixed for
// the life of the process, so each file is compressed once, at startup.
//
// Only these static files are compressed. API responses are not: they carry
// per-session secrets, and compressing secrets next to attacker-influenced
// input is how BREACH-style attacks read them.

type gzipAsset struct {
	body        []byte
	contentType string
}

// minCompressSize skips files where the gzip framing would be most of the gain.
const minCompressSize = 1024

func precompress(files fs.FS) map[string]gzipAsset {
	out := make(map[string]gzipAsset)
	_ = fs.WalkDir(files, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		contentType := mime.TypeByExtension(path.Ext(name))
		if !compressible(contentType) {
			return nil
		}
		data, err := fs.ReadFile(files, name)
		if err != nil || len(data) < minCompressSize {
			return nil
		}
		var buf bytes.Buffer
		zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if err != nil {
			return nil
		}
		if _, err := zw.Write(data); err != nil || zw.Close() != nil {
			return nil
		}
		if buf.Len() >= len(data) {
			return nil
		}
		out[name] = gzipAsset{body: buf.Bytes(), contentType: contentType}
		return nil
	})
	return out
}

func compressible(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	mediaType = strings.TrimSpace(mediaType)
	switch {
	case strings.HasPrefix(mediaType, "text/"):
		return true
	case mediaType == "application/json", mediaType == "application/manifest+json",
		mediaType == "image/svg+xml", mediaType == "application/javascript":
		return true
	}
	return false
}

// acceptsGzip reports whether an Accept-Encoding header admits gzip, honouring
// an explicit q=0 refusal for gzip or for the wildcard.
func acceptsGzip(header string) bool {
	accepted := false
	for _, part := range strings.Split(header, ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		coding = strings.ToLower(strings.TrimSpace(coding))
		if coding != "gzip" && coding != "*" {
			continue
		}
		q := 1.0
		for _, param := range strings.Split(params, ";") {
			key, value, found := strings.Cut(strings.TrimSpace(param), "=")
			if found && strings.EqualFold(strings.TrimSpace(key), "q") {
				if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
					q = parsed
				}
			}
		}
		if coding == "gzip" {
			return q > 0
		}
		accepted = q > 0
	}
	return accepted
}
