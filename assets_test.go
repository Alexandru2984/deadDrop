package deaddrop

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedWebBundleContainsEntryAndManifest(t *testing.T) {
	web := WebFS()
	index, err := fs.ReadFile(web, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), "Dead Drop") {
		t.Fatal("embedded index is not the Dead Drop entry point")
	}
	manifest, err := fs.ReadFile(web, "SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), "  js/app.js\n") {
		t.Fatal("embedded integrity manifest does not cover app.js")
	}
}
