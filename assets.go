package deaddrop

import (
	"embed"
	"io/fs"
)

// embeddedWeb contains the exact browser client compiled into the server
// binary. Runtime edits to the checkout therefore cannot silently change the
// cryptography delivered by an already-audited binary.
//
// The all: prefix is load-bearing: a bare "web" pattern silently drops every
// file whose name starts with "_" or ".", which would leave the vendored
// ML-KEM dependencies (_crystals.js, _u64.js) out of the binary and 404 the
// entire post-quantum handshake at runtime.
//
//go:embed all:web
var embeddedWeb embed.FS

// WebFS returns the embedded browser bundle rooted at web/.
func WebFS() fs.FS {
	sub, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		panic("embedded web bundle is missing: " + err.Error())
	}
	return sub
}
