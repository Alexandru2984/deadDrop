package deaddrop

import (
	"embed"
	"io/fs"
)

// embeddedWeb contains the exact browser client compiled into the server
// binary. Runtime edits to the checkout therefore cannot silently change the
// cryptography delivered by an already-audited binary.
//
//go:embed web
var embeddedWeb embed.FS

// WebFS returns the embedded browser bundle rooted at web/.
func WebFS() fs.FS {
	sub, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		panic("embedded web bundle is missing: " + err.Error())
	}
	return sub
}
