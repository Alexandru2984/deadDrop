package deaddrop

// Version identifies a release.
//
// It lived as a string inside an ASCII banner and nowhere else, which meant
// nobody could name the build they were running. For a security product that is
// the wrong shape of gap: when a fix ships, the only honest answer to "am I
// running it?" was to compare a SHA-256 by hand.
//
// Bump this, tag the commit, and `deaddrop version` prints both this and the
// digest of the client the binary serves — the two things somebody needs in
// order to check rather than trust.
const Version = "0.3.0"
