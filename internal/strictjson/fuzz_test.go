package strictjson

import (
	"bytes"
	"encoding/json"
	"testing"
)

// This package exists to make one parser's verdict trustworthy: every API body
// and every WebSocket frame passes through it, and the fields it fills decide
// who is authenticated and what they may do.
//
// The risk is not a crash. It is a differential — the duplicate-key scanner
// walking the bytes one way while encoding/json fills the struct another, so a
// body is accepted after being checked as something other than what it becomes.
// That is the shape of a great many auth bypasses, and it is invisible to
// example-based tests because you have to guess the input that splits them.

type fuzzTarget struct {
	Token string `json:"token"`
	M1    string `json:"M1"`
	Count int    `json:"count"`
	Flag  bool   `json:"flag"`
}

func FuzzDecodeObject(f *testing.F) {
	f.Add([]byte(`{"token":"abc","M1":"ff","count":1,"flag":true}`))
	f.Add([]byte(`{"token":"a","token":"b"}`))
	f.Add([]byte(`{"TOKEN":"a","token":"b"}`))
	f.Add([]byte(`{"m1":"a","M1":"b"}`))
	f.Add([]byte(`{} {}`))
	f.Add([]byte(`{"token":"a"} trailing`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"unknown":1}`))
	f.Add([]byte("{\"tokKen\":1}")) // Kelvin sign folds to 'k' in Go's matcher
	f.Add([]byte(`{"token":"a","token":"b"}`))
	f.Add([]byte(`{"count":1e309}`))
	f.Add([]byte(`{"count":"1"}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var strict fuzzTarget
		strictErr := DecodeObject(bytes.NewReader(raw), &strict)
		if strictErr != nil {
			return // rejected: nothing more to promise
		}

		// Accepted. Whatever this package decided the body says, a plain decode
		// of the same bytes has to agree — otherwise the checks ran against one
		// reading and the handler acts on another.
		var plain fuzzTarget
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&plain); err != nil {
			t.Fatalf("accepted a body that encoding/json rejects: %q (%v)", raw, err)
		}
		if strict != plain {
			t.Fatalf("parsers disagree on %q: strict=%+v plain=%+v", raw, strict, plain)
		}

		// And an accepted body must survive a round trip, so nothing it holds
		// depends on the exact bytes it arrived in.
		encoded, err := json.Marshal(strict)
		if err != nil {
			t.Fatalf("cannot re-encode %+v: %v", strict, err)
		}
		var again fuzzTarget
		if err := DecodeObject(bytes.NewReader(encoded), &again); err != nil {
			t.Fatalf("re-encoded body %q is rejected: %v", encoded, err)
		}
		if again != strict {
			t.Fatalf("round trip changed the value: %+v -> %+v", strict, again)
		}
	})
}
