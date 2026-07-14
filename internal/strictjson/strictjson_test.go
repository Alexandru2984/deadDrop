package strictjson

import (
	"strings"
	"testing"
)

func TestDecodeObject(t *testing.T) {
	type body struct {
		Name string         `json:"name"`
		Size int            `json:"size"`
		Meta map[string]any `json:"meta"`
	}
	var got body
	if err := DecodeObject(strings.NewReader(`{"name":"alice","meta":{"ok":true}}`), &got); err != nil {
		t.Fatalf("valid object rejected: %v", err)
	}
	bad := []string{
		``,
		`[]`,
		`{"name":"a","name":"b"}`,
		`{"name":"a","Name":"b"}`,
		`{"size":1,"ſize":2}`,
		`{"name":"a","meta":{"x":1,"x":2}}`,
		`{"name":"a","meta":{"\u0000":true}}`,
		`{"name":"a","unknown":true}`,
		`{"name":"a"}{"name":"b"}`,
	}
	for _, raw := range bad {
		if err := DecodeObject(strings.NewReader(raw), &body{}); err == nil {
			t.Errorf("accepted invalid JSON %q", raw)
		}
	}
}
