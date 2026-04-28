package crypto

import (
	"encoding/json"
	"testing"
)

func TestHashCanonicalJSON_KeyOrderInvariant(t *testing.T) {
	a := json.RawMessage(`{"b":2,"a":1}`)
	b := json.RawMessage(`{"a":1,"b":2}`)
	ha, err := HashCanonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := HashCanonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("hash differs: %s vs %s", ha, hb)
	}
}
