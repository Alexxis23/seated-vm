package seatedvm

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Fuzz vectors extracted from the SDK's own HH wasm (hh_oracle.wasm).
// Regenerate with out/gt (see sdk/oracle/fuzz notes); file optional.
func TestFuzzVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/fuzz_vectors.json")
	if err != nil {
		t.Skip("testdata/fuzz_vectors.json not present")
	}
	var vectors []struct {
		Len  int    `json:"len"`
		Data string `json:"data"`
		HH   string `json:"hh"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for i, v := range vectors {
		data, _ := hex.DecodeString(v.Data)
		got := HHHex(data)
		if got != v.HH {
			t.Errorf("vector %d (len %d): got %s want %s", i, v.Len, got, v.HH)
		}
	}
}
