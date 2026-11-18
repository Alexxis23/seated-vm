// Command buffergen generates the SDK hash-input buffer from browser params.
//   go run ./cmd/buffergen --env env.json --out buffer.bin [--hh]
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	seatedvm "github.com/Alexxis23/seated-vm"
)

func main() {
	envPath := flag.String("env", "", "env JSON file (required)")
	outPath := flag.String("out", "buffer.bin", "output buffer path")
	hh := flag.Bool("hh", false, "also print HH(buffer) and HH(HH(buffer))")
	flag.Parse()

	if *envPath == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/buffergen --env env.json --out buffer.bin")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*envPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var j map[string]any
	if err := json.Unmarshal(raw, &j); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	p := seatedvm.ParamsFromJSON(j)
	buf := p.Build()
	if err := os.WriteFile(*outPath, buf, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	id := seatedvm.FVLIdentityOf(p.FVL)
	fmt.Printf("model     : %s\n", id.Model)
	fmt.Printf("keystream : %d values\n", len(id.Keystream))
	fmt.Printf("buffer    : %s (%d bytes)\n", *outPath, len(buf))
	if *hh {
		h1 := seatedvm.HighwayHash128(buf)
		h2 := seatedvm.HighwayHash128(h1[:])
		fmt.Printf("HH(buffer) = %s\n", hex.EncodeToString(h1[:]))
		fmt.Printf("HH(H1)     = %s\n", hex.EncodeToString(h2[:]))
	}
}
