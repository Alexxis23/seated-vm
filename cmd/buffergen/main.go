// Command buffergen generates the SDK hash-input buffer / signals payload
// from browser params.
//
// Static path (pure Go reimplementation, no wasm):
//
//	go run ./cmd/buffergen --env env.json --out buffer.bin [--hh]
//
// Real-core path (executes the actual chunk.941 wasm under wazero):
//
//	go run ./cmd/buffergen --env env.json --wasm --out payload.bin
//
// The --wasm mode produces the exact raw-deflate protobuf body the SDK POSTs
// to /v1/signals (Content-Type: application/vnd.prelude.signals), including
// the internally computed HighwayHash-128 and a fresh dispatch UUID, and
// cross-checks it against the static builder.
package main

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	seatedvm "github.com/Alexxis23/seated-vm"
)

func main() {
	envPath := flag.String("env", "", "env JSON file (required)")
	outPath := flag.String("out", "buffer.bin", "output path (buffer, or payload with --wasm)")
	hh := flag.Bool("hh", false, "also print HH(buffer) and HH(HH(buffer))")
	wasm := flag.Bool("wasm", false, "execute the real chunk.941 core wasm (generates the full signals payload)")
	flag.Parse()

	if *envPath == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/buffergen --env env.json --out buffer.bin [--hh|--wasm]")
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

	if *wasm {
		runWasm(p, *outPath)
		return
	}

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

func runWasm(p *seatedvm.Params, outPath string) {
	ctx := context.Background()
	core, err := seatedvm.NewCore(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "core:", err)
		os.Exit(1)
	}
	defer core.Close(ctx)

	endpoint, _ := core.GetDefaultEndpoint(ctx)
	fmt.Printf("core      : %s\n", core.CoreVersion())
	fmt.Printf("ua        : %s\n", core.SDKUserAgent())
	fmt.Printf("endpoint  : %s\n", endpoint)

	body, dispatchID, err := core.GeneratePayload(ctx, p)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate_payload:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, body, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("dispatch  : %s\n", dispatchID)
	fmt.Printf("payload   : %s (%d bytes, raw-deflate protobuf — POST body)\n", outPath, len(body))

	// Cross-check: the fingerprint inside the payload must equal the static
	// builder's HH128(Build()).
	proto, err := inflate(body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "inflate:", err)
		os.Exit(1)
	}
	got, err := payloadFingerprint(proto)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fingerprint:", err)
		os.Exit(1)
	}
	want := seatedvm.HighwayHash128(p.Build())
	ok := bytes.Equal(got, want[:])
	fmt.Printf("f9.f2     : %s (static HH128(Build()) = %s, match=%v)\n",
		hex.EncodeToString(got), hex.EncodeToString(want[:]), ok)
	if !ok {
		os.Exit(1)
	}
}

func inflate(body []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(body))
	defer r.Close()
	return io.ReadAll(r)
}

// payloadFingerprint extracts field 9.2 (the 16-byte HighwayHash-128) from
// the inflated signals protobuf.
func payloadFingerprint(proto []byte) ([]byte, error) {
	f9, err := fieldBytes(proto, 9)
	if err != nil {
		return nil, err
	}
	return fieldBytes(f9, 2)
}

func fieldBytes(msg []byte, num uint64) ([]byte, error) {
	i := 0
	for i < len(msg) {
		key, n := binary.Uvarint(msg[i:])
		if n <= 0 {
			return nil, io.ErrUnexpectedEOF
		}
		i += n
		fnum, wire := key>>3, byte(key&7)
		switch wire {
		case 0:
			_, n := binary.Uvarint(msg[i:])
			if n <= 0 {
				return nil, io.ErrUnexpectedEOF
			}
			i += n
		case 1:
			i += 8
		case 2:
			l, n := binary.Uvarint(msg[i:])
			if n <= 0 {
				return nil, io.ErrUnexpectedEOF
			}
			i += n
			if i+int(l) > len(msg) {
				return nil, io.ErrUnexpectedEOF
			}
			if fnum == num {
				return msg[i : i+int(l)], nil
			}
			i += int(l)
		case 5:
			i += 4
		default:
			return nil, fmt.Errorf("unsupported wire type %d", wire)
		}
	}
	return nil, fmt.Errorf("field %d not found", num)
}
