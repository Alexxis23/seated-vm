package seatedvm

// core_extract.go — the real Prelude core wasm lives base64-embedded inside
// the SDK webpack chunk ("chunk.941", i.e. entry82.js) as a
// `data:application/wasm;base64,...` URL that the SDK instantiates directly.
// This file extracts that blob and pins it byte-exactly, so the module only
// ever executes a wasm binary whose SHA-256 matches a known build.
//
// Provenance of the pinned blob (core 0.3.2, js-sdk 0.14.0, entry82.js):
//
//	sha256 = f7689c2ddbe3cf29bf9399b0958d085fa461517c271d399ae797b75a9b8d0ab6
//	bytes  = 170053 (byte-identical to wasm/core.wasm in this repository)

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// CoreWasmSHA256 is the SHA-256 of the core wasm currently embedded in the
// captured chunk.941 (entry82.js). Executing a DIFFERENT core build is not
// guaranteed to work: the wasm-bindgen import ABI and payload layout are
// version-specific. Bump this (and wasm/core.wasm) when capturing a new
// SDK version.
const CoreWasmSHA256 = "f7689c2ddbe3cf29bf9399b0958d085fa461517c271d399ae797b75a9b8d0ab6"

//go:embed wasm/core.wasm
var coreWasmEmbedded []byte

var wasmDataURL = []byte("data:application/wasm;base64,")

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// CoreWasm returns the embedded, extracted core wasm after re-verifying its
// pinned SHA-256 (fail-fast against accidental corruption of wasm/core.wasm).
func CoreWasm() ([]byte, error) {
	if got := sha256hex(coreWasmEmbedded); got != CoreWasmSHA256 {
		return nil, fmt.Errorf("embedded core wasm sha256 mismatch: got %s, want %s", got, CoreWasmSHA256)
	}
	return coreWasmEmbedded, nil
}

// ExtractCoreWasm pulls the base64 wasm payload out of a chunk.941-style JS
// bundle (any bundle containing the SDK's data:application/wasm;base64 URL).
func ExtractCoreWasm(chunkJS []byte) ([]byte, error) {
	i := bytes.Index(chunkJS, wasmDataURL)
	if i < 0 {
		return nil, errors.New("no embedded data:application/wasm;base64 URL found in chunk")
	}
	i += len(wasmDataURL)
	j := i
	for j < len(chunkJS) && isBase64Char(chunkJS[j]) {
		j++
	}
	if j == i {
		return nil, errors.New("empty base64 payload after wasm data URL")
	}
	raw := make([]byte, base64.StdEncoding.DecodedLen(j-i))
	n, err := base64.StdEncoding.Decode(raw, chunkJS[i:j])
	if err != nil {
		return nil, fmt.Errorf("decoding embedded wasm: %w", err)
	}
	return raw[:n], nil
}

// ExtractCoreWasmVerified extracts and then checks the blob against wantSHA
// (typically CoreWasmSHA256). A mismatch means the chunk carries a different
// core build: do not execute it blindly, re-reverse the ABI first.
func ExtractCoreWasmVerified(chunkJS []byte, wantSHA string) ([]byte, error) {
	blob, err := ExtractCoreWasm(chunkJS)
	if err != nil {
		return nil, err
	}
	if got := sha256hex(blob); got != wantSHA {
		return nil, fmt.Errorf("extracted core wasm sha256 mismatch: got %s, want %s (different SDK core version?)", got, wantSHA)
	}
	return blob, nil
}

func isBase64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '='
}

// sha256sum is a small helper used by the spy/probe tooling and tests.
func sha256sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
