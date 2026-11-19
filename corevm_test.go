package seatedvm

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"testing"
)

// ---------- chunk.941 extraction ----------

func TestExtractCoreWasmFromChunk(t *testing.T) {
	src, err := os.ReadFile("entry82.js")
	if err != nil {
		t.Skip("entry82.js (captured chunk.941) not present")
	}
	blob, err := ExtractCoreWasmVerified(src, CoreWasmSHA256)
	if err != nil {
		t.Fatalf("extract+verify: %v", err)
	}
	emb, err := CoreWasm()
	if err != nil {
		t.Fatalf("embedded core wasm: %v", err)
	}
	if !bytes.Equal(blob, emb) {
		t.Fatalf("chunk.941 blob != embedded wasm/core.wasm")
	}
}

// ---------- payload proto walker ----------

type pfield struct {
	num    uint64
	wire   byte
	val    []byte // wire 2 payload
	varint uint64 // wire 0
	fixed  []byte // wire 1/5 raw
}

func walkProto(b []byte) ([]pfield, error) {
	var out []pfield
	i := 0
	for i < len(b) {
		key, n := binary.Uvarint(b[i:])
		if n <= 0 {
			return nil, io.ErrUnexpectedEOF
		}
		i += n
		f := pfield{num: key >> 3, wire: byte(key & 7)}
		switch f.wire {
		case 0:
			v, n := binary.Uvarint(b[i:])
			if n <= 0 {
				return nil, io.ErrUnexpectedEOF
			}
			f.varint = v
			i += n
		case 1:
			if i+8 > len(b) {
				return nil, io.ErrUnexpectedEOF
			}
			f.fixed = b[i : i+8]
			i += 8
		case 2:
			l, n := binary.Uvarint(b[i:])
			if n <= 0 {
				return nil, io.ErrUnexpectedEOF
			}
			i += n
			if i+int(l) > len(b) {
				return nil, io.ErrUnexpectedEOF
			}
			f.val = b[i : i+int(l)]
			i += int(l)
		case 5:
			if i+4 > len(b) {
				return nil, io.ErrUnexpectedEOF
			}
			f.fixed = b[i : i+4]
			i += 4
		default:
			return nil, io.ErrUnexpectedEOF
		}
		out = append(out, f)
	}
	return out, nil
}

func findFields(fs []pfield, num uint64, wire byte) []pfield {
	var out []pfield
	for _, f := range fs {
		if f.num == num && f.wire == wire {
			out = append(out, f)
		}
	}
	return out
}

func inflateRaw(body []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(body))
	defer r.Close()
	return io.ReadAll(r)
}

// ---------- end-to-end: real wasm vs static Build() ----------

// sig86Params is the real Chrome-156 capture environment (the same one
// TestGoldenBuffer verifies against fixtures/real_input.bin).
func sig86Params() *Params {
	return &Params{
		TZ:                  "Europe/Warsaw",
		FVL:                 []FVLEntry{{"Not:A-Brand", "8.0.0.0"}, {"Chromium", "156.0.8078.80"}, {"Google Chrome", "156.0.8078.80"}},
		OSType:              "Windows",
		Arch:                "x86",
		FontsDigest:         "61052e74ac13cb864ce5331005cdc65836d3c6f1532abf520ae52fa200ecee30",
		UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
		Locale:              "pl-PL",
		Languages:           []string{"pl-PL", "pl", "en-US", "en"},
		HardwareConcurrency: 4,
		MemoryGiB:           16,
		ScreenW:             1920,
		ScreenH:             1080,
		InnerW:              958,
		InnerH:              896,
		DevicePixelRatio:    1.0,
		RTT:                 200,
		Cookies:             true,
		LocalStorage:        true,
		IndexedDB:           true,
		MediaDigest:         "0607b220ecb0c6fe48506008a804d0d8a7eb64cf6ea168f241c590575ae88a01",
		PluginsDigest:       "0382071da078da8ea4375d7681b9138b86deb8023303ef804196ec3c0f78e80a",
		OSRelease:           "10.0.0",
		Notification:        "default",
		Granted:             []string{"payment-handler", "gyroscope", "clipboard-write", "screen-wake-lock", "accelerometer", "background-sync", "storage-access", "magnetometer"},
		Throwing:            []string{"ambient-light-sensor", "bluetooth", "compute-pressure", "push", "top-level-storage-access"},
	}
}

func TestCoreGeneratePayload(t *testing.T) {
	ctx := context.Background()
	core, err := NewCore(ctx)
	if err != nil {
		t.Fatalf("NewCore: %v", err)
	}
	defer core.Close(ctx)

	if v := core.CoreVersion(); v == "" {
		t.Fatal("empty core version")
	}
	if ua := core.SDKUserAgent(); ua != "Prelude/0.14.0 Core/"+core.CoreVersion()+" (Web)" {
		t.Errorf("SDKUserAgent = %q", ua)
	}

	p := sig86Params()
	// A real headed Chrome has a working WebGL context.
	p.PostPluginsFlag = true
	body, id, err := core.GeneratePayload(ctx, p)
	if err != nil {
		t.Fatalf("GeneratePayload: %v", err)
	}
	if len(id) == 0 {
		t.Fatal("empty dispatch id")
	}

	proto, err := inflateRaw(body)
	if err != nil {
		t.Fatalf("payload is not raw-deflate: %v", err)
	}
	top, err := walkProto(proto)
	if err != nil {
		t.Fatalf("payload is not protobuf: %v", err)
	}

	// Field 1 = the dispatch id (a UUID string).
	if got := findFields(top, 1, 2); len(got) == 0 || string(got[0].val) != id {
		t.Errorf("payload f1 = %q, want dispatch id %q", string(got[0].val), id)
	}

	// Field 9 = the fingerprint message {1: kind, 2: 16-byte HighwayHash-128}.
	f9 := findFields(top, 9, 2)
	if len(f9) == 0 {
		t.Fatal("payload has no field 9 (fingerprint)")
	}
	f9m, err := walkProto(f9[0].val)
	if err != nil {
		t.Fatalf("f9 not protobuf: %v", err)
	}
	h := findFields(f9m, 2, 2)
	if len(h) == 0 || len(h[0].val) != 16 {
		t.Fatalf("f9.2 missing or not 16 bytes (%d)", len(h[0].val))
	}

	// THE invariants, three ways:
	// 1. the wasm's own fingerprint equals HighwayHash128 of our statically
	//    rebuilt buffer — the real core's internal hash-input buffer is
	//    byte-identical to Params.Build();
	buf := p.Build()
	want := HighwayHash128(buf)
	if !bytes.Equal(h[0].val, want[:]) {
		t.Errorf("wasm f9.2 = %s, want HH128(Build()) = %s",
			hex.EncodeToString(h[0].val), hex.EncodeToString(want[:]))
	}
	// 2. it also equals the fingerprint inside the REAL Chrome capture
	//    (fixtures/real_sig86.proto.bin, sdk/0.3.2 branch);
	if got := hex.EncodeToString(h[0].val); got != "fb777997a04a586c219bb6d424fcc0c4" {
		t.Errorf("fingerprint = %s, want fb777997… (real sig86 capture)", got)
	}
	// 3. and Build() did not drift from its own golden.
	if hh := HHHex(buf); hh != "fb777997a04a586c219bb6d424fcc0c4" {
		t.Errorf("Build() drifted: HH(buffer) = %s", hh)
	}

	// Permissions: 19 (name,state) entries under f6.19.3.
	f6 := findFields(top, 6, 2)
	if len(f6) == 0 {
		t.Fatal("payload has no field 6 (device)")
	}
	f6m, _ := walkProto(f6[0].val)
	f19 := findFields(f6m, 19, 2)
	if len(f19) == 0 {
		t.Fatal("payload has no f6.19 (webProperties)")
	}
	f19m, _ := walkProto(f19[0].val)
	perms := findFields(f19m, 3, 2)
	if len(perms) != 19 {
		t.Errorf("f6.19.3 permission entries = %d, want 19", len(perms))
	}

	// Repeatability: same env -> same fingerprint (and a fresh dispatch id).
	pAgain := sig86Params()
	pAgain.PostPluginsFlag = true
	body2, id2, err := core.GeneratePayload(ctx, pAgain)
	if err != nil {
		t.Fatalf("GeneratePayload #2: %v", err)
	}
	if id2 == id {
		t.Errorf("dispatch id repeated across calls: %s", id)
	}
	proto2, _ := inflateRaw(body2)
	top2, _ := walkProto(proto2)
	f9b := findFields(top2, 9, 2)
	f9bm, _ := walkProto(f9b[0].val)
	h2 := findFields(f9bm, 2, 2)
	if !bytes.Equal(h[0].val, h2[0].val) {
		t.Errorf("fingerprint not stable across runs: %s vs %s",
			hex.EncodeToString(h[0].val), hex.EncodeToString(h2[0].val))
	}
}

func TestCoreRTTSwitch(t *testing.T) {
	ctx := context.Background()
	core, err := NewCore(ctx)
	if err != nil {
		t.Fatalf("NewCore: %v", err)
	}
	defer core.Close(ctx)

	// sig86 (rtt 200) vs sig92 (rtt 100): the ONLY env differences between the
	// two real captures are rtt and nothing else — flipping rtt must flip the
	// fingerprint onto the other capture's value.
	pGl := sig86Params()
	pGl.PostPluginsFlag = true
	f1, _, err := core.GeneratePayload(ctx, pGl)
	if err != nil {
		t.Fatalf("sig86: %v", err)
	}
	p2 := sig86Params()
	p2.PostPluginsFlag = true
	p2.RTT = 100
	f2b, _, err := core.GeneratePayload(ctx, p2)
	if err != nil {
		t.Fatalf("sig92: %v", err)
	}
	a := hashFromPayload(t, f1)
	b := hashFromPayload(t, f2b)
	if bytes.Equal(a, b) {
		t.Errorf("rtt 200 vs 100 produced identical fingerprints")
	}
	if got := hex.EncodeToString(a); got != "fb777997a04a586c219bb6d424fcc0c4" {
		t.Errorf("rtt=200 fingerprint = %s, want fb777997… (real sig86)", got)
	}
	if got := hex.EncodeToString(b); got != "6716c0f443514fa27326ea3b40cbcacc" {
		t.Errorf("rtt=100 fingerprint = %s, want 6716c0f4… (real sig92)", got)
	}
	// And the static builder agrees with the wasm on both.
	p3 := sig86Params()
	p3.PostPluginsFlag = true
	wantA := HighwayHash128(p3.Build())
	if !bytes.Equal(a, wantA[:]) {
		t.Errorf("rtt=200: wasm vs Build() mismatch")
	}
	p4 := sig86Params()
	p4.PostPluginsFlag = true
	p4.RTT = 100
	wantB := HighwayHash128(p4.Build())
	if !bytes.Equal(b, wantB[:]) {
		t.Errorf("rtt=100: wasm vs Build() mismatch")
	}
}

func hashFromPayload(t *testing.T, body []byte) []byte {
	t.Helper()
	proto, err := inflateRaw(body)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	top, err := walkProto(proto)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	f9 := findFields(top, 9, 2)
	if len(f9) == 0 {
		t.Fatal("no f9")
	}
	f9m, _ := walkProto(f9[0].val)
	h := findFields(f9m, 2, 2)
	if len(h) == 0 {
		t.Fatal("no f9.2")
	}
	return h[0].val
}

// TestParamsOverrides proves every identity/metadata knob flows into the
// payload (or is safely ignored by the hash) — the hooks for adapting the
// module to another browser.
func TestParamsOverrides(t *testing.T) {
	ctx := context.Background()
	core, err := NewCore(ctx)
	if err != nil {
		t.Fatalf("NewCore: %v", err)
	}
	defer core.Close(ctx)

	p := sig86Params()
	p.PostPluginsFlag = true
	refBody, _, err := core.GeneratePayload(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	refHash := hashFromPayload(t, refBody)

	// DispatchID override: lands in payload field 1, does NOT touch the hash.
	p2 := sig86Params()
	p2.PostPluginsFlag = true
	p2.DispatchID = "11111111-2222-7333-8444-555555555555"
	body, id, err := core.GeneratePayload(ctx, p2)
	if err != nil {
		t.Fatal(err)
	}
	if id != p2.DispatchID {
		t.Errorf("dispatch id = %q, want override %q", id, p2.DispatchID)
	}
	top, err := walkProto(mustInflate(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(findFields(top, 1, 2)[0].val); got != p2.DispatchID {
		t.Errorf("payload f1 = %q, want %q", got, p2.DispatchID)
	}
	if !bytes.Equal(hashFromPayload(t, body), refHash) {
		t.Errorf("fingerprint changed when only DispatchID was overridden")
	}

	// Metadata overrides that are NOT hashed buffer inputs: fingerprint must
	// stay identical (DispatchID additionally lands in payload field 1).
	p3 := sig86Params()
	p3.PostPluginsFlag = true
	p3.SDKVersion = "9.9.9"
	p3.CoreVersion = "9.9.9"
	p3.Origin = "https://example.com"
	p3.ImplementedFeatures = 7
	body3, _, err := core.GeneratePayload(ctx, p3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hashFromPayload(t, body3), refHash) {
		t.Errorf("fingerprint changed when only non-hashed metadata was overridden")
	}
	if ua := core.SDKUserAgentOf(p3); ua != "Prelude/9.9.9 Core/9.9.9 (Web)" {
		t.Errorf("SDKUserAgentOf = %q", ua)
	}

	// DevicePlatform and CellularData ARE hashed buffer inputs:
	// - device.platform: the u32 at offset 56 is an equality marker —
	//   len("web")=3 when the value is exactly "web", 0 otherwise;
	// - network.cellular_data: a raw 0/1 byte at offset 49 when present
	//   (absent — the real-capture default — writes nothing).
	p4 := sig86Params()
	p4.PostPluginsFlag = true
	p4.DevicePlatform = "not-web"
	body4, _, err := core.GeneratePayload(ctx, p4)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(hashFromPayload(t, body4), refHash) {
		t.Errorf("DevicePlatform override unexpectedly did not change the fingerprint")
	}
	cd := true
	p5 := sig86Params()
	p5.PostPluginsFlag = true
	p5.CellularData = &cd
	body5, _, err := core.GeneratePayload(ctx, p5)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(hashFromPayload(t, body5), refHash) {
		t.Errorf("CellularData override unexpectedly did not change the fingerprint")
	}
}

// TestPrepareDispatch checks the complete-request helper.
func TestPrepareDispatch(t *testing.T) {
	ctx := context.Background()
	core, err := NewCore(ctx)
	if err != nil {
		t.Fatalf("NewCore: %v", err)
	}
	defer core.Close(ctx)

	p := sig86Params()
	p.PostPluginsFlag = true
	dr, err := core.PrepareDispatch(ctx, p, "test-sdk-key")
	if err != nil {
		t.Fatal(err)
	}
	if dr.Endpoint == "" || dr.Endpoint != "https://edge.prelude.dev" {
		t.Errorf("Endpoint = %q", dr.Endpoint)
	}
	if dr.ContentType != "application/vnd.prelude.signals" || dr.ContentEncoding != "deflate" || dr.Connection != "close" {
		t.Errorf("content headers wrong: %+v", dr)
	}
	if dr.SDKKey != "test-sdk-key" || dr.SDKUserAgent == "" || dr.DispatchID == "" || dr.RequestDate == "" {
		t.Errorf("missing header values: %+v", dr)
	}
	if dr.ImplementedFeatures != "0" {
		t.Errorf("ImplementedFeatures = %q, want \"0\"", dr.ImplementedFeatures)
	}
	// The body must be a valid payload whose f1 matches DispatchID.
	top, err := walkProto(mustInflate(t, dr.Body))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(findFields(top, 1, 2)[0].val); got != dr.DispatchID {
		t.Errorf("payload f1 = %q, want %q", got, dr.DispatchID)
	}
	// SetHeaders must apply the exact SDK header set (verbatim casing).
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, dr.Endpoint, bytes.NewReader(dr.Body))
	dr.SetHeaders(req)
	for k, want := range map[string]string{
		"Content-Type":               "application/vnd.prelude.signals",
		"Content-Encoding":           "deflate",
		"Connection":                 "close",
		"X-SDK-User-Agent":           dr.SDKUserAgent,
		"X-SDK-DispatchID":           dr.DispatchID,
		"X-SDK-Key":                  "test-sdk-key",
		"X-SDK-Request-Date":         dr.RequestDate,
		"X-SDK-Implemented-Features": "0",
	} {
		v, ok := req.Header[k] // direct map read: verbatim key, no canonicalization
		if !ok {
			t.Errorf("header %s missing (casing not preserved?)", k)
			continue
		}
		if len(v) != 1 || v[0] != want {
			t.Errorf("header %s = %v, want %q", k, v, want)
		}
	}
	// Spot-check verbatim casing survives Go's canonicalization
	// (X-SDK-User-Agent, not X-Sdk-User-Agent). Canonical Get() would miss it.
	if _, ok := req.Header["X-SDK-User-Agent"]; ok {
		if _, canon := req.Header["X-Sdk-User-Agent"]; canon {
			t.Errorf("X-SDK-User-Agent was canonicalized to X-Sdk-User-Agent")
		}
	} else {
		t.Errorf("X-SDK-User-Agent casing not preserved")
	}
}

func mustInflate(t *testing.T, body []byte) []byte {
	t.Helper()
	proto, err := inflateRaw(body)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	return proto
}
