package seatedvm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Golden vectors generated from the extracted SDK oracle (sdk/oracle/hh_oracle.wasm).
var hhVectors = []struct {
	name string
	data []byte
	want string
}{
	{"empty", nil, "2f6380a491d0415ae514c834a55b3b00"},
	{"abc", []byte("abc"), "fedb8ead2abea66f4384d03c11813128"},
	{"31B", mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"), "d9dbbc2ad8d3d3aaae9723bc75ef0e88"},
	{"32B", mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), "b5289af79af634a9888c00939a0d4782"},
	{"33B", mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"), "59c02848414f1435f952ce4d705ccf5c"},
	{"h1", mustHex("dab600eacc9120c7724b04f20eb3bdb4"), "ae4cf1ceab7513c4e0e5817c990369a8"},
	{"sig86buf", mustHex(goldenBufHex), "dab600eacc9120c7724b04f20eb3bdb4"},
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestHighwayHash128(t *testing.T) {
	for _, v := range hhVectors {
		got := HHHex(v.data)
		if got != v.want {
			t.Errorf("HH(%s) = %s, want %s", v.name, got, v.want)
		}
	}
}

func TestGoldenBuffer(t *testing.T) {
	// The sig86 environment, exactly as captured from the real browser.
	// NOTE: this golden is the Node-harness capture (webGlEnabled byte = 0,
	// i.e. PostPluginsFlag unset). A real headed Chrome has WebGL, so for
	// browser-equivalent fingerprints set PostPluginsFlag: true — see
	// doc/wasm_execution.md and TestWebGLByteHypothesis.
	p := &Params{
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
	got := p.Build()
	want := mustHex(goldenBufHex)
	if !bytes.Equal(got, want) {
		i := 0
		for i < len(got) && i < len(want) && got[i] == want[i] {
			i++
		}
		t.Fatalf("buffer mismatch (%d vs %d bytes), first diff at %d", len(got), len(want), i)
	}
	// And the SDK's hash of it:
	if hh := HHHex(got); hh != "dab600eacc9120c7724b04f20eb3bdb4" {
		t.Errorf("HH(buffer) = %s", hh)
	}
}

func TestKeystream(t *testing.T) {
	model := "Chromium-156.0.8078.80::Google Chrome-156.0.8078.80::Not:A-Brand-8.0.0.0"
	digest := "61052e74ac13cb864ce5331005cdc65836d3c6f1532abf520ae52fa200ecee30"

	// Length = len(model): the cycle wraps for i >= len(model).
	k := Keystream(model)
	if len(k) != len(model) {
		t.Fatalf("keystream len %d, want %d", len(k), len(model))
	}

	// Ground truth: the zone derived from (digest, model) must appear byte-exact
	// inside the golden buffer at offset 63.
	zone := FontsZone(digest, model)
	golden := mustHex(goldenBufHex)
	if !bytes.Equal(zone, golden[63:127]) {
		i := 0
		for i < 64 && zone[i] == golden[63+i] {
			i++
		}
		t.Fatalf("fonts zone mismatch at position %d: got %02x want %02x", i, zone[i], golden[63+i])
	}

	// Per-position identity: de-rotating the zone with k recovers the digest.
	for i := 0; i < 64; i++ {
		c := digest[i]
		if rotl8(c, int(k[i%len(k)])) != golden[63+i] {
			t.Errorf("keystream[%d] = %d does not map %q onto the buffer", i, k[i%len(k)], c)
		}
	}
}
