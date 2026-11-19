# seated-vm

Reversed-engineered generator for the Seated/Prelude SDK signals hash-input
buffer and its HighwayHash-128 fingerprint — and, since the wasm rewrite,
an executor for the **real SDK core wasm** that produces the complete
signals request body. Pure Go (wazero, no cgo); no browser needed.

## The fonts-keystream rule (the unknown this repo cracks)

The 64-byte "fonts zone" of the hash-input buffer is the 64-char hex
`fontsDigest` string with each byte rotated left by an amount derived from
the **model** string (the FVL-derived `brand-version` list):

```
model      = join("::", sort(brand + "-" + version for fullVersionList))
k[i]       = (-utf8(model)[i mod len(model)]) & 7      // == (8 - byte%8)%8
zone[i]    = rotl_u8(digest_ascii[i], k[i])            // i = 0..63
```

Full derivation + evidence: [doc/keystream_rule.md](doc/keystream_rule.md).
Bonus crack: the locale obfuscation is a fixed per-position rotation
`rotl(locale[i], [3,0,2,7,5][i])` — works for any 5-char locale.

## Two implementation paths

1. **Static builder** (`Params.Build()` + `HighwayHash128`) — pure Go
   reimplementation of the buffer + hash, reversed from the wasm.
2. **Real-core executor** (`seatedvm.NewCore` + `Core.GeneratePayload`) —
   embeds the actual wasm from chunk.941 (sha256-pinned), implements all 79
   wasm-bindgen imports in Go, and produces the full raw-deflate protobuf
   body the SDK POSTs to `/v1/signals`, with the wasm computing everything
   itself (buffer, hash, dispatch UUID, serialization). See
   [doc/wasm_execution.md](doc/wasm_execution.md).

The two paths agree byte-exactly on every tested environment — the test
suite asserts the wasm's own fingerprint equals `HH128(Build())` AND the
fingerprints inside the real browser captures.

**Full usage guide & flow: [doc/USAGE.md](doc/USAGE.md)** — parameter
reference (every value the wasm consumes, mapped to its browser source),
collection recipes, the complete HTTP dispatch flow, env JSON schema and the
new-browser/new-version adaptation checklist.

## Branch map

| branch | contents |
|---|---|
| `main` | production Go module (buffer builder + HighwayHash-128 + wasm host), docs, test vectors |
| `sdk/<version>` | one branch per captured VM build: the wasm blob, spy/oracle tooling, fixtures, evidence dumps |

Current: [`sdk/0.3.2`](../../tree/sdk/0.3.2) — Prelude core 0.3.2
(js-sdk 0.14.0, `entry82.js`).

## Use in your bot

```
go get github.com/Alexxis23/seated-vm
```

```go
import seatedvm "github.com/Alexxis23/seated-vm"

// Static: buffer + hash only.
p := &seatedvm.Params{
    TZ:          "Europe/Warsaw",
    FVL: []seatedvm.FVLEntry{
        {"Not:A-Brand", "8.0.0.0"},
        {"Chromium", "156.0.8078.80"},
        {"Google Chrome", "156.0.8078.80"},
    },
    FontsDigest: digestHex,      // sha256 of the font-probe string
    UserAgent:   ua,
    Locale:      "pl-PL",
    Languages:   []string{"pl-PL", "pl", "en-US", "en"},
    RTT:         130, ConnType: "wifi",
    // ... every per-browser field; see Params doc + examples/env_example.json
}
buf := p.Build()                               // full hash-input buffer
h1 := seatedvm.HighwayHash128(buf)             // SDK HH-128 (zero key) = f9.f2

// Real core: the complete request body the SDK would send.
ctx := context.Background()
core, _ := seatedvm.NewCore(ctx)
defer core.Close(ctx)
body, dispatchID, _ := core.GeneratePayload(ctx, p) // POST body + X-SDK-DispatchID
// headers: Content-Encoding: deflate, Content-Type: application/vnd.prelude.signals,
// X-SDK-User-Agent: core.SDKUserAgent(), endpoint: core.GetDefaultEndpoint(ctx)
```

CLI:

```
go run ./cmd/buffergen --env examples/env_example.json --out buffer.bin --hh
go run ./cmd/buffergen --env examples/env_sig86.json --wasm --out payload.bin
```

Every per-browser field is a `Params` member — see the table in
[doc/keystream_rule.md](doc/keystream_rule.md) and `Params.Defaults()`
(fills a Chrome-156-like profile into zero values).

## Verification

```
go test ./...
```

- golden buffer = the sig86 capture environment (`examples/env_sig86.json`),
  byte-exact against `fixtures/real_input.bin` on the `sdk/0.3.2` branch
- the real wasm (executed in-process under wazero) reproduces the
  fingerprints of BOTH real browser captures byte-exactly:
  sig86 `fb777997a04a586c219bb6d424fcc0c4`, sig92 `6716c0f443514fa27326ea3b40cbcacc`,
  and its internal hash-input buffer equals `Params.Build()` byte-for-byte
  (`TestCoreGeneratePayload`, `TestCoreRTTSwitch`, `TestSpyHashSpan`)
- 54 HighwayHash vectors extracted from the SDK's own wasm oracle
  (`testdata/fuzz_vectors.json`)
- keystream rule byte-exact on 16 fixture buffers + 2 novel FVLs (predictive
  run against the real SDK)

## Note on f9.f2

**`f9.f2 = HighwayHash128(Params.Build())` — a single hash, byte-exact.**

Verified by executing the SDK's actual wasm under the Go wasm host (see
[doc/wasm_execution.md](doc/wasm_execution.md)): the span the wasm feeds its
HighwayHash is byte-identical to `Params.Build()`, and its digest equals the
payload's f9.f2 for every environment tested — including both real captures
(sig86/sig92).

Two semantic corrections this execution-first approach surfaced:

- **`PostPluginsFlag` is the SDK's `webGlEnabled` probe** (one bitrev'd byte
  after the plugins digest). Real headed Chrome = 1. The repo's historical
  golden buffer was captured via the Node harness (no WebGL → 0 →
  `dab600ea…`), which explains the old fixture mismatch — real captures
  carry `fb777997…`/`6716c0f4…`.
- **`maybeHeadless` is never sent by the real collector** (the property
  stays undefined; the wasm skips its buffer byte). It is therefore
  `*bool` and nil by default.

The wasm contains a second HighwayHash stage (`h1 ‖ X`), but its input slot
is statically and empirically dead (a permanently-`None` Option) — the span
spy shows only a single HH update call during `generate_payload`; its output
never reaches the payload. Earlier hypotheses about runtime-map bytes and
differing keys do not apply to core 0.3.2.

`PermissionStates` (per-name values, ror1-encoded per entry; 1=granted
→`0x80`, 2=denied→`0x01`, 3=prompt→`0x81`) and the webGl byte are required
for byte-exactness; see `Params` and the env JSON keys
`permissionStates` / `postPluginsFlag` (alias `webGlEnabled`).
