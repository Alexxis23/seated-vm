# seated-vm

Reversed-engineered generator for the Seated/Prelude SDK signals hash-input
buffer and its HighwayHash-128 fingerprint. Pure Go, no browser or wasm
needed at runtime.

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

## Branch map

| branch | contents |
|---|---|
| `main` | production Go module (buffer builder + HighwayHash-128), docs, test vectors |
| `sdk/<version>` | one branch per captured VM build: the wasm blob, spy/oracle tooling, fixtures, evidence dumps |

Current: [`sdk/0.3.2`](../../tree/sdk/0.3.2) — Prelude core 0.3.2
(js-sdk 0.14.0, `entry82.js`).

## Use in your bot

```
go get github.com/seated-vm/seated-vm
```

```go
import seatedvm "github.com/seated-vm/seated-vm"

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
h1 := seatedvm.HighwayHash128(buf)             // SDK HH-128 (zero key)
h2 := seatedvm.HighwayHash128(h1[:])           // double hash (wifi case)
zone := seatedvm.FontsZone(digestHex, id.Model)
```

CLI:

```
go run ./cmd/buffergen --env examples/env_example.json --out buffer.bin --hh
```

Every per-browser field is a `Params` member — see the table in
[doc/keystream_rule.md](doc/keystream_rule.md) and `Params.Defaults()`
(fills a Chrome-156-like profile into zero values).

## Verification

```
go test ./...
```

- golden buffer = the real Chrome-156 capture (`fixtures/real_input.bin` on
  the `sdk/0.3.2` branch), byte-exact
- 54 HighwayHash vectors extracted from the SDK's own wasm oracle
  (`testdata/fuzz_vectors.json`)
- keystream rule byte-exact on 16 fixture buffers + 2 novel FVLs (predictive
  run against the real SDK)

## Note on f9.f2

**`f9.f2 = HighwayHash128(Params.Build())` — a single hash, byte-exact.**

Verified against a live browser by swapping the SDK's embedded wasm for an
instrumented build that logs both HighwayHash input spans: the builder
reproduces the real hash-input buffer byte-for-byte (all buffer inputs are
visible in the signals payload — viewport, per-name permission states,
notification string, and the rest of `Params`), and the single HH-128
digest equals the browser's own f9.f2.

The wasm contains a second HighwayHash stage (`h1 ‖ X`), but its input slot
is statically and empirically dead (a permanently-`None` Option) — its
output never reaches the payload. Earlier hypotheses about runtime-map
bytes do not apply to core 0.3.2.

`PermissionStates` (per-name values, ror1-encoded per entry) and
`PostPluginsFlag` are required for byte-exactness; see `Params` and the
env JSON keys `permissionStates` / `postPluginsFlag`.
