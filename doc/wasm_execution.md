# Executing the real core wasm (the `--wasm` path)

seated-vm hosts the **actual Prelude core wasm** — the exact blob embedded
base64 inside the SDK's webpack chunk (`chunk.941`, i.e. `entry82.js`) —
under [wazero](https://github.com/tetratelabs/wazero) (pure Go, no cgo) and
drives it exactly the way the SDK's wasm-bindgen glue does. This is a second,
independent implementation path next to the static `Params.Build()` builder.

## Pipeline

```
chunk.941 (entry82.js)
   │  ExtractCoreWasm: "data:application/wasm;base64,…" → 170,053 bytes
   │  sha256 = f7689c2d…ab6  (pinned in CoreWasmSHA256, verified on every use)
   ▼
NewCore(ctx)                         wazero instantiation
   │  79 "wbg" imports implemented in Go (corevm.go): the wasm-bindgen ABI
   │  (JS heap with glue-exact slot numbering 128=undefined/129=null,
   │  malloc/realloc/free via __wbindgen_export_0/1/3, passStringToWasm0,
   │  iterator protocol for Object.entries, getRandomValues via crypto/rand,
   │  Date/now, …)
   ▼
signals object (signals.go)          mirror of entry82.js collectors
   │  {id, application:{name,version,platform{…},implementedFeatures,sdkInfo},
   │   device:{fontsDigest,locale…,webProperties{…}}, hardware:{…}, network:{…}}
   ▼
generate_payload(retPtr, signalsRef) the wasm export the SDK calls
   │  add_to_stack_pointer(-16) → call → read (ptr,len) → free
   ▼
raw-deflate protobuf                 the exact POST body for /v1/signals
   │  (Content-Type: application/vnd.prelude.signals,
   │   Content-Encoding: deflate, X-SDK-DispatchID / X-SDK-User-Agent headers)
```

`get_dispatch_id`, `get_version` and `get_default_endpoint` are the wasm's
own exports, so the dispatch UUID, core version string and endpoint are the
real ones (dispatch UUIDs are v7, minted from `Date.now()` +
`crypto.getRandomValues` inside the wasm).

## What the wasm proved (and what it corrected)

Running the real core under the Go host — with the binary-patch spy from
`spy_test.go` (`call 114` → import 68, the technique from
`harness_tmp/run11.mjs`) dumping the exact HighwayHash input span — settled
every open question in TASK-KEYSTREAM.md:

1. **The hash input is exactly `Params.Build()`.** The span the wasm feeds
   into its HH-128 is byte-identical to the static builder's output (878
   bytes for the sig86 env).
2. **f9.f2 = single HH-128, zero key.** Only ONE HH update call fires during
   `generate_payload`; the rumored second stage (`h1 ‖ X`) never runs.
3. **The "PostPluginsFlag" byte is the SDK's `webGlEnabled` probe.** Toggling
   `webGlEnabled` in the signals flips exactly that one byte (offset 397).
   This resolved the long-standing fixture contradiction: the repo's
   `real_input.bin`/golden buffer was captured through the Node harness
   (no WebGL → byte 0 → `dab600ea…`), while the real Chrome captures carry
   webGl=1 → byte `bitrev(1)`:
   - sig86 (rtt 200): `f9.f2 = fb777997a04a586c219bb6d424fcc0c4`
   - sig92 (rtt 100): `f9.f2 = 6716c0f443514fa27326ea3b40cbcacc`
   Both are reproduced byte-exactly by `Build()` + `HighwayHash128` once
   `PostPluginsFlag=true` is set (and by the real wasm, which agrees with
   the static builder on every input tested).
4. **`maybeHeadless` must stay absent.** The SDK collector never assigns the
   property; a concrete `false` makes the wasm insert an extra `0x00` byte
   before the plugins digest (879-byte buffer). Params.MaybeHeadless is
   therefore `*bool` and nil by default.
5. **Permission state 2 = "denied"** (encodes as `ror1(2)=0x01`;
   1=granted→`0x80`, 3=prompt→`0x81`), confirmed by flipping one entry.
6. **`device.platform` is an equality marker, not a string zone.** The u32
   at buffer offset 56..60 — long mistaken for a constant `03 00 00 00` —
   is `len("web")` when `device.platform == "web"`, and `00 00 00 00` for
   ANY other value (independent of its length). Byte-exact fingerprints
   require platform "web" (Params.DevicePlatform empty or "web").
7. **`network.cellular_data` is a raw `0/1` byte at buffer offset 49**
   (right after manufacturer, before osType) — but only when the field is
   PRESENT (a defined bool). The real captures leave it undefined
   (connection type unknown) and the byte is skipped. Params.CellularData
   (*bool, nil = absent) reproduces all three states.

## Fidelity rules encoded in signals.go

The host mirrors the JS collectors field-by-field (names are the wasm's own
read keys). Notable behaviors that matter for byte-exactness:

- absent vs null vs false are distinct: `connectionType`/`rtt` are only
  present when `navigator.connection` exists (`ConnType != "" || RTT > 0`),
  `pluginsDigest`/`mediaCapabilities` are digest strings, `memorySize` is a
  BigInt (`GiB * 1024³`), `cpuCount` only when non-zero.
- `manufacturer`/`model` = `sort().join("::")` over the fullVersionList
  (`vA` in entry82.js — no dedup).
- permissionsApiStatuses: `{name: "granted"|"denied"|"prompt"}`, throwing
  names absent entirely; insertion order sorted for determinism (the wasm
  serializes into its own HashMap anyway).
- `application.name` = `location.hostname` (the buffer's hostname zone);
  `device.hostname` = origin and is never read by the wasm.

## Spy tooling (for future SDK versions)

`spy_test.go` shows the whole recipe: take the extracted blob, patch the two
HH-update call sites (`0x1da4c`/`0x1dd70`: opcode index byte `call 114` →
`call 68`), run a payload, and the import logs `(ptr,len)` + span. Diff the
span against `Params.Build()` to find any new/changed zone in minutes.

Bump procedure for a new capture: extract the new blob
(`ExtractCoreWasmVerified`), update `wasm/core.wasm` + `CoreWasmSHA256`, run
`TestSpyHashSpan` and the bisect technique above, adjust `signals.go` if the
span diverges.
