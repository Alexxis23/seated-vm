# The Prelude fonts-keystream derivation — SOLVED

## The rule

The 64-byte "fonts zone" in the hash-input buffer is produced from the
64-character lowercase-hex `fontsDigest` string by **per-byte bit-rotation**,
where the rotation amount for position `i` is derived from the byte value of
the **`model` string** (the FVL-derived `brand-version` list), cyclically:

```
model      = join("::", sort([f"{brand}-{version}" for each entry in fullVersionList]))
model_b    = utf8_bytes(model)
k[i]       = ( -model_b[i mod len(model_b)] ) & 7          # == (8 - byte % 8) % 8
fonts_zone[i] = rotl_u8( fontsDigest_ascii[i], k[i] )      # i = 0..63
```

where `rotl_u8(x, k) = ((x << k) | (x >> (8-k))) & 0xFF` (0 when k == 0).

Note `(-b) & 7 == (8 - (b % 8)) % 8`, i.e. the rotation amount is the
**negative of the model byte modulo 8**. Example: `'C'` = 0x43 = 67,
67 % 8 = 3 → k = 5.

### The model string

Exactly the same `model` value that is carried in the payload
(protobuf `f7.2`) and placed (ror2-obfuscated) into the hash-input buffer:

- real Chrome-156 capture (sig86/sig92):
  `"Chromium-156.0.8078.80::Google Chrome-156.0.8078.80::Not:A-Brand-8.0.0.0"`
  → keystream = `5,0,6,1,3,7,3,3,3,7,3,2,2,0,2,0,0,1,0,2,0,0,6,6,1,1,1,1,4,3,0,5,0,6,1,3,3,3,7,3,2,2,0,2,0,0,1,0,2,0,0,6,6,2,1,4,6,7,3,6,6,7,2,4`
- Node harness / 131-FVL env (base.bin, s1-s7):
  `"Chromium-131.0.0.0::Google Chrome-131.0.6830.0"`
  → keystream = `5,0,6,1,3,7,3,3,3,7,5,7,2,0,2,0,2,0,6,6,1,1,1,1,4,3,0,5,0,6,1,3,3,3,7,5,7,2,0,2,2,0,5,0,2,0,5,0,6,1,3,7,3,3,3,7,5,7,2,0,2,0,2,0`

(The first 10 positions agree between the two because the model strings share
the prefix `"Chromium-15`/`Chromium-13` … up to the first differing digit —
this explains the "mixed FVLs → mixed schedules" observation: the schedule is
position-wise determined by the model bytes.)

## Verification (byte-exact, all 16 fixture buffers + 2 novel environments)

Re-encrypting each fixture's digest with the rule reproduces the fonts zone
of every fixture buffer exactly:

| fixture            | zone offset | keystream | match |
|--------------------|-------------|-----------|-------|
| base.bin           | 55          | OLD       | OK    |
| s1..s7.bin         | 52..61      | OLD       | OK    |
| real_input.bin     | 63          | NEW       | OK    |
| digest0..4.bin     | 63          | NEW       | OK    |

(digest0 = "0"*64, digest1 = "f"*64, digest2 = "0123456789abcdef"*4,
digest3 = "aaaaaaaabbbbbbbbccccccccdddddddd"*2, digest4 = the real digest —
all share the NEW keystream, proving digest-independence; the schedule is
purely model-keyed.)

**Predictive falsification test (independent agent, `out/verify/`)**: two
never-before-tested FVLs — a 2-entry `Microsoft Edge`/`Chromium` mix and a
3-entry list appending `Not:A-Brand-99.0.0.0` — were run through the real
SDK wasm; the predicted zones matched the captured buffers **byte-exact
(64/64)**, including novel model characters and the cycle wrapping past
`len(model)`. The rule generalizes.

## How it was found

1. Built a wasm-spy: appended a wrapper function (index 320) to `core.wasm`
   that intercepts **all 14 call sites** of SipHash-2-4 (func 119) and logs
   `(k0, k1, ptr, len, bytes)` to JS via a reused wbg import. Run via
   `out/spy/spy_run.mjs` (patcher: `out/spy/patch_spy.py`).
   → All SipHash traffic is the **permissions HashMap** (name → state);
   SipHash keys are Rust `RandomState` (malloc address + stack address +
   counter) — SipHash is NOT the keystream source and is env-independent.
2. The stage that hashes the buffer is `HighwayHash` (funcs 114/141/169/121,
   4-lane minio layout, zero key = the pi constants). An oracle module
   (`out/spy/build_oracle.py` → `hh_oracle.wasm`) embedding the original
   function bodies was built to compute it directly.
3. Controlled-FVL spy runs (`--env base` vs `--env real`, plus PV_FVL) showed
   the keystream follows the model string **character-for-character** — the
   per-character rotation map extracted from two independent environments is
   identical for every shared character, giving `k = (-byte) & 7`.

## About the f9 field (protobuf f9.f2)

Discovered while trying to close the original "f9 = HH-128(zero key, buffer)"
verification gate (it does NOT hold literally):

- `HH_oracle(buffer)` for the 878-byte real buffer = `dab600ea…bdb4` — the
  SDK's own HighwayHash-128 (validated against the live post-update state of
  the real wasm run, byte-exact).
- The wasm performs a **second** hash stage (func 114 site 0x1dd6f): with the
  connection `type` present (real browsers, `navigator.connection.type`),
  the buffer contains 4 extra bytes (bitrev("wifi") = `ee966696`, inserted
  before the `00 00 00 + bitrev(rtt)` bytes; note bitrev(200)=0x13,
  bitrev(100)=0x26) and the pipeline computes `h1 = HH(buffer_882)`, then
  `f9 = HH(h1)` (a second pi-initialized update over the 16-byte `h1` blob;
  confirmed live: stage-2 logged `len=16, data=992f9773…` = exactly `h1`).
- Node runs without `connection.type` skip the second stage's data slice
  (an `Option` gate at 0x1da7e: `local15 == -2147483648`), which is why the
  "f9 = single hash of the buffer" premise appeared plausible but never
  reproduced `fb777997…`/`6716c0f4…`.
- In the real browser the second stage's input additionally carries a
  hashbrown-map-derived blob (`Option<String/map>` built from the
  permissions-API slice at frame slots 852/856 → slot 1140), whose bytes
  depend on runtime allocation addresses. The exact real-browser f9 therefore
  cannot be recomputed from payload values alone in a Node environment.
- Evidence files: `out/leaks/real_leaks114.json` (current = the wifi-variant
  run: record[0] = 882-byte stage-1 buffer, record[1] = 16-byte `h1` blob);
  `out/leaks/real_input.bin` = the older 878-byte no-wifi capture (identical
  to `fixtures/real_input.bin`); the 882-byte wifi buffer is reconstructible
  by inserting `ee966696` at offset 261 of the 878-byte rebuild.

`out/keystream_solver.py` implements the keystream + buffer reconstruction and
verifies both real captures' buffers byte-exactly; `out/spy/hh_oracle.wasm`
(+ `out/gt/verify_f9.mjs`) reproduces the SDK's HighwayHash for any input.
