# TASK: crack the Prelude fonts-keystream derivation

You are reverse-engineering one specific construction inside a Rust→WASM
SDK. Everything you need is in this directory (see README.md). Do not
assume internet access to the ticky repo; this directory is self-contained.

## Background (established facts — trust these)

The SDK (Prelude @prelude.so/js-sdk 0.14.0, core 0.3.2) builds a byte
buffer ("hash input"), obfuscates parts of it, and computes
`f9 = HighwayHash-128(32-byte zero key, buffer)` (proven; see
harness/build_spec2.py for the byte-perfect buffer reconstruction).

Buffer layout (in order): [appVersion rol2] timezone(raw) manufacturer(ror1)
osType(bitrev) 03 00 00 00 arch(rol2) **FONTS-DIGEST-ZONE(64)** cpuCount(raw
byte) 00 00 00 locale(5-byte cipher) langs(raw concat) UA(bitrev)
[connType(bitrev)] 00 00 00 rtt(bitrev byte) cookies/localStorage/indexedDB
(bitrev bools) [dnt(bitrev str)] multiTouch(bool) mediaDigest(bitrev)
pluginsDigest(bitrev) 00 systemName(ror2) hostname(raw) arch(rol2)
systemVersion(raw) screenW/H(u32 LE raw) mem(8B: 00*4, GiB/8, 00*3)
osRelease(raw) model(raw) innerW/H(u32 LE, bytes bitrev'd) dpr(f32 LE ×2
raw) automation(bool) notification(ror1) then per permission:
name(ror1) 00 00 00 state(ror1). All fixed except the FONTS ZONE.

The FONTS ZONE: the 64-hex-char fontsDigest string, each byte rotated by
k[i] (rol-k, k∈0..7). The k[] ("keystream") is:

- IDENTICAL across different digests in the same environment (proven with
  fixtures digest0-4.bin).
- CHANGES when the browser's fullVersionList (FVL) content changes. FVL
  feeds: manufacturer (brands sorted, joined "::"), model (brand-version
  sorted joined "::"), systemName (FVL[0].brand), systemVersion (FVL[0].version).
  Changing ONLY FVL version digits (same lengths) changes the keystream →
  content-keyed. Mixed FVLs → mixed schedules → continuous function.
- INDEPENDENT of 23 other env values (each individually bisected: locale,
  langs, permissions set/states, dnt, connType, touch, notification, dpr,
  tz, appVersion, plugins, UA, cpu, mem, screens, inner, rtt, TZ env,
  crypto wrapper...).

WASM mechanics (core.dis / core.wat / core.dcmp in wasm/):

- `generate_payload` = func[261]. HighwayHash update = func[114]
  (call sites at code offsets 0x1da4b and 0x1dd6f).
- **SipHash-2-4 = func[119]**, sig (i64 k0, i64 k1, i32 ptr, i32 end) -> i64.
  Five call sites in func[261]: 0x01951c (keys from stack [1280]/[1288]),
  0x01a8b6 ([3688]/[3696]), 0x01d00e, 0x01e458 ([1192]/[1200]), 0x01f630.
- A [16]uint64 HighwayHash state table (minio layout v0|v1|mul0|mul1,
  init constants dbe6d5d5fe4cce2f, a4093822299f31d0, 13198a2e03707344,
  243f6a8885a308d3, 3bd39e10cb0ef593, c0acf169b5f18a8c, be5466cf34e90c6c,
  452821e638d01377) lives at stack 1240..1368; a 176-byte state copy at
  0x01dd71. The SipHash key slots (1280/1288 etc.) overlap this region —
  but whether keys are live HH lanes or independently computed values is
  UNRESOLVED (simple "running HH state" hypotheses failed, see registry).
- Fonts zone in the buffer starts (no appVersion) at offset 63, length 64.

## Your goal

Produce the exact rule: given the environment values (everything above,
notably manufacturer/model/systemName/systemVersion and the 64-char
fontsDigest), compute k[0..63]. Then the fonts zone bytes =
rol_k[i](digest[i]).

## Method (recommended)

1. **Leak the SipHash calls.** The spy technique that worked for the HH
   input: binary-patch call sites (opcode bytes) to redirect to a JS-
   controllable import, then wrap that import in WebAssembly.instantiate
   (see harness/run11.mjs lines patching 0x1da4c → import 68
   `__wbg_prototypesetcall_...`). For func[119] no import has a matching
   signature (i64,i64,i32,i32)->i64, so EITHER:
   a) rewrite the wasm import section to ADD such an import (module
      binary editing; import section sits before code, all func indices
      shift by +1 — re-locate call sites by byte pattern `10 72` /
      `20 10 20 04 10 72` rather than offsets), patch the five `call 119`
      (`10 77`) sites to the new import, and log (k0,k1,ptr,end)+memory
      slice in JS; OR
   b) patch func[119]'s prologue to store its four args to a dead stack/
      memory region you can read post-call (e.g. write k0/k1/ptr/end at
      fixed scratch addresses; 1176-region before HH init may be usable,
      or grow memory and use a high address), then read them from
      wasmInstance.exports.memory after each dispatch; OR
   c) single-step the decompile (core.dcmp) around the five sites and
      identify the arg-producing stores statically (A2 below).
2. Run the harness twice: once in the base env (fixtures/base.bin family)
   and once in the real env (run13 defaults), dump all (k0,k1,data) pairs.
   Diff → find how keys/data differ and what they derive from.
3. Formulate the rule (likely: k0/k1 = HH64/HH128/SipHash of manufacturer
   and/or model string with constant or length-derived keys; keystream
   per 8-byte block = SipHash(k0,k1, block or counter or string-so-far),
   k[i] = out_byte[i] & 7 — but VERIFY, the naive versions failed).
4. Implement in Python (out/keystream_solver.py) and pass the gate below.

## Verification gate (must pass exactly)

Rebuild, from payload values, the full hash-input buffers of BOTH real
browser captures and check HighwayHash-128(zero key) equals their f9.f2:

- fixtures/real_sig92.proto.bin — f9.f2 = 6716c0f443514fa27326ea3b40cbcacc
  Its values: no appVersion, tz Europe/Warsaw, manufacturer
  "Chromium::Google Chrome::Not:A-Brand", osType Windows, arch x86,
  fontsDigest "61052e74ac13cb864ce5331005cdc65836d3c6f1532abf520ae52fa200ecee30",
  cpu 4, locale pl-PL (cipher bytes 83 6c b4 28 89), langs "pl-PLplen-USen",
  UA Chrome/156 Win (see payload), no connType, rtt 200, cookies/ls/idb true,
  no dnt, multiTouch false, mediaDigest 0607b220ecb0c6fe48506008a804d0d8a7eb64cf6ea168f241c590575ae88a01,
  pluginsDigest 0382071da078da8ea4375d7681b9138b86deb8023303ef804196ec3c0f78e80a,
  systemName "Not:A-Brand", hostname go.seated.com, systemVersion "8.0.0.0",
  screens 1920x1080, mem 16GiB, osRelease "10.0.0", model
  "Chromium-156.0.8078.80::Google Chrome-156.0.8078.80::Not:A-Brand-8.0.0.0",
  inner 958x896, dpr 1.0, automation false, notification "default",
  permissions: 19 names with states — camera=3 display-capture=3
  persistent-storage=3 window-management=3 payment-handler=1 midi=3
  geolocation=3 gyroscope=1 local-fonts=3 clipboard-write=1
  screen-wake-lock=1 clipboard-read=3 microphone=3 accelerometer=1
  background-sync=1 storage-access=1 captured-surface-control=3
  notifications=3 magnetometer=1 (granted=1 prompt=3; ASYNC-RANDOM order in
  proto — the HASH INPUT order must be determined, try sorted).
  Expected input buffer ≈ fixtures/real_input.bin (878 bytes) — byte-exact
  comparison against it is the strongest check; HH must then equal the f9.
- fixtures/real_sig86.proto.bin — f9.f2 = fb777997a04a586c219bb6d424fcc0c4.
  Same env EXCEPT rtt=100 (and dispatchId/timestamp, not hashed). If your
  rule is right, the same reconstruction with rtt=100 flips the hash.

Reference: harness/keystream_test2.py contains a working minio-HH generic
port + SipHash-2-4 + HH128; reuse it.

## Dead-end registry (do NOT retry)

30,720 combos already swept and FAILED: {all adjacent key-slot pairs of a
minio-layout HH-256 state after absorbing the obfuscated OR plaintext
prefix (0, 32, or 63-byte prefixes)} × {SipHash 2-4, 1-3, 2-2} × {data =
8-byte digest block / whole digest / digest-so-far / counter / buffer-so-far}
× {LE/BE output} × {& 7 with shifts 0..3}. Also failed: SipHash with keys
(0,0), (07060504...,0f0e0d0c...), (1,2), (13198a2e...,243f6a88...) over
manufacturer/model/systemVersion/systemName directly. The wiring is more
involved — leak the actual args (method 1) instead of guessing.

Also known: schedule does NOT depend on digest content; does NOT depend on
any single non-FVL env value; is NOT length-only-keyed (same-length
different-digits differ).

## Outputs

- `out/keystream_rule.md` — the derivation specified precisely enough to
  reimplement in any language (constants, order, key derivation, per-block
  construction, extraction of k[i]).
- `out/keystream_solver.py` — working implementation + a main() that runs
  the verification gate and prints PASS/FAIL for both captures.
- `out/leaks/` — the raw (k0,k1,data) dumps from the spy runs (evidence).
