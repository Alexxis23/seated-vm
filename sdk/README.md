# sdk/0.3.2 — Prelude core 0.3.2 (js-sdk 0.14.0)

Artifacts pinned to the exact VM build reversed in this repo
(`entry82.js` chunk, Chrome 131 / Chrome 156 capture sessions).

| path | contents |
|---|---|
| `core-0.3.2.wasm` | the extracted SDK core wasm (the "vm") |
| `entry82.js` | the SDK JS chunk embedding the wasm as a data URL |
| `oracle/hh_oracle.wasm` | minimal module embedding the ORIGINAL HH bodies (funcs 114/141/169/121) with call indices relocated — use as ground truth for HighwayHash-128 |
| `oracle/build_oracle.py` | builds the oracle from `wasm/core.wasm` |
| `spy/patch_spy.py` | patches the wasm: all 14 SipHash-2-4 call sites → logging wrapper (func 320), both HighwayHash call sites → state-snapshot wrapper (func 321), stage-2 Option gate forced open |
| `spy/spy_run.mjs` | runs the real SDK in Node with the patched wasm, dumps SipHash calls + HH states + payload |
| `fixtures/` | real captures: base.bin, s1–s7 (131-FVL env), real_input.bin, digest0–4 (controlled digests), real_sig86/92 protos (payloads + f9) |
| `../evidence/` | spy leaks, verify-agent reports (independent audits), state dumps |
| `../harness/` | original Node harnesses (run11/run13/...) + buffer spec builder |

Regenerate the patched wasm: `python spy/patch_spy.py` (writes `core_spy.wasm`).
Run: `node spy/spy_run.mjs --env real` (see script header for env knobs).

A new VM build gets its own branch `sdk/<version>`: drop the new wasm/entry
chunk here, re-run the spy, and diff the buffer builder against `main`.
