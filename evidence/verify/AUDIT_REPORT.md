# Audit of out/keystream_rule.md — "About the f9 field" (2026-11-08)

Scratch scripts: wasm_audit.py, oracle_audit.mjs, proto_audit.py (this dir).
No existing files were modified.

## Claim 1 — rebuilt buffers  VERIFIED (one factual slip in the claim's parenthetical)

- out/gt/real_sig86_rebuilt.bin == fixtures/real_input.bin, byte-identical.
  Both 878 bytes, sha256 08edeb5b9a9b72158e9eeaf92295ae93aa264ea376c1f481e5478b42c05760a2.
- out/gt/real_sig92_rebuilt.bin (sha256 16b7da03f78cb74239cf8622fe51e5bc51c655db19bce78ec3cf659b2fdd1981)
  differs from sig86 at exactly ONE byte: offset 264.  sig86=0x13, sig92=0x26.
- ACTUAL bytes: bitrev(100)=0x26, bitrev(200)=0x13.  The claim's quoted values
  "bitrev(100)=0x4c / bitrev(200)=0x64" are WRONG (0x64 is plain 100 in hex, not
  bit-reversed).  Buffer bytes are sig86=0x13=bitrev(200), sig92=0x26=bitrev(100),
  consistent with rtt 200/100 (format: 00 00 00 + bitrev[rtt] at offsets 261..264).
- Independently rebuilt from extracted proto values: matches both rebuilt files and the fixture.

## Claim 2 — proto field extraction  VERIFIED (with precision notes)

- f9 verified: sig86 = {1: 4, 2: fb777997a04a586c219bb6d424fcc0c4};
  sig92 = {1: 4, 2: 6716c0f443514fa27326ea3b40cbcacc}.
- Every listed payload value confirmed identical in BOTH protos and matching
  out/gt/real_sig86.json / real_sig92.json (22 fields each): tz Europe/Warsaw (f6.14),
  manufacturer f7.1, model f7.2, arch x86 f7.3, cpu f7.4=4, mem f7.6=17179869184,
  inner f7.8={958,896}, screen f7.10={1920,1080}, dpr f7.9/f7.11 = fixed32 0x3f800000 = 1.0,
  osRelease f6.6=10.0.0, systemName f6.8, systemVersion f6.9, locale f6.12=pl-PL,
  langs f6.13 = 4 entries, fontsDigest f6.17=61052e74..., UA f5.5.1, rtt f5.5.3 = 200/100,
  mediaDigest f5.5.9=0607b220..., pluginsDigest f5.5.11=0382071d..., hostname f5.1,
  notification f6.19.2='default', 19 permissions in f6.19.3.
- Full recursive proto diff sig86 vs sig92 — differences ONLY at:
  (1) top f1 (dispatch UUID), (2) top f2 timestamp 1793911637.564000000 vs
      1793911656.051000000 (~19 s later),
  (3) f5.5.3 rtt 200 vs 100,
  (4) f9.2 hash,
  (5) f6.19.3 permission ENTRIES IN DIFFERENT ORDER (identical set of 19 (name,state)
      pairs; HashMap serialization order differs between captures).
  So "identical EXCEPT rtt and f9/dispatch fields" holds semantically; byte-strictly,
  the perms order also differs (irrelevant to the rebuilt buffer, which emits sorted order).
- End-to-end: build_buffer() from independently extracted values reproduces
  fixtures/real_input.bin byte-exact and both out/gt rebuilds.

## Claim 3 — HH oracle  VERIFIED (one wording correction)

- `node out/gt/hh_js.mjs out/spy/hh_oracle.wasm fixtures/real_input.bin`
  -> dab600eacc9120c7724b04f20eb3bdb4.  Reproduced in an independent harness too.
- Faithfulness, checked two ways:
  a) wasm/core.wat: func 141 (lines 32273-32435) calls 169 exactly 4x; func 114
     (26894-27137) calls 141 exactly 3x; func 121 (28514-28736) calls 141 exactly 2x;
     func 169 (35686-35786): no calls.  No other call/call_indirect in those bodies.
  b) raw wasm (opcode-exact decoder, out/verify/wasm_audit.py): same counts, zero
     unknown opcodes.  Applying build_oracle.py's exact relocate() to the core.wasm
     bodies (169->1 x4, 141->0 x3, 141->0 x2) reproduces the hh_oracle.wasm bodies
     BYTE-EXACT (lengths shrink only from uleb 2B->1B).  f169 body identical unrelocated.
     Oracle module: no imports/table/elem/data; 3 types; funcs types [0,2,1,0];
     memory 2 pages; mutable i32 global = 65504; exports memory/update/fin.
     Call relocation mapping confirmed: 141->0, 169->1.
- Post-state: hh_js.mjs init == live record 'pre' (pi constants x2 + 48 zero bytes).
  Oracle post-update 176-byte snapshot (compared as RAW memory bytes, as spy_run.mjs
  dumps them) matches record[0].post byte-exact (882-byte wifi buffer) and
  record[1].post byte-exact (16-byte h1).
- CORRECTION: in the CURRENT real_leaks114.json, record[0] is the 882-byte wifi
  record.  The oracle post for the 878-byte real_input.bin does NOT match
  record[0].post (nor should it).  The byte-exact live-state validation holds for
  the 882-byte buffer; there is no live 878-byte post snapshot on disk anymore.

## Claim 4 — leak evidence  MOSTLY VERIFIED, two file-level statements REFUTED

- VERIFIED: record[1] len=16, data = 992f9773b5d20473365bb19b5baa1e7d == HH(882) (stage-1 h1);
  its input corresponds to the 882-byte buffer.
- VERIFIED (semantics): build_buffer(sig86 env + connType "wifi") == record[0].data
  (882 bytes); explicitly, inserting ee966696 at offset 261 (immediately before the
  00 00 00 + 0x13 rtt bytes) of the 878-byte rebuild reproduces record[0].data
  byte-exact.  ee966696 = bitrev("wifi") (0x77->0xee, 0x69->0x96, 0x66->0x66, 0x69->0x96).
- REFUTED (as description of current files):
  (a) The CURRENT out/leaks/real_leaks114.json contains exactly TWO records:
      [len=882 wifi stage-1, len=16 stage-2].  There is NO len=878 stage-1 record;
      the pre-wifi version of the file was overwritten (mtime 01:25:01, run with
      PV_CONN type:"wifi").  out/leaks/real_leaks.json is SipHash spy output (unrelated).
  (b) out/leaks/real_input.bin is 878 bytes, NOT 882, and is byte-identical to
      fixtures/real_input.bin (same sha256 08edeb5b...).  It is a stale leftover of the
      earlier non-wifi run (mtime 00:33:58 vs the 01:25:01 leaks rerun; written by
      spy_run.mjs's import-68 capture path).  The real 882-byte wifi capture survives
      only as hex inside real_leaks114.json record[0].data.

## Claim 5 — HH != f9  VERIFIED

- HH(878) = dab600eacc9120c7724b04f20eb3bdb4  != fb777997a04a586c219bb6d424fcc0c4
  and != 6716c0f443514fa27326ea3b40cbcacc.
- HH(882) = 992f9773b5d20473365bb19b5baa1e7d (== stage-1 h1 == record[1].data).
- HH(16-byte h1) = bb47fea7bac126b740efd300ac9fac4e != either real f9.
- Conclusion supported: neither single nor double hashing of buffer-only bytes
  reproduces the real f9 values; the real browser's f9 includes additional runtime bytes.

## Bottom line

All substantive writeup claims hold and were re-verified independently.  Two claim
statements are inaccurate against the CURRENT files (stale-artifact wording, not
broken science): (1) real_leaks114.json no longer contains a len=878 stage-1 record —
it is the 882-byte wifi run; (2) out/leaks/real_input.bin is the 878-byte plain
buffer, not an 882-byte wifi capture.  Also the audit request's parenthetical
"bitrev(100)=0x4c / bitrev(200)=0x64" is simply wrong (actual 0x26 / 0x13).
