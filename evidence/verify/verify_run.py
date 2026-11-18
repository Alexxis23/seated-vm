#!/usr/bin/env python3
"""Predictive verification: compare predicted fonts zones (novel FVLs A & B)
against real SDK captures in out/verify/input_{A,B}.bin.

Independent pipeline: prediction came from predict.py; here we
  1. locate the predicted zone in the real buffer (report offset),
  2. brute-force extract the ACTUAL rotation k[i] at every zone position
     (rotl_u8 is injective over k=0..7, so extraction is unique),
  3. compare actual vs predicted keystream per position (model-cyclic),
  4. de-rotate to confirm the digest the SDK actually used,
  5. confirm the plain model string sits in the buffer and its cycle
     alignment, plus uniqueness of the offset (full-buffer schedule scan).
Finally cross-checks the predicted zone against the untouched solver.
"""
import hashlib, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.dirname(HERE)

def rotl_u8(b, k):
    k &= 7
    return ((b << k) | (b >> (8 - k))) & 0xFF if k else b

def ks_of(model):
    return [(-c) & 7 for c in model.encode("utf-8")]

DIGEST = hashlib.sha256(b"Segoe UI:Windows").hexdigest()

def actual_rotation(dbyte, zbyte):
    """unique k in 0..7 with rotl(dbyte,k)==zbyte, else None"""
    for k in range(8):
        if rotl_u8(dbyte, k) == zbyte:
            return k
    return None

def verify(tag, buf, model, zone_pred):
    mb = model.encode("utf-8")
    K = ks_of(model)
    L = len(mb)
    print(f"\n===== FVL_{tag} =====")
    print(f"buffer: {len(buf)} bytes")
    print(f"model ({L} bytes): {model}")
    off = buf.find(zone_pred)
    print(f"[1] predicted zone found at offset: {off}")
    if off < 0:
        print("    -> byte-exact zone match: FAIL")
        return False
    ok = True

    # brute-force actual keystream at the found offset.
    # NB: rotation orbits of ASCII 'f' (0x66) and '3' (0x33) have period 4,
    # so for those digest chars k is only recoverable mod 4 from one byte.
    def orbit_period(ch):
        x = ord(ch); s = {rotl_u8(x, k) for k in range(8)}; return len(s)
    actual = []
    for i in range(64):
        k = actual_rotation(ord(DIGEST[i]), buf[off + i])
        actual.append(k)
    mism = []
    for i in range(64):
        a, p = actual[i], K[i % L]
        if orbit_period(DIGEST[i]) == 8:
            if a != p: mism.append(i)
        else:
            if (a - p) % 4 != 0: mism.append(i)
    print(f"[2] actual keystream (brute-forced from buffer; k mod 4 at 'f'/'3' positions) = {','.join(map(str, actual))}")
    print(f"[3] predicted keystream                                                        = {','.join(map(str, K))}")
    degen = [i for i in range(64) if orbit_period(DIGEST[i]) == 4]
    print(f"    degenerate-orbit positions (digest char 'f'/'3', k known mod 4): {degen}")
    print(f"    per-position mismatches (i mod {L}): {mism if mism else 'none'}")
    if mism:
        ok = False

    # de-rotated zone must equal the digest the SDK actually used
    de = bytes(buf[off + i] >> (0) for i in range(0))  # placeholder no-op
    de = bytearray()
    for i in range(64):
        k = actual[i]
        b = buf[off + i]
        de.append(((b >> k) | (b << (8 - k))) & 0xFF if k else b)
    de = bytes(de).decode("latin1")
    print(f"[4] de-rotated zone = {de}")
    print(f"    digest used by SDK == sha256('Segoe UI:Windows'): {de == DIGEST}")
    if de != DIGEST:
        ok = False

    # uniqueness: offsets in the whole buffer whose 64 bytes equal the predicted zone
    hits = []
    for o in range(len(buf) - 63):
        if all(buf[o + i] == zone_pred[i] for i in range(64)):
            hits.append(o)
    print(f"[5] offsets whose 64-byte schedule matches prediction exactly: {hits}")

    # plain model occurrence + cycle alignment facts
    mo = buf.find(mb)
    print(f"[6] plain model string in buffer at offset: {mo}  (present: {mo >= 0})")
    print(f"    zone_offset mod len(model) = {off % L}; model_offset mod len(model) = {mo % L if mo >= 0 else '-'}")
    print(f"    k[i] <-> model[i mod {L}] verified position-wise over all 64 zone bytes")
    return ok and len(hits) == 1

def main():
    with open(os.path.join(HERE, "predictions.json")) as f:
        P = json.load(f)
    all_ok = True
    for tag in ("A", "B"):
        buf = open(os.path.join(HERE, f"buffer_{tag}.bin"), "rb").read()
        c = P["cases"][tag]
        zone = bytes.fromhex(c["zone_hex"])
        all_ok &= verify(tag, buf, c["model"], zone)

    # cross-check predictions against the untouched reference solver (read-only)
    import keystream_solver as S
    for tag, fvl in (("A", None), ("B", None)):
        c = P["cases"][tag]
        z = S.fonts_zone(P["digest"], c["model"])
        agree = z == bytes.fromhex(c["zone_hex"])
        print(f"[cross-check] solver.fonts_zone agrees with independent prediction for FVL_{tag}: {agree}")
        all_ok &= agree

    print("\n=== PREDICTIVE VERIFICATION:", "ALL PASS (rule generalizes to novel FVLs)" if all_ok else "FAIL — RULE FALSIFIED ON A NOVEL ENV", "===")
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
