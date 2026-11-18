#!/usr/bin/env python3
"""Independent prediction of the fonts zone for novel FVLs.

Deliberately NOT importing out/keystream_solver.py — fresh re-implementation
of the rule under test:
    model  = "::".join(sorted(brand + "-" + version for each fullVersionList entry))
    k[i]   = (-model_utf8[i % len]) & 7
    zone[i] = rotl_u8(digest_ascii[i], k[i])   for i in 0..63
Base env digest = sha256("Segoe UI:Windows") hex, computed natively by the SDK.
"""
import hashlib, json, os, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))

def rotl_u8(b, k):
    k &= 7
    if k == 0:
        return b & 0xFF
    return ((b << k) | (b >> (8 - k))) & 0xFF

def model_string(fvl):
    return "::".join(sorted(e["brand"] + "-" + e["version"] for e in fvl))

def keystream(model):
    return [(-b) & 7 for b in model.encode("utf-8")]

def predict(fvl, digest_hex):
    m = model_string(fvl)
    K = keystream(m)
    dg = digest_hex.encode("ascii")
    zone = bytes(rotl_u8(dg[i], K[i % len(K)]) for i in range(64))
    return m, K, zone

DIGEST = hashlib.sha256("Segoe UI:Windows".encode()).hexdigest()

FVL_A = [{"brand": "Microsoft Edge", "version": "99.0.1150.30"},
         {"brand": "Chromium",       "version": "99.0.4744.5"}]
FVL_B = [{"brand": "Chromium",       "version": "131.0.0.0"},
         {"brand": "Google Chrome",  "version": "131.0.6830.0"},
         {"brand": "Not:A-Brand",    "version": "99.0.0.0"}]

def main():
    print("digest_hex (sha256 'Segoe UI:Windows') =", DIGEST)
    results = {}
    for name, fvl in (("A", FVL_A), ("B", FVL_B)):
        m, K, zone = predict(fvl, DIGEST)
        results[name] = {"model": m, "keystream": K, "zone_hex": zone.hex(),
                         "model_bytes": list(m.encode("utf-8"))}
        print(f"\n--- FVL_{name} ({len(fvl)} entries) ---")
        print("model           =", m)
        print("model len       =", len(m.encode("utf-8")))
        print("keystream k[i]  =", ",".join(map(str, K)))
        print("predicted zone  =", zone.hex())
    with open(os.path.join(HERE, "predictions.json"), "w") as f:
        json.dump({"digest": DIGEST, "cases": results}, f, indent=1)
    print("\nwrote", os.path.join(HERE, "predictions.json"))

if __name__ == "__main__":
    main()
