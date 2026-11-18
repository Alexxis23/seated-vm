#!/usr/bin/env python3
"""Rebuild the hash-input buffer from real_sig86/92 payload values and verify
HH-128 (via the wasm oracle) equals f9.f2."""
import sys, os, json, subprocess
sys.path.insert(0, r"C:\Users\Administrator\Desktop\seated-vm\harness")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from build_spec2 import build, mkenv, PERM_NAMES, LOCALE_CIPHER

def rv(b, i):
    v, sh = 0, 0
    while True:
        c = b[i]; i += 1
        v |= (c & 0x7F) << sh; sh += 7
        if not (c & 0x80):
            return v, i

def fields(b):
    i, out = 0, {}
    while i < len(b):
        key, i = rv(b, i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = rv(b, i); out.setdefault(f, []).append(v)
        elif wt == 1:
            out.setdefault(f, []).append(b[i:i+8]); i += 8
        elif wt == 5:
            out.setdefault(f, []).append(b[i:i+4]); i += 4
        else:
            l, i = rv(b, i); out.setdefault(f, []).append(b[i:i+l]); i += l
    return out

def parse(path):
    top = fields(open(path, "rb").read())
    sig = top[9][0]
    f5 = fields(top[5][0])
    f5_5 = fields(f5[5][0])
    f6 = fields(top[6][0])
    f7 = fields(top[7][0])
    f9 = fields(sig)
    f6_19 = fields(f6[19][0])
    perms = []
    for e in f6_19.get(3, []):
        ee = fields(e)
        perms.append((ee[1][0].decode(), ee[2][0]))
    d = dict(
        hostname=f5[1][0].decode(),
        ua=f5_5[1][0].decode(),
        rtt=f5_5[3][0],
        mediaDigest=f5_5[9][0].decode(),
        pluginsDigest=f5_5[11][0].decode(),
        osRelease=f6[6][0].decode(),
        platform=f6[7][0].decode(),
        systemName=f6[8][0].decode(),
        systemVersion=f6[9][0].decode(),
        locale=f6[12][0].decode(),
        langs=[x.decode() for x in f6[13]],
        tz=f6[14][0].decode(),
        fontsDigest=f6[17][0].decode(),
        manufacturer=f7[1][0].decode(),
        model=f7[2][0].decode(),
        arch=f7[3][0].decode(),
        cpu=f7[4][0],
        memGiB=f7[6][0] // (1024 * 1024 * 1024),
        inner=f7[8][0], inner2=f7[8][0],
        innerMsg=fields(f7[8][0]),
        physMsg=fields(f7[10][0]),
        f9=f9,
        perms=perms,
        permHead=f6_19.get(1, [None])[0],
        permState0=f6_19.get(2, [None])[0],
    )
    return d

for name in ("real_sig86", "real_sig92"):
    d = parse(os.path.join(r"C:\Users\Administrator\Desktop\seated-vm\fixtures", name + ".proto.bin"))
    print("=" * 20, name)
    print("rtt:", d["rtt"], "cpu:", d["cpu"], "memGiB:", d["memGiB"])
    print("inner:", d["innerMsg"], "phys:", d["physMsg"])
    print("langs:", d["langs"], "locale:", d["locale"], "tz:", d["tz"])
    print("f9:", {k: (v.hex() if isinstance(v, bytes) else v) for k, v in d["f9"].items()})
    print("f6.19 head:", d["permHead"], d["permState0"])
    print("perms (%d):" % len(d["perms"]))
    for n, s in d["perms"]:
        print("   %-28s %d" % (n, s))
    json.dump({k: v for k, v in d.items() if k != "f9"},
              open(r"C:\Users\Administrator\Desktop\seated-vm\out\gt\%s.json" % name, "w"),
              default=lambda o: o.hex() if isinstance(o, bytes) else str(o), indent=1)
