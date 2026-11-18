#!/usr/bin/env python3
"""Independent audit of the payload claims (claim 2) + wifi-variant (claim 4).

- Parses fixtures/real_sig86.proto.bin and real_sig92.proto.bin from scratch.
- Prints every top-level field and a full recursive diff between the two protos.
- Verifies every payload value listed in the audit request.
- Compares against out/gt/real_sig86.json / real_sig92.json (parse_sig output).
- Rebuilds the 878-byte buffer from the extracted values and compares to
  fixtures/real_input.bin; then builds the wifi variant and compares to the
  882-byte stage-1 record in out/leaks/real_leaks114.json.
"""
import sys, os, json, struct

sys.path.insert(0, r"C:\Users\Administrator\Desktop\seated-vm\out")
from keystream_solver import build_buffer  # noqa: E402  (out/keystream_solver.py)

FX = r"C:\Users\Administrator\Desktop\seated-vm\fixtures"
GT = r"C:\Users\Administrator\Desktop\seated-vm\out\gt"
LEAKS = r"C:\Users\Administrator\Desktop\seated-vm\out\leaks"


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
            v, i = rv(b, i); out.setdefault(f, []).append(("v", v))
        elif wt == 1:
            out.setdefault(f, []).append(("b8", b[i:i+8])); i += 8
        elif wt == 2:
            l, i = rv(b, i); out.setdefault(f, []).append(("m", b[i:i+l])); i += l
        elif wt == 5:
            out.setdefault(f, []).append(("b4", b[i:i+4])); i += 4
        else:
            raise ValueError(f"wire type {wt}")
    return out


def show(v):
    t, x = v
    if t in ("b8", "b4"):
        return x.hex()
    if t == "v":
        return x
    try:
        s = x.decode("utf-8")
        if all(32 <= ord(c) < 127 or c in "\t" for c in s):
            return repr(s)
    except UnicodeDecodeError:
        pass
    return x.hex()


def tree(f, indent=""):
    lines = []
    for k in sorted(f):
        for v in f[k]:
            if isinstance(v, tuple) and v[0] == "m":
                try:
                    sub = fields(v[1])
                    lines.append(f"{indent}f{k} ({len(v[1])}B): <msg>")
                    lines.extend(tree(sub, indent + "  "))
                    continue
                except Exception:
                    pass
            lines.append(f"{indent}f{k}: {show(v) if isinstance(v, tuple) else v}")
    return lines


def diff(a, b, path=""):
    ds = []
    keys = sorted(set(a) | set(b))
    for k in keys:
        va, vb = a.get(k, []), b.get(k, [])
        if len(va) != len(vb):
            ds.append(f"{path}f{k}: count {len(va)} vs {len(vb)}")
            continue
        for j, (x, y) in enumerate(zip(va, vb)):
            p = f"{path}f{k}[{j}]"
            if x[0] == "m" and y[0] == "m":
                try:
                    ds.extend(diff(fields(x[1]), fields(y[1]), p + "."))
                except Exception:
                    if x[1] != y[1]:
                        ds.append(f"{p}: {show(x)} vs {show(y)}")
            elif x != y:
                ds.append(f"{p}: {show(x)} vs {show(y)}")
    return ds


def scalar(f, k):
    t, v = f[k][0]
    return v


def extract(path):
    top = fields(open(path, "rb").read())
    d = {}
    f5 = fields(scalar(top, 5, ) if False else top[5][0][1])
    f5_5 = fields(f5[5][0][1])
    f6 = fields(top[6][0][1])
    f7 = fields(top[7][0][1])
    sig = top[9][0][1]
    f9 = fields(sig)
    f6_19 = fields(f6[19][0][1])
    perms = []
    for e in f6_19.get(3, []):
        ee = fields(e[1])
        perms.append((ee[1][0][1].decode(), ee[2][0][1]))
    d["top_fields"] = sorted(top.keys())
    d["hostname"] = f5[1][0][1].decode()
    d["ua"] = f5_5[1][0][1].decode()
    d["rtt"] = f5_5[3][0][1]
    d["mediaDigest"] = f5_5[9][0][1].decode()
    d["pluginsDigest"] = f5_5[11][0][1].decode()
    d["osRelease"] = f6[6][0][1].decode()
    d["platform"] = f6[7][0][1].decode()
    d["systemName"] = f6[8][0][1].decode()
    d["systemVersion"] = f6[9][0][1].decode()
    d["locale"] = f6[12][0][1].decode()
    d["langs"] = [x[1].decode() for x in f6[13]]
    d["tz"] = f6[14][0][1].decode()
    d["fontsDigest"] = f6[17][0][1].decode()
    d["manufacturer"] = f7[1][0][1].decode()
    d["model"] = f7[2][0][1].decode()
    d["arch"] = f7[3][0][1].decode()
    d["cpu"] = f7[4][0][1]
    d["mem_raw"] = f7[6][0][1]
    inner = fields(f7[8][0][1])
    d["inner"] = [inner[1][0][1], inner[2][0][1]]
    phys = fields(f7[10][0][1])
    d["screen"] = [phys[1][0][1], phys[2][0][1]]
    d["dpr9"] = struct.unpack("<f", f7[9][0][1])[0]
    d["dpr11"] = struct.unpack("<f", f7[11][0][1])[0]
    d["f9"] = {k: [show(v) for v in f9.get(k, [])] for k in sorted(f9)}
    d["permHead"] = f6_19.get(1, [(None, None)])[0][1]
    d["permState0"] = f6_19[2][0][1]
    d["permStates_raw"] = f6_19.get(3, [])
    d["perms"] = perms
    d["n_f5_fields"] = sorted(f5.keys())
    d["n_f5_5_fields"] = sorted(f5_5.keys())
    d["n_f6_fields"] = sorted(f6.keys())
    d["n_f7_fields"] = sorted(f7.keys())
    d["n_f6_19_fields"] = sorted(f6_19.keys())
    return d


def main():
    a = extract(os.path.join(FX, "real_sig86.proto.bin"))
    b = extract(os.path.join(FX, "real_sig92.proto.bin"))
    raw86 = open(os.path.join(FX, "real_sig86.proto.bin"), "rb").read()
    raw92 = open(os.path.join(FX, "real_sig92.proto.bin"), "rb").read()
    print(f"sig86 proto: {len(raw86)} bytes, top fields {a['top_fields']}")
    print(f"sig92 proto: {len(raw92)} bytes, top fields {b['top_fields']}")
    print(f"sig86 subfields: f5={a['n_f5_fields']} f5.5={a['n_f5_5_fields']} f6={a['n_f6_fields']} "
          f"f7={a['n_f7_fields']} f6.19={a['n_f6_19_fields']}")
    print(f"sig92 subfields: f5={b['n_f5_fields']} f5.5={b['n_f5_5_fields']} f6={b['n_f6_fields']} "
          f"f7={b['n_f7_fields']} f6.19={b['n_f6_19_fields']}")

    print("\n=== full recursive diff sig86 vs sig92 ===")
    diffs = diff(fields(raw86), fields(raw92))
    for dline in diffs:
        print("  DIFF", dline)
    if not diffs:
        print("  (protos byte-identical)")

    print("\n=== claimed values (sig86 | sig92) ===")
    for k in ("hostname", "manufacturer", "model", "arch", "cpu", "mem_raw", "inner", "screen",
              "dpr9", "dpr11", "osRelease", "systemName", "systemVersion", "locale", "langs",
              "tz", "fontsDigest", "ua", "rtt", "mediaDigest", "pluginsDigest",
              "permHead", "permState0"):
        print(f"  {k:14s}: {a[k]!r} | {b[k]!r}")
    print(f"  perms count   : {len(a['perms'])} | {len(b['perms'])}")
    print(f"  perms sig86   : {sorted(a['perms'])}")
    print(f"  perms sig92   : {sorted(b['perms'])}")
    print(f"  perm sets equal: {sorted(a['perms']) == sorted(b['perms'])}   "
          f"perm orders equal: {a['perms'] == b['perms']}")
    print(f"  f9 sig86      : {a['f9']}")
    print(f"  f9 sig92      : {b['f9']}")

    print("\n=== top-level tree (sig86) — characterizing dispatch/envelope fields ===")
    raw = fields(raw86)
    for line in tree(raw, "  "):
        print(line)

    print("\n=== f9 claims ===")
    ok = True
    f986, f992 = a["f9"], b["f9"]
    c1 = f986.get(1) == [4] and f986.get(2) == ["fb777997a04a586c219bb6d424fcc0c4"]
    c2 = f992.get(2) == ["6716c0f443514fa27326ea3b40cbcacc"]
    print(f"  sig86 f9 == {{1:4, 2:fb777997a04a586c219bb6d424fcc0c4}} : {c1}")
    print(f"  sig92 f9.2 == 6716c0f443514fa27326ea3b40cbcacc           : {c2}  (f9.1={f992.get(1)})")
    ok &= c1 and c2

    print("\n=== value claims ===")
    claims = {
        "cpu f7.4 == 4": a["cpu"] == 4 == b["cpu"],
        "mem f7.6 == 17179869184": a["mem_raw"] == 17179869184 == b["mem_raw"],
        "inner f7.8 == [958,896]": a["inner"] == [958, 896] == b["inner"],
        "screen f7.10 == [1920,1080]": a["screen"] == [1920, 1080] == b["screen"],
        "dpr f7.9 == f7.11 == 1.0": a["dpr9"] == 1.0 and a["dpr11"] == 1.0 and b["dpr9"] == 1.0 and b["dpr11"] == 1.0,
        "langs has 4 entries": len(a["langs"]) == 4 == len(b["langs"]),
        "notification f6.19.2 == 'default'": a["permState0"] == b"default" == b["permState0"],
        "19 perms in f6.19.3": len(a["perms"]) == 19 == len(b["perms"]),
        "rtt sig86 == 200": a["rtt"] == 200,
        "rtt sig92 == 100": b["rtt"] == 100,
    }
    for k, v in claims.items():
        print(f"  {k}: {v}")
        ok &= v

    print("\n=== comparison vs out/gt/*.json (parse_sig capture) ===")
    for name, d in (("real_sig86", a), ("real_sig92", b)):
        j = json.load(open(os.path.join(GT, name + ".json")))
        j["inner"] = [j["innerMsg"]["1"][0], j["innerMsg"]["2"][0]]
        j["screen"] = [j["physMsg"]["1"][0], j["physMsg"]["2"][0]]
        pairs = [
            ("hostname", d["hostname"], j["hostname"]),
            ("ua", d["ua"], j["ua"]),
            ("rtt", d["rtt"], j["rtt"]),
            ("mediaDigest", d["mediaDigest"], j["mediaDigest"]),
            ("pluginsDigest", d["pluginsDigest"], j["pluginsDigest"]),
            ("osRelease", d["osRelease"], j["osRelease"]),
            ("systemName", d["systemName"], j["systemName"]),
            ("systemVersion", d["systemVersion"], j["systemVersion"]),
            ("locale", d["locale"], j["locale"]),
            ("langs", d["langs"], j["langs"]),
            ("tz", d["tz"], j["tz"]),
            ("fontsDigest", d["fontsDigest"], j["fontsDigest"]),
            ("manufacturer", d["manufacturer"], j["manufacturer"]),
            ("model", d["model"], j["model"]),
            ("arch", d["arch"], j["arch"]),
            ("cpu", d["cpu"], j["cpu"]),
            ("memGiB", d["mem_raw"] // (1 << 30), j["memGiB"]),
            ("inner", d["inner"], j["inner"]),
            ("screen", d["screen"], j["screen"]),
            ("permHead", d["permHead"], j["permHead"]),
            ("permState0", d["permState0"].decode(), bytes.fromhex(j["permState0"]).decode()),
            ("perms(set)", sorted(d["perms"]), sorted(map(tuple, j["perms"]))),
        ]
        for k, mine, theirs in pairs:
            if mine != theirs:
                print(f"  MISMATCH {name}.{k}: mine={mine!r} json={theirs!r}")
                ok = False
        print(f"  {name}: all {len(pairs)} captured values match out/gt/{name}.json")

    print("\n=== buffer reconstruction (independent) ===")
    def env_from(d, conn=None):
        return dict(
            appVersion=None, tz=d["tz"], manufacturer=d["manufacturer"], osType=d["platform"],
            arch=d["arch"], fontsDigest=d["fontsDigest"], cpu=d["cpu"], locale=d["locale"],
            langs=d["langs"], ua=d["ua"], connType=conn, rtt=d["rtt"], cookies=True,
            localStorage=True, indexedDB=True, dnt=None, multiTouch=False,
            mediaDigest=d["mediaDigest"], pluginsDigest=d["pluginsDigest"],
            systemName=d["systemName"], hostname=d["hostname"], systemVersion=d["systemVersion"],
            screenW=d["screen"][0], screenH=d["screen"][1], memGiB=d["mem_raw"] // (1 << 30),
            osRelease=d["osRelease"], model=d["model"], innerW=d["inner"][0], innerH=d["inner"][1],
            dpr=d["dpr9"], automation=False, notification=d["permState0"].decode(),
            perms=sorted(d["perms"]),
        )

    ri = open(os.path.join(FX, "real_input.bin"), "rb").read()
    e86 = env_from(a)
    buf86 = build_buffer(e86)
    print(f"  build(extracted sig86 values) == fixtures/real_input.bin : {buf86 == ri} ({len(buf86)} bytes)")
    print(f"  build(...) == out/gt/real_sig86_rebuilt.bin              : "
          f"{buf86 == open(os.path.join(GT, 'real_sig86_rebuilt.bin'), 'rb').read()}")
    e92 = env_from(b)
    buf92 = build_buffer(e92)
    print(f"  build(extracted sig92 values) == out/gt/real_sig92_rebuilt.bin : "
          f"{buf92 == open(os.path.join(GT, 'real_sig92_rebuilt.bin'), 'rb').read()}")
    ok &= buf86 == ri

    leaks = json.load(open(os.path.join(LEAKS, "real_leaks114.json")))
    wifi_live = bytes.fromhex(leaks[0]["data"])
    buf_wifi = build_buffer({**e86, "connType": "wifi"})
    print(f"  build(sig86 + connType='wifi') == leaks record[0].data   : "
          f"{buf_wifi == wifi_live} ({len(buf_wifi)} vs {len(wifi_live)} bytes)")
    ok &= buf_wifi == wifi_live

    # explicit insertion-position check: ee966696 sits before the 0000+rtt bytes
    bit = bytes(int(f"{i:08b}"[::-1], 2) for i in range(256))
    ee = bytes(bit[c] for c in b"wifi")
    pos = buf86.find(bytes(bit[c] for c in b"go.seated.com")) + len(b"go.seated.com")  # end of hostname
    # locate '000000'+bitrev(rtt) region: after bitrev(ua) comes [connType] 000000 rtt
    idx = buf86.find(b"\x00\x00\x00" + bytes([bit[a['rtt']]]))
    manual = buf86[:idx] + ee + buf86[idx:]
    print(f"  manual insert ee966696 before '000000'+rtt({hex(bit[a['rtt']])}) @off {idx} == record[0].data : "
          f"{manual == wifi_live}")
    ok &= manual == wifi_live
    wpos = wifi_live.find(ee)
    print(f"  ee966696 offset in 882 record: {wpos}; bytes after: {wifi_live[wpos+4:wpos+8].hex(' ')} "
          f"(000000 + {hex(bit[a['rtt']])}=bitrev({a['rtt']}))")

    print("\nRESULT:", "ALL CLAIM-2/4 RECONSTRUCTION CHECKS PASS" if ok else "FAILURES PRESENT")


if __name__ == "__main__":
    main()
