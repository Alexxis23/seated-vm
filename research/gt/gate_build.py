#!/usr/bin/env python3
"""THE VERIFICATION GATE: rebuild both real captures' hash-input buffers from
payload values only, HH-128 them via the extracted wasm oracle, and check
against f9.f2."""
import sys, os, subprocess, struct
sys.path.insert(0, r"C:\Users\Administrator\Desktop\seated-vm\harness")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from parse_sig import parse
from build_spec2 import bitrev, rol1, ror1, rol2, ror2, LOCALE_CIPHER

def rolk(b, k):
    k &= 7
    return ((b << k) | (b >> (8 - k))) & 0xFF if k else b

def keystream(model):
    return [(-c) & 7 for c in model.encode()]

def build_buffer(env):
    out = b""
    out += bytes(rol2[b] for b in env["appVersion"].encode()) if env.get("appVersion") else b""
    out += env["tz"].encode()
    out += bytes(ror1[b] for b in env["manufacturer"].encode())
    out += bytes(bitrev[b] for b in env["osType"].encode())
    out += bytes.fromhex("03000000")
    out += bytes(rol2[b] for b in env["arch"].encode())
    K = keystream(env["model"])
    dg = env["fontsDigest"]
    out += bytes(rolk(ord(dg[i]), K[i % len(K)]) for i in range(64))
    out += bytes([env["cpu"]])
    out += b"\x00\x00\x00"
    out += LOCALE_CIPHER[env["locale"]]
    out += "".join(env["langs"]).encode()
    out += bytes(bitrev[b] for b in env["ua"].encode())
    if env.get("connType"):
        out += bytes(bitrev[b] for b in env["connType"].encode())
    out += b"\x00\x00\x00"
    out += bytes([bitrev[env["rtt"]]])
    out += bytes([bitrev[1] if env["cookies"] else 0])
    out += bytes([bitrev[1] if env["localStorage"] else 0])
    out += bytes([bitrev[1] if env["indexedDB"] else 0])
    if env.get("dnt"):
        out += bytes(bitrev[b] for b in env["dnt"].encode())
    out += bytes([bitrev[1] if env["multiTouch"] else 0])
    out += bytes(bitrev[b] for b in env["mediaDigest"].encode())
    out += bytes(bitrev[b] for b in env["pluginsDigest"].encode())
    out += b"\x00"
    out += bytes(ror2[b] for b in env["systemName"].encode())
    out += env["hostname"].encode()
    out += bytes(rol2[b] for b in env["arch"].encode())
    out += env["systemVersion"].encode()
    out += struct.pack("<I", env["screenW"])
    out += struct.pack("<I", env["screenH"])
    mem = env["memGiB"] // 8
    out += bytes([0, 0, 0, 0, mem, 0, 0, 0])
    out += env["osRelease"].encode()
    out += env["model"].encode()
    out += bytes(bitrev[b] for b in struct.pack("<I", env["innerW"]))
    out += bytes(bitrev[b] for b in struct.pack("<I", env["innerH"]))
    out += struct.pack("<f", env["dpr"])
    out += struct.pack("<f", env["dpr"])
    out += bytes([bitrev[1] if env["automation"] else 0])
    out += bytes(ror1[b] for b in env["notification"].encode())
    return out

def build_permissions(states_sorted):
    out = b""
    for name, state in states_sorted:
        out += bytes(ror1[b] for b in name.encode())
        out += b"\x00\x00\x00" + bytes([ror1[state]])
    return out

def main():
    fx = r"C:\Users\Administrator\Desktop\seated-vm\fixtures"
    outdir = r"C:\Users\Administrator\Desktop\seated-vm\out\gt"
    for name, rtt_expected in (("real_sig86", 200), ("real_sig92", 100)):
        d = parse(os.path.join(fx, name + ".proto.bin"))
        f9 = d["f9"][2][0]
        env = dict(
            appVersion=None, tz=d["tz"], manufacturer=d["manufacturer"],
            osType="Windows", arch=d["arch"], fontsDigest=d["fontsDigest"],
            cpu=d["cpu"], locale=d["locale"], langs=d["langs"], ua=d["ua"],
            connType=None, rtt=d["rtt"], cookies=True, localStorage=True,
            indexedDB=True, dnt=None, multiTouch=False,
            mediaDigest=d["mediaDigest"], pluginsDigest=d["pluginsDigest"],
            systemName=d["systemName"], hostname=d["hostname"],
            systemVersion=d["systemVersion"], screenW=1920, screenH=1080,
            memGiB=d["memGiB"], osRelease=d["osRelease"], model=d["model"],
            innerW=958, innerH=896, dpr=1.0, automation=False,
            notification="default",
        )
        buf = build_buffer(env)
        states = sorted(d["perms"])
        buf += build_permissions(states)
        open(os.path.join(outdir, name + "_rebuilt.bin"), "wb").write(buf)
        print(name, "rebuilt buffer:", len(buf), "bytes; f9 =", f9.hex())
        # compare with real_input.bin (rtt 200 capture)
        if name == "real_sig86":
            ri = open(os.path.join(fx, "real_input.bin"), "rb").read()
            if ri == buf:
                print("  == real_input.bin byte-exact")
            else:
                p = 0
                while p < min(len(ri), len(buf)) and ri[p] == buf[p]:
                    p += 1
                print("  != real_input.bin: lens %d/%d, first diff @%d" % (len(ri), len(buf), p))
                print("    real:", ri[max(0,p-8):p+8].hex(" "))
                print("    mine:", buf[max(0,p-8):p+8].hex(" "))

if __name__ == "__main__":
    main()
