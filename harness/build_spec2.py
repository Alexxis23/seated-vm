import sys, hashlib, struct
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import os
h = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")

bitrev = bytes(int(f"{i:08b}"[::-1], 2) for i in range(256))
rol1 = bytes(((i << 1) | (i >> 7)) & 0xff for i in range(256))
ror1 = bytes(((i >> 1) | (i << 7)) & 0xff for i in range(256))
rol2 = bytes(((i << 2) | (i >> 6)) & 0xff for i in range(256))
ror2 = bytes(((i >> 2) | (i << 6)) & 0xff for i in range(256))

def rolk(b, k):
    k %= 8
    return ((b << k) | (b >> (8 - k))) & 0xff if k else b

FONTS_ROT = [5,0,6,1,3,7,3,3,3,7,5,7,2,0,2,0,2,0,6,6,1,1,1,1,4,3,0,5,0,6,1,3,
             3,3,7,5,7,2,0,2,2,0,5,0,2,0,5,0,6,1,3,7,3,3,3,7,5,7,2,0,2,0,2,0]

LOCALE_CIPHER = {
    "en-US": bytes.fromhex("2b6eb4aa6a"),
    "en-GB": bytes.fromhex("2b6eb4a348"),
    "en-AU": bytes.fromhex("2b6eb4a0aa"),
    "pl-PL": bytes.fromhex("836cb42889"),
}

PERM_NAMES = ["accelerometer","ambient-light-sensor","background-sync","bluetooth","camera",
"captured-surface-control","clipboard-read","clipboard-write","compute-pressure","display-capture",
"geolocation","gyroscope","local-fonts","magnetometer","microphone","midi","notifications",
"payment-handler","persistent-storage","push","screen-wake-lock","storage-access",
"top-level-storage-access","window-management"]

def fonts_cipher(digest_hex):
    return bytes(rolk(b, FONTS_ROT[i]) for i, b in enumerate(digest_hex.encode()))

def media_digest_hex(all_supported=True):
    codecs = ["audio/ogg; codecs=vorbis","audio/ogg; codecs=flac",'audio/mp4; codecs="mp4a.40.2"','audio/mpeg; codecs="mp3"','video/mp4; codecs="avc1.42E01E"']
    val = "true" if all_supported else "false"
    parts = sorted(c + ":" + val for c in codecs)
    return hashlib.sha256("::".join(parts).encode()).hexdigest()

def plugins_digest_hex(names):
    low = sorted(n.lower() for n in names)
    return hashlib.sha256("::".join(low).encode()).hexdigest()

def build(env):
    out = b""
    out += bytes(rol2[b] for b in env["appVersion"].encode()) if env.get("appVersion") else b""
    out += env["tz"].encode()
    out += bytes(ror1[b] for b in env["manufacturer"].encode())
    out += bytes(bitrev[b] for b in env["osType"].encode())
    out += bytes.fromhex("03000000")
    out += bytes(rol2[b] for b in env["arch"].encode())
    out += fonts_cipher(env["fontsDigest"])
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
    for i, name in enumerate(PERM_NAMES):
        out += bytes(ror1[b] for b in name.encode())
        stateVal = 1 if env["grantedPerm"] == name else 3
        out += b"\x00\x00\x00" + bytes([ror1[stateVal]])
    return out

def fvl_fields(fvl):
    systemName = fvl[0]["brand"]
    systemVersion = fvl[0]["version"]
    manufacturer = "::".join(sorted(b["brand"] for b in fvl))
    model = "::".join(sorted(b["brand"] + "-" + b["version"] for b in fvl))
    return systemName, systemVersion, manufacturer, model

def fonts_digest_of(font, os_type):
    zA = {"-apple-system":"MacOS","Segoe UI":"Windows","Tahoma":"Windows","Yu Gothic UI":"Windows",
          "Microsoft JhengHei UI":"Windows","Microsoft YaHei UI":"Windows","Meiryo UI":"Windows",
          "Cantarell":"Linux","Ubuntu":"Linux","Sans":"Linux","sans-serif":"Linux","Fira Sans":"Linux","Roboto":"Android"}
    s = font + (":" + zA[font] if font in zA else "")
    return hashlib.sha256(s.encode()).hexdigest()

DEFAULT_FVL = [{"brand":"Chromium","version":"131.0.0.0"},{"brand":"Google Chrome","version":"131.0.6830.0"}]

def mkenv(**over):
    e = dict(
        appVersion="1.2.3", tz="Europe/Warsaw", osType="Windows", arch="x86",
        fontsDigest=fonts_digest_of("Segoe UI", "Windows"), cpu=12, locale="en-US",
        langs=["en-US","en"],
        ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        connType="wifi", rtt=50, cookies=True, localStorage=True, indexedDB=True,
        dnt="1", multiTouch=True, mediaDigest=media_digest_hex(True),
        pluginsDigest=plugins_digest_hex(["PDF Viewer","Chrome PDF Viewer"]),
        hostname="go.seated.com", systemVersion="131.0.0.0",
        screenW=2560, screenH=1440, memGiB=8, osRelease="15.0.0",
        model="Chromium-131.0.0.0::Google Chrome-131.0.6830.0",
        innerW=1280, innerH=720, dpr=2.0, automation=False,
        notification="granted", grantedPerm="geolocation",
        systemName="Chromium", manufacturer="Chromium::Google Chrome")
    e.update(over)
    return e

def fix_fvl(e, fvl):
    sn, sv, man, model = fvl_fields(fvl)
    e.update(systemName=sn, systemVersion=sv, manufacturer=man, model=model)
    return e

base = open(h + r"\base.bin","rb").read()
mine = build(mkenv())
print("base:", "MATCH" if mine == base else f"FAIL len {len(mine)} vs {len(base)}")

samples = {
 "s1": mkenv(tz="Asia/Tokyo", cpu=6),
 "s2": mkenv(ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
             tz="America/Chicago", cpu=16, memGiB=32, screenW=3840, screenH=2160, innerW=1920, innerH=1040, dpr=1.5,
             fontsDigest=fonts_digest_of("Tahoma", "Windows"), appVersion="5.5.5", connType="ethernet",
             mediaDigest=None, rtt=25, notification="denied"),
 "s3": fix_fvl(mkenv(ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
             tz="Europe/London", locale="en-GB", langs=["en-GB","en"], cpu=8, memGiB=16,
             screenW=2560, screenH=1440, innerW=1440, innerH=900, dpr=2.0,
             fontsDigest=fonts_digest_of("Helvetica Neue", None), osType="macOS", arch="arm", osRelease="14.5.1"),
             DEFAULT_FVL),
 "s4": mkenv(),
 "s5": mkenv(ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
             tz="Australia/Sydney", locale="en-AU", langs=["en-AU","en"], cpu=20, memGiB=16,
             screenW=2560, screenH=1440, innerW=1512, innerH=982, dpr=1.25,
             pluginsDigest=plugins_digest_hex(["A","B","C"]), mediaDigest=media_digest_hex(False)),
 "s6": mkenv(ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
             tz="America/Los_Angeles", cpu=4, screenW=1680, screenH=1050, innerW=1218, innerH=683, dpr=2.0,
             grantedPerm="camera"),
 "s7": mkenv(fontsDigest=fonts_digest_of("zzzfont", None)),
}
# s2 rtt: CONN had rtt 25 -> the rtt in env comes from connection
samples["s2"]["rtt"] = 25

allok = True
for name, env in samples.items():
    if env.get("mediaDigest") is None:
        env["mediaDigest"] = media_digest_hex(True)
    d = open(h + f"\\{name}.bin","rb").read()
    mine = build(env)
    if mine == d:
        print(f"{name}: MATCH ({len(mine)} bytes)")
    else:
        allok = False
        p = 0
        while p < min(len(mine), len(d)) and mine[p] == d[p]: p += 1
        print(f"{name}: FAIL len {len(mine)} vs {len(d)}, first diff @{p}")
        print("  mine:", mine[max(0,p-8):p+8].hex(" "))
        print("  real:", d[max(0,p-8):p+8].hex(" "))
print("ALL OK" if allok else "FAILURES PRESENT")

