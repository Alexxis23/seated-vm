#!/usr/bin/env python3
"""INDEPENDENT re-verification of the fonts-zone keystream claim.

Claim under test:
    zone[i] = rotl_u8(digest_ascii[i], k[i])           i = 0..63
    k[i]    = (-utf8(model)[i mod len(model)]) & 7
    model   = "::".join(sorted(brand + "-" + version for fullVersionList))
    rotl_u8(x,k) = ((x<<k)|(x>>(8-k)))&0xFF, k=0 -> x

Nothing here imports out/keystream_solver.py; all logic re-derived from the
claim text / documented buffer layout alone.
Writes out/verify/report.txt; exits 0 iff every check passes.
"""
import sys, os, hashlib
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FX = os.path.join(ROOT, "fixtures")
OUT = os.path.dirname(os.path.abspath(__file__))

# ------------------------------------------------------------ primitives
def rotl_u8(x, k):
    k &= 7
    if k == 0:
        return x & 0xFF
    return ((x << k) | (x >> (8 - k))) & 0xFF

def ror_u8(x, k):
    k &= 7
    if k == 0:
        return x & 0xFF
    return ((x >> k) | (x << (8 - k))) & 0xFF

# tables for the *documented* prefix obfuscations
# (TASK-KEYSTREAM.md: appVersion rol2, tz raw, manufacturer ror1,
#  osType bitrev, 03 00 00 00, arch rol2)
BITREV = bytes(int(f"{i:08b}"[::-1], 2) for i in range(256))
ROL2 = bytes(rotl_u8(i, 2) for i in range(256))
ROR1 = bytes(ror_u8(i, 1) for i in range(256))
IDX = {t: {v: i for i, v in enumerate(t)} for t in (BITREV, ROL2, ROR1)}

def de(table, data):
    return bytes(IDX[table][b] for b in data)

# ------------------------------------------------------------ claim rule
def model_of(fvl):
    return "::".join(sorted(e["brand"] + "-" + e["version"] for e in fvl))

def keystream(model):
    return [(-b) & 7 for b in model.encode("utf-8")]

def encrypt_zone(digest_hex, model):
    dg, K = digest_hex.encode("ascii"), keystream(model)
    return bytes(rotl_u8(dg[i], K[i % len(K)]) for i in range(64))

def decrypt_zone(zone64, model):
    K = keystream(model)
    return bytes(ror_u8(zone64[i], K[i % len(K)]) for i in range(64))

def rot_candidates(dbyte, zbyte):
    """all k in 0..7 with rotl_u8(dbyte,k)==zbyte"""
    return [k for k in range(8) if rotl_u8(dbyte, k) == zbyte]

def sha_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

# ------------------------------------------------------------ fixtures
FVL131 = [{"brand": "Chromium", "version": "131.0.0.0"},
          {"brand": "Google Chrome", "version": "131.0.6830.0"}]
FVL156 = [{"brand": "Not:A-Brand", "version": "8.0.0.0"},
          {"brand": "Chromium", "version": "156.0.8078.80"},
          {"brand": "Google Chrome", "version": "156.0.8078.80"}]
M131, M156 = model_of(FVL131), model_of(FVL156)
MAN131, MAN156 = "::".join(sorted(b["brand"] for b in FVL131)), \
                 "::".join(sorted(b["brand"] for b in FVL156))
DG_SEG = sha_hex("Segoe UI:Windows")
DG_TAH = sha_hex("Tahoma:Windows")
DG_HEL = sha_hex("Helvetica Neue")
DG_ZZZ = sha_hex("zzzfont")
DG_REAL = "61052e74ac13cb864ce5331005cdc65836d3c6f1532abf520ae52fa200ecee30"

# documented prefix fields (env values per harness/build_spec2.py + claim)
PREFIX_DOCS = {
    "base.bin":       ("1.2.3", "Europe/Warsaw",     MAN131, "Windows", "x86"),
    "s1.bin":         ("1.2.3", "Asia/Tokyo",        MAN131, "Windows", "x86"),
    "s2.bin":         ("5.5.5", "America/Chicago",   MAN131, "Windows", "x86"),
    "s3.bin":         ("1.2.3", "Europe/London",     MAN131, "macOS",   "arm"),
    "s4.bin":         ("1.2.3", "Europe/Warsaw",     MAN131, "Windows", "x86"),
    "s5.bin":         ("1.2.3", "Australia/Sydney",  MAN131, "Windows", "x86"),
    "s6.bin":         ("1.2.3", "America/Los_Angeles", MAN131, "Windows", "x86"),
    "s7.bin":         ("1.2.3", "Europe/Warsaw",     MAN131, "Windows", "x86"),
    "real_input.bin": ("",      "Europe/Warsaw",     MAN156, "Windows", "x86"),
    "digest0.bin":    ("",      "Europe/Warsaw",     MAN156, "Windows", "x86"),
    "digest1.bin":    ("",      "Europe/Warsaw",     MAN156, "Windows", "x86"),
    "digest2.bin":    ("",      "Europe/Warsaw",     MAN156, "Windows", "x86"),
    "digest3.bin":    ("",      "Europe/Warsaw",     MAN156, "Windows", "x86"),
    "digest4.bin":    ("",      "Europe/Warsaw",     MAN156, "Windows", "x86"),
}

FIXTURES = [
    ("base.bin",       M131, DG_SEG),
    ("s1.bin",         M131, DG_SEG),
    ("s2.bin",         M131, DG_TAH),
    ("s3.bin",         M131, DG_HEL),
    ("s4.bin",         M131, DG_SEG),
    ("s5.bin",         M131, DG_SEG),
    ("s6.bin",         M131, DG_SEG),
    ("s7.bin",         M131, DG_ZZZ),
    ("real_input.bin", M156, DG_REAL),
    ("digest0.bin",    M156, "0" * 64),
    ("digest1.bin",    M156, "f" * 64),
    ("digest2.bin",    M156, "0123456789abcdef" * 4),
    ("digest3.bin",    M156, "aaaaaaaabbbbbbbbccccccccdddddddd" * 2),
    ("digest4.bin",    M156, DG_REAL),
]
EXPECTED_OFF = {"base.bin": 55, "s1.bin": 52, "s2.bin": 57, "s3.bin": 53,
                "s4.bin": 55, "s5.bin": 58, "s6.bin": 61, "s7.bin": 55,
                "real_input.bin": 63, "digest0.bin": 63, "digest1.bin": 63,
                "digest2.bin": 63, "digest3.bin": 63, "digest4.bin": 63}

lines = []
def emit(s=""):
    print(s)
    lines.append(s)

# ============================================================ 1. per-fixture
emit("=" * 78)
emit("STEP 1: per-fixture fonts-zone verification (independent implementation)")
emit("=" * 78)
results, allok = {}, True
for name, model, dg in FIXTURES:
    buf = open(os.path.join(FX, name), "rb").read()
    K = keystream(model)
    z_expect = encrypt_zone(dg, model)
    off = buf.find(z_expect)
    okA = okB = okC = False
    if off >= 0:
        zone = buf[off:off + 64]
        okA = decrypt_zone(zone, model) == dg.encode("ascii")   # de-rotate == digest
        okB = z_expect == zone                                  # re-encrypt == zone
        okC = all(rotl_u8(ord(dg[i]), K[i % len(K)]) == zone[i] for i in range(64))
    uniq = off >= 0 and buf.count(z_expect) == 1
    exp = EXPECTED_OFF[name]
    off_ok = off == exp
    status = "PASS" if (okA and okB and okC and uniq and off_ok) else "FAIL"
    if status == "FAIL":
        allok = False
    results[name] = (status, off)
    dg_s = dg if len(dg) <= 24 else dg[:12] + ".." + dg[-8:]
    emit(f"  {name:16s} zone@{off if off>=0 else '-':>3} (expect {exp:>2}) "
         f"derot==digest:{okA} reenc==zone:{okB} perpos:{okC} unique:{uniq} "
         f"-> {status}")
    emit(f"       digest={dg_s}  model={model}")
emit()
emit("PER-FIXTURE PASS/FAIL TABLE:")
for name, _, _ in FIXTURES:
    st, off = results[name]
    emit(f"  {name:16s} {st}  zone@{off}")
emit(f"  OVERALL: {'ALL PASS' if allok else 'FAILURES PRESENT'}")

# ============================================================ 2. maps
emit()
emit("=" * 78)
emit("STEP 2: char->rotation maps from base.bin and real_input.bin zones")
emit("=" * 78)

def extract_map(fname, model, dg):
    buf = open(os.path.join(FX, fname), "rb").read()
    off = EXPECTED_OFF[fname]
    zone, dgb = buf[off:off + 64], dg.encode("ascii")
    mb, K = model.encode("utf-8"), keystream(model)
    unamb, amb = {}, []
    for i in range(64):
        mc = mb[i % len(mb)]
        cands = rot_candidates(dgb[i], zone[i])
        if len(cands) == 1:
            unamb.setdefault(mc, set()).add(cands[0])
        else:
            amb.append((i, chr(mc), cands, K[i % len(mb)]))
    return unamb, amb

maps = {}
map_ok = True
for fname, model, dg, tag in [("base.bin", M131, DG_SEG, "base"),
                              ("real_input.bin", M156, DG_REAL, "real")]:
    unamb, amb = extract_map(fname, model, dg)
    maps[tag] = unamb
    emit(f"--- {fname}: {len(unamb)} unambiguous model-chars, {len(amb)} ambiguous positions")
    bad = 0
    for c in sorted(unamb):
        pred = (-c) & 7
        ok = unamb[c] == {pred}
        if not ok:
            map_ok = False
            bad += 1
        emit(f"    {chr(c)!r:6s} byte=0x{c:02x} k={sorted(unamb[c])} "
             f"predict={pred} {'OK' if ok else 'MISMATCH'}")
    n_amb_in = 0
    for i, ch, cands, kpred in amb:
        inside = kpred in cands
        if not inside:
            map_ok = False
        else:
            n_amb_in += 1
    if amb:
        emit(f"    ambiguous positions: {len(amb)}, claimed-k inside candidates: {n_amb_in}")
        for i, ch, cands, kpred in amb[:6]:
            emit(f"      e.g. pos {i:2d} model-char {ch!r} candidates {cands} claimed {kpred}")
    emit(f"    -> {fname} map: {'ALL k == (-byte)&7' if bad == 0 else f'{bad} MISMATCHES'}")

shared = sorted(set(maps["base"]) & set(maps["real"]))
emit()
emit(f"shared model chars ({len(shared)}):")
for c in shared:
    same = maps["base"][c] == maps["real"][c]
    pred = (-c) & 7
    ok = same and maps["base"][c] == {pred}
    if not ok:
        map_ok = False
    emit(f"  {chr(c)!r:6s} base={sorted(maps['base'][c])} real={sorted(maps['real'][c])} "
         f"predict={pred} {'OK' if ok else 'MISMATCH'}")
emit(f"  MAP CONSISTENCY: {'CONSISTENT, all shared chars k == (-byte)&7' if map_ok else 'INCONSISTENCY FOUND'}")

# ============================================================ 3. prefixes
emit()
emit("=" * 78)
emit("STEP 3: zone offsets vs documented buffer prefixes")
emit("=" * 78)
emit("layout: [appVersion rol2][tz raw][manufacturer ror1][osType bitrev]"
     "[03 00 00 00][arch rol2][FONTS ZONE 64]")
prefix_ok = True
for name, av, tz, man, osT, arch in [(n, *PREFIX_DOCS[n]) for n, _, _ in FIXTURES]:
    buf = open(os.path.join(FX, name), "rb").read()
    off = results[name][1]
    if off < 0:
        continue
    avb, tzb, manb, osb, archb = av.encode(), tz.encode(), man.encode(), osT.encode(), arch.encode()
    L = len(avb) + len(tzb) + len(manb) + len(osb) + 4 + 3
    p = buf
    ok_marker = p[L - 7:L - 3] == b"\x03\x00\x00\x00"
    ok_av = (de(ROL2, p[0:len(avb)]) == avb) if avb else (len(avb) == 0)
    ok_tz = p[len(avb):len(avb) + len(tzb)] == tzb
    o1 = len(avb) + len(tzb)
    ok_man = de(ROR1, p[o1:o1 + len(manb)]) == manb
    o2 = o1 + len(manb)
    ok_os = de(BITREV, p[o2:o2 + len(osb)]) == osb
    ok_arch = de(ROL2, p[L - 3:L]) == archb
    ok_len = L == off
    ok = ok_marker and ok_av and ok_tz and ok_man and ok_os and ok_arch and ok_len
    if not ok:
        prefix_ok = False
    emit(f"  {name:16s} documented-prefix-len={L:3d} zone@{off:3d} "
         f"av:{ok_av} tz:{ok_tz} man:{ok_man} os:{ok_os} "
         f"marker:{ok_marker} arch:{ok_arch} -> {'OK' if ok else 'MISMATCH'}")
emit()
emit("  BASE ARITHMETIC: 5('1.2.3') + 13('Europe/Warsaw') + 23('Chromium::Google Chrome')"
     f" + 7('Windows') + 4(marker) + 3('x86') = {5 + 13 + 23 + 7 + 4 + 3} (== base zone@55)")

# ============================================================ verdict
emit()
emit("=" * 78)
verdict = allok and map_ok and prefix_ok
emit(f"FINAL VERDICT: {'CLAIM VERIFIED - all independent checks pass' if verdict else 'CLAIM NOT VERIFIED'}")
emit("=" * 78)

with open(os.path.join(OUT, "report.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
sys.exit(0 if verdict else 1)
