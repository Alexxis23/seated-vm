#!/usr/bin/env python3
"""Extract the fonts-zone rotation keystream k[0..63] from fixture buffers.

The fonts zone is 64 bytes = rol_k[i](digest_hex_utf8[i]), k[i] in 0..7.
This script:
  1. scans each fixture bin for the zone start offset (50..70, prefer 55/63);
  2. extracts k per byte from the known digest (base/real) or from the
     keystream solved on base.bin (de-rotate -> recover digest -> verify hex);
  3. verifies against the known OLD keystream (build_spec2.FONTS_ROT);
  4. best-effort dumps the protobuf fields of real_sig92/sig86.proto.bin.
Print-only; writes no files.
"""
import hashlib
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.normpath(os.path.join(HERE, "..", "..", "fixtures"))

# Known OLD keystream (harness/build_spec2.py FONTS_ROT)
OLD = [5, 0, 6, 1, 3, 7, 3, 3, 3, 7, 5, 7, 2, 0, 2, 0, 2, 0, 6, 6, 1, 1, 1, 1,
       4, 3, 0, 5, 0, 6, 1, 3, 3, 3, 7, 5, 7, 2, 0, 2, 2, 0, 5, 0, 2, 0, 5, 0,
       6, 1, 3, 7, 3, 3, 3, 7, 5, 7, 2, 0, 2, 0, 2, 0]

HEX_BYTES = frozenset(b"0123456789abcdef")
HEX64_RE = re.compile(r"[0-9a-f]{64}")

REAL_DIGEST = "61052e74ac13cb864ce5331005cdc65836d3c6f1532abf520ae52fa200ecee30"


def rolk(b, k):
    k %= 8
    return ((b << k) | (b >> (8 - k))) & 0xff if k else b


def rork(b, k):
    k %= 8
    return ((b >> k) | (b << (8 - k))) & 0xff if k else b


def sha_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


KNOWN_DIGESTS = {
    "base.bin": sha_hex("Segoe UI:Windows"),
    "s1.bin": sha_hex("Segoe UI:Windows"),
    "s2.bin": sha_hex("Tahoma:Windows"),
    "s3.bin": sha_hex("Helvetica Neue"),
    "s4.bin": sha_hex("Segoe UI:Windows"),
    "s5.bin": sha_hex("Segoe UI:Windows"),
    "s6.bin": sha_hex("Segoe UI:Windows"),
    "s7.bin": sha_hex("zzzfont"),
    "real_input.bin": REAL_DIGEST,
}


def cands_from_digest(zone, digest):
    """Per position: rotations r with rol_r(digest[i]) == zone[i]."""
    return [[r for r in range(8) if rolk(digest[i], r) == zone[i]]
            for i in range(64)]


def cands_hexonly(zone):
    """Per position: rotations r with ror_r(zone[i]) being an ASCII hex char."""
    return [[r for r in range(8) if rork(zone[i], r) in HEX_BYTES]
            for i in range(64)]


def scan_offsets(buf):
    """Weak hex-only scan: offsets where some per-byte rotation yields hex.
    Note: ±1/±2 shifted windows of a hex string also pass this (r=0), so it
    is only informational; verification below is the real discriminator."""
    ok = []
    for off in range(50, min(71, len(buf) - 63)):
        c = cands_hexonly(buf[off:off + 64])
        if all(c):
            ok.append(off)
    return ok


def derot(zone, ks):
    return bytes(rork(zone[i], ks[i]) for i in range(64))


def verified_offsets(buf, digest_hex):
    """Offsets that survive strict verification:
    - known digest: every position has a rotation of digest[i] hitting zone[i];
    - unknown digest: de-rotation with one of the given keystreams (OLD/NEW)
      yields all ASCII-hex."""
    full = []
    for off in range(50, min(71, len(buf) - 63)):
        zone = buf[off:off + 64]
        if digest_hex:
            if all(cands_from_digest(zone, digest_hex.encode())):
                full.append(off)
    return full


def pick_offset(name, hexoffs, veroffs):
    prefer = 63 if name == "real_input.bin" else 55
    if prefer in veroffs:
        return prefer, "documented+verified"
    if len(veroffs) == 1:
        return veroffs[0], "unique-verified"
    if veroffs:
        return veroffs[0], "first-verified-of-%s" % veroffs
    return (hexoffs[0] if hexoffs else None), "UNVERIFIED hexonly=%s" % hexoffs


def family_solve(buffers, prefer=63):
    """Joint solve for same-env fixture family with unknown digests.

    At offset `off`, position i: candidate rotations per fixture are
    {r : ror_r(zone[i]) is ASCII-hex}; the true shared k[i] must lie in the
    intersection across ALL fixtures. An offset is solvable if no position's
    intersection is empty. Returns (chosen_offset, all_solvable_offsets,
    ks-or-None, digests-or-None). Ambiguity ('3'/'f' bytes) collapses because
    different digests see the same k with different zone bytes."""
    solvable = {}
    for off in range(50, min(71, 127)):
        per_pos = []
        ok = True
        for i in range(64):
            inter = set(range(8))
            for buf in buffers:
                inter &= {r for r in range(8) if rork(buf[off + i], r) in HEX_BYTES}
            if not inter:
                ok = False
                break
            per_pos.append(sorted(inter))
        if ok:
            solvable[off] = per_pos
    if not solvable:
        return None, [], None, None
    off = prefer if prefer in solvable else sorted(solvable)[0]
    per_pos = solvable[off]
    ks = [s[0] if len(s) == 1 else None for s in per_pos]
    digests = None
    if all(k is not None for k in ks):
        digests = [bytes(rork(buf[off + i], ks[i]) for i in range(64)).decode()
                   for buf in buffers]
    return off, sorted(solvable), ks, digests


def fmt_ks(cands):
    out = []
    for c in cands:
        if len(c) == 1:
            out.append(str(c[0]))
        else:
            out.append("/".join(str(x) for x in c) + "*")
    return " ".join(out)


def rol_zone(digest, ks):
    return bytes(rolk(digest[i], ks[i]) for i in range(64))


def matches_ks(zone, digest, ks):
    return rol_zone(digest, ks) == zone


# ---------------------------------------------------------------- protobuf

def read_varint(buf, pos):
    val = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("varint EOF")
        b = buf[pos]
        pos += 1
        val |= (b & 0x7f) << shift
        if not b & 0x80:
            return val, pos
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")


def try_parse(buf):
    """Parse protobuf wire format; None if not a valid message."""
    fields = []
    pos = 0
    try:
        while pos < len(buf):
            tag, pos = read_varint(buf, pos)
            fnum, wt = tag >> 3, tag & 7
            if not 1 <= fnum <= 100000:
                return None
            if wt == 0:
                v, pos = read_varint(buf, pos)
                fields.append((fnum, 0, v))
            elif wt == 1:
                if pos + 8 > len(buf):
                    return None
                fields.append((fnum, 1, bytes(buf[pos:pos + 8])))
                pos += 8
            elif wt == 2:
                ln, pos = read_varint(buf, pos)
                if pos + ln > len(buf):
                    return None
                fields.append((fnum, 2, bytes(buf[pos:pos + ln])))
                pos += ln
            elif wt == 5:
                if pos + 4 > len(buf):
                    return None
                fields.append((fnum, 5, bytes(buf[pos:pos + 4])))
                pos += 4
            else:
                return None  # groups (3,4) unsupported
    except ValueError:
        return None
    return fields


def as_text(v):
    try:
        t = v.decode("ascii")
    except UnicodeDecodeError:
        return None
    return t if all(31 < ord(ch) < 127 for ch in t) else None


def fmt_val(wt, v):
    if wt == 0:
        return str(v)
    if wt in (1, 5):
        return v.hex() + " (LE u64=%d)" % int.from_bytes(v, "little") if wt == 1 else v.hex()
    t = as_text(v)
    if t is not None and t:
        return repr(t)
    return v.hex()


def dump_fields(buf, path, depth, lines):
    fields = try_parse(buf)
    if fields is None:
        lines.append("%s<not a message: %s>" % ("  " * depth, fmt_val(2, buf)))
        return
    for fnum, wt, v in fields:
        p = "%s.%d" % (path, fnum) if path else "f%d" % fnum
        if wt == 2 and v and depth < 6:
            t = as_text(v)
            sub = try_parse(v)
            if t is None and sub is not None:
                lines.append("%s%s (len=%d, message):" % ("  " * depth, p, len(v)))
                dump_fields(v, p, depth + 1, lines)
                continue
        lines.append("%s%s wt%d: %s" % ("  " * depth, p, wt, fmt_val(wt, v)))


def flat_walk(buf, path, out):
    fields = try_parse(buf)
    if fields is None:
        return
    for fnum, wt, v in fields:
        p = "%s.%d" % (path, fnum) if path else "f%d" % fnum
        out.append((p, wt, v))
        if wt == 2:
            t = as_text(v)
            if t is None and v:
                flat_walk(v, p, out)


def proto_report(fname):
    buf = open(os.path.join(FIX, fname), "rb").read()
    print("=" * 78)
    print("PROTO: %s (%d bytes)" % (fname, len(buf)))
    lines = []
    dump_fields(buf, "", 0, lines)
    for ln in lines:
        print(ln)
    flat = []
    flat_walk(buf, "", flat)
    hits = []
    for p, wt, v in flat:
        if wt == 2:
            t = as_text(v) or ""
            m = HEX64_RE.search(t)
            if m:
                hits.append("  hex64 in %s: %s" % (p, m.group(0)))
        elif wt == 0 and v in (50, 100, 200):
            hits.append("  varint %s = %d  (rtt candidate)" % (p, v))
    print("  interesting:")
    for h in hits or ["    (none)"]:
        print(h)


# ---------------------------------------------------------------- main

def main():
    names = (["base.bin"] + ["s%d.bin" % i for i in range(1, 8)]
             + ["digest%d.bin" % i for i in range(5)] + ["real_input.bin"])
    buffers = {n: open(os.path.join(FIX, n), "rb").read() for n in names}

    # Pass 1: hexonly scan + digest-verified offsets (known digests only).
    hexoffs, digver = {}, {}
    for name in names:
        buf = buffers[name]
        hexoffs[name] = scan_offsets(buf)
        digver[name] = (verified_offsets(buf, KNOWN_DIGESTS[name])
                        if name in KNOWN_DIGESTS else [])

    # NEW keystream from real_input.bin (known digest -> no ks needed first).
    roff, _ = pick_offset("real_input.bin", hexoffs["real_input.bin"],
                          digver["real_input.bin"])
    rzone = buffers["real_input.bin"][roff:roff + 64]
    newks = [c[0] for c in cands_from_digest(rzone, REAL_DIGEST.encode())]

    # Joint solve of the digest0-4 family (same env, unknown digests).
    fambufs = [buffers["digest%d.bin" % i] for i in range(5)]
    famoff, famsolvable, famks, famdigests = family_solve(fambufs)

    # Pass 2: offsets for unknown-digest fixtures verified via OLD/NEW or family.
    print("=" * 78)
    print("SECTION 1: offset scan (50..70)")
    results = {}
    for name in names:
        buf = buffers[name]
        if name.startswith("digest"):
            idx = int(name[6])
            off = famoff
            how = "family-joint-solve (solvable offsets: %s)" % famsolvable
        else:
            ver = digver[name]
            off, how = pick_offset(name, hexoffs[name], ver)
        results[name] = (buf, off)
        print("  %-16s len=%4d hexonly=%s -> %s (%s)"
              % (name, len(buf), hexoffs[name], off, how))

    print("=" * 78)
    print("SECTION 2: base.bin extraction vs OLD keystream")
    buf, off = results["base.bin"]
    digest_hex = KNOWN_DIGESTS["base.bin"]
    zone = buf[off:off + 64]
    cands = cands_from_digest(zone, digest_hex.encode())
    bad = [i for i, c in enumerate(cands) if not c]
    amb = [i for i, c in enumerate(cands) if len(c) > 1]
    ok_old = all(OLD[i] in c for i, c in enumerate(cands))
    print("  offset=%d  impossible positions=%s  ambiguous(%s-class)=%s"
          % (off, bad, "'3'/'f' bytes: {k,k+4}", amb))
    print("  OLD keystream consistent with base.bin zone: %s" % ok_old)
    print("  OLD matches:", "YES" if ok_old and not bad else "NO")

    print("=" * 78)
    print("SECTION 3: per-fixture digests + keystream equality")
    summary = {}
    for name in names:
        buf, off = results[name]
        zone = buf[off:off + 64]
        if name in KNOWN_DIGESTS:
            dhex = KNOWN_DIGESTS[name]
            src = "known"
        elif name.startswith("digest") and famdigests is not None:
            dhex = famdigests[int(name[6])]
            src = "family joint-solve @%d, all [0-9a-f] OK" % famoff
        else:
            dhex = None
            src = "RECOVERY FAILED"
        line = "  %-16s off=%2d  %s" % (name, off, src)
        if dhex is None:
            print(line + "  digest=???")
            summary[name] = None
            continue
        d = dhex.encode()
        cands = cands_from_digest(zone, d)
        eq_old = matches_ks(zone, d, OLD)
        eq_new = matches_ks(zone, d, newks)
        eq_fam = matches_ks(zone, d, famks) if famks else False
        amb = [i for i, c in enumerate(cands) if len(c) > 1]
        if name == "real_input.bin":
            tag = "== NEW (real env)"
        elif eq_old:
            tag = "== OLD"
        elif eq_new or eq_fam:
            tag = "== NEW (real env)"
        else:
            tag = "DIFFERENT"
        print(line)
        print("      digest: %s" % dhex)
        print("      ks vs digest: %s   %s" % (fmt_ks(cands), tag))
        summary[name] = (dhex, eq_old, eq_new, eq_fam, amb)

    print("=" * 78)
    print("SECTION 4: FINAL NEW keystream (real env family, offset %d)" % famoff)
    d = REAL_DIGEST.encode()
    zone = rzone
    rcands = cands_from_digest(zone, d)
    resolved = all(famks[i] in rcands[i] for i in range(64))
    exact = matches_ks(zone, d, famks)
    naive_amb = [i for i, c in enumerate(rcands) if len(c) > 1]
    print("  family joint-solve ks (all 64 values, fully resolved):")
    print("  NEW = %s" % famks)
    print("  python list: k = %s" % famks)
    print("  consistent with real_input.bin per-position candidates: %s" % resolved)
    print("  re-encrypts real digest -> real_input zone byte-exact: %s" % exact)
    print("  positions where real_input alone was ambiguous ('3'/'f', {k,k+4}): %s"
          % [(i, chr(d[i]), sorted(rcands[i])) for i in naive_amb])
    print("  all resolved by the digest0-4 joint solve (digest4 == real digest):")
    for i in naive_amb:
        print("    idx %2d: naive=%s  final=%d" % (i, sorted(rcands[i]), famks[i]))
    print("  digest bytes: %s" % REAL_DIGEST)

    print("=" * 78)
    print("SECTION 5: which fixture shares which keystream")
    groups = {}
    for name, s in summary.items():
        if s is None:
            groups.setdefault("UNRESOLVED", []).append(name)
            continue
        _, eq_old, eq_new, eq_fam, _ = s
        if eq_old and (eq_new or eq_fam):
            key = "== OLD and == NEW (identical)"
        elif eq_old:
            key = "== OLD"
        elif eq_new or eq_fam:
            key = "== NEW (real env)"
        else:
            key = "DIFFERENT"
        groups.setdefault(key, []).append(name)
    for key, ns in sorted(groups.items()):
        print("  %s: %s" % (key, ", ".join(ns)))

    for fname in ("real_sig92.proto.bin", "real_sig86.proto.bin"):
        proto_report(fname)


if __name__ == "__main__":
    main()
