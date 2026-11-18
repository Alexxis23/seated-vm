import sys, hashlib
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import os
h = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")

M = (1 << 64) - 1
MASK32 = 0xffffffff
init0 = [0xdbe6d5d5fe4cce2f, 0xa4093822299f31d0, 0x13198a2e03707344, 0x243f6a8885a308d3]
init1 = [0x3bd39e10cb0ef593, 0xc0acf169b5f18a8c, 0xbe5466cf34e90c6c, 0x452821e638d01377]

def hh_init():
    st = [0]*16
    st[8:12] = init0[:]
    st[12:16] = init1[:]
    for i in range(4):
        st[i] = init0[i] ^ 0          # v0 = init0 ^ k
        st[4+i] = init1[i] ^ 0        # v1 = init1 ^ bswap(k) ; k=0
    return st

def le64(b): return int.from_bytes(b, 'little')

def zipper(val0, val1):
    res  = val0 & (0xff << 16)
    res2 = (val0 & (0xff << 56)) + (val1 & (0xff << 16))
    res += (val1 & (0xff << 56)) >> 8
    res2 += (val0 & (0xff << 48)) >> 8
    res += ((val0 & (0xff << 40)) + (val1 & (0xff << 48))) >> 16
    res2 += (val1 & (0xff << 40)) >> 16
    res += ((val0 & (0xff << 24)) + (val1 & (0xff << 32))) >> 24
    res2 += ((val1 & (0xff << 24)) + (val0 & (0xff << 32))) >> 24
    res += (val0 & (0xff << 8)) << 32
    res2 += (val1 & 0xff) << 48
    res += val0 << 56
    res2 += (val1 & (0xff << 8)) << 24
    return res & M, res2 & M

def hh_update_packet(st, m):
    st[4] = (st[4] + le64(m[0:8]) + st[8]) & M
    st[8] ^= (st[4] & MASK32) * (st[0] >> 32) & M
    st[0] = (st[0] + st[12]) & M
    st[12] ^= (st[0] & MASK32) * (st[4] >> 32) & M

    st[5] = (st[5] + le64(m[8:16]) + st[9]) & M
    st[9] ^= (st[5] & MASK32) * (st[1] >> 32) & M
    st[1] = (st[1] + st[13]) & M
    st[13] ^= (st[1] & MASK32) * (st[5] >> 32) & M

    st[6] = (st[6] + le64(m[16:24]) + st[10]) & M
    st[10] ^= (st[6] & MASK32) * (st[2] >> 32) & M
    st[2] = (st[2] + st[14]) & M
    st[14] ^= (st[2] & MASK32) * (st[6] >> 32) & M

    st[7] = (st[7] + le64(m[24:32]) + st[11]) & M
    st[11] ^= (st[7] & MASK32) * (st[3] >> 32) & M
    st[3] = (st[3] + st[15]) & M
    st[15] ^= (st[3] & MASK32) * (st[7] >> 32) & M

    r, r2 = zipper(st[4], st[5]); st[0] = (st[0] + r) & M; st[1] = (st[1] + r2) & M
    r, r2 = zipper(st[6], st[7]); st[2] = (st[2] + r) & M; st[3] = (st[3] + r2) & M
    r, r2 = zipper(st[0], st[1]); st[4] = (st[4] + r) & M; st[5] = (st[5] + r2) & M
    r, r2 = zipper(st[2], st[3]); st[6] = (st[6] + r) & M; st[7] = (st[7] + r2) & M

def hh_update(st, msg):
    i = 0
    while i + 32 <= len(msg):
        hh_update_packet(st, msg[i:i+32])
        i += 32

def rol(x, n): return ((x << n) | (x >> (64 - n))) & M
def sipround(v0, v1, v2, v3):
    v0 = (v0 + v1) & M; v1 = rol(v1, 13); v1 ^= v0; v0 = rol(v0, 32)
    v2 = (v2 + v3) & M; v3 = rol(v3, 16); v3 ^= v2
    v0 = (v0 + v3) & M; v3 = rol(v3, 21); v3 ^= v0
    v2 = (v2 + v1) & M; v1 = rol(v1, 17); v1 ^= v2; v2 = rol(v2, 32)
    return v0, v1, v2, v3

def siphash24(k0, k1, data):
    v0 = k0 ^ 0x736f6d6570736575
    v1 = k1 ^ 0x646f72616e646f6d
    v2 = k0 ^ 0x6c7967656e657261
    v3 = k1 ^ 0x7465646279746573
    ln = len(data)
    full = ln - (ln % 8)
    for i in range(0, full, 8):
        m = le64(data[i:i+8])
        v3 ^= m
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
        v0 ^= m
    tail = data[full:]
    m = (le64(tail.ljust(8, b'\0')) | ((ln & 0xff) << 56)) & M
    v3 ^= m
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0 ^= m
    v2 ^= 0xff
    for _ in range(4):
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    return (v0 ^ v1 ^ v2 ^ v3) & M

OLD = [5,0,6,1,3,7,3,3,3,7,5,7,2,0,2,0,2,0,6,6,1,1,1,1,4,3,0,5,0,6,1,3,3,3,7,5,7,2,0,2,2,0,5,0,2,0,5,0,6,1,3,7,3,3,3,7,5,7,2,0,2,0,2,0]
NEW = [5,0,6,1,3,7,3,3,3,7,3,2,2,0,2,0,0,1,0,2,0,0,6,6,1,1,1,1,4,3,0,5,0,6,1,3,3,3,7,3,2,2,0,2,0,0,1,0,2,0,0,6,6,2,1,4,6,7,3,6,6,7,2,4]

dg_old = hashlib.sha256(b"Segoe UI:Windows").hexdigest().encode()
dg_new = b"61052e74ac13cb864ce5331005cdc65836d3c6f1532abf520ae52fa200ecee30"

base = open(h + r"\base.bin","rb").read()
real = open(h + r"\real_input.bin","rb").read()

def plain_prefix_parts_old():
    return b"1.2.3" + b"Europe/Warsaw" + b"Chromium::Google Chrome" + b"Windows" + b"\x03\x00\x00\x00" + b"x86"
def plain_prefix_parts_new():
    return b"Europe/Warsaw" + b"Chromium::Google Chrome::Not:A-Brand" + b"Windows" + b"\x03\x00\x00\x00" + b"x86"

def attempt(name, prefix_bytes, dg, want):
    st = hh_init()
    hh_update(st, prefix_bytes)
    slots = {f"st[{i}],st[{i+1}]": (st[i], st[i+1]) for i in range(15)}
    for kn, (k0, k1) in slots.items():
        for dn, mk in {
            "blk": lambda i: dg[i*8:(i+1)*8],
            "blk+ctr": lambda i: dg[i*8:(i+1)*8] + bytes([i]),
            "whole": lambda i: dg,
            "sofar": lambda i: dg[:i*8],
        }.items():
            for endian in ("little", "big"):
                got = []
                for blk in range(8):
                    out = siphash24(k0, k1, mk(blk))
                    got.extend((b & 7) for b in out.to_bytes(8, endian))
                if got == want:
                    print(f"MATCH {name}: keys={kn} data={dn} out={endian}")
                    return True
    return False

print(attempt("OLD", base[:55], dg_old, OLD) or "OLD: no match")
print(attempt("NEW", real[:63], dg_new, NEW) or "NEW: no match")
# also try state absorbing PLAINTEXT prefix instead of obfuscated
print(attempt("OLD-plain", plain_prefix_parts_old(), dg_old, OLD) or "OLD-plain: no match")
print(attempt("NEW-plain", plain_prefix_parts_new(), dg_new, NEW) or "NEW-plain: no match")

