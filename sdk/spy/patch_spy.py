#!/usr/bin/env python3
"""Patch core.wasm so every call to SipHash-2-4 (func[119]) goes through a spy
wrapper func[320] that records (k0, k1, ptr, end, len, data) into a scratch
region at the top of linear memory, then calls the original.

Scratch layout (SCR = 0x10FC00, memory = 17 pages = 0x110000):
  SCR+0            : u32 record count
  SCR+4 + i*96     : record i
      +0  i64 k0
      +8  i64 k1
      +16 i32 ptr
      +20 i32 end
      +24 i32 n (bytes copied, cap 63)
      +28 [63]u8 data copy

Also keeps the original HH-input spy (call 114 -> import 68 at 0x1da4b).
"""
import sys, os

SRC = r"C:\Users\Administrator\Desktop\seated-vm\wasm\core.wasm"
DST = r"C:\Users\Administrator\Desktop\seated-vm\out\spy\core_spy.wasm"

SCR = int(os.environ.get("SPY_SCR", "1113088"))   # 0x10FC00 default
MODE = os.environ.get("SPY_MODE", "full")         # full | nostore | pass

# All 14 call sites of func 119 in the file (verified `10 77` at each).
CALL_SITES = [0x00792c, 0x007b6a, 0x0084cb, 0x0086fc, 0x008aa6, 0x008ce8,
              0x00ccbb, 0x00ce88, 0x00d0c6, 0x01951c, 0x01a8b6, 0x01d00e,
              0x01e458, 0x01f630]
FUNC_119 = 119
NEW_FUNC_IDX = 320       # 79 imports + 241 defined funcs -> appended index 320

# func114 call sites -> spy func321 (both stage1 0x1da4b and stage2 0x1dd6f)
CALL_SITES_114 = [0x01da4b, 0x01dd6f]
FUNC_114 = 114
NEW_FUNC_IDX2 = 321


def spy114_body():
    """func[321] (sig 4): log state (pre), data, then call func114, log state (post)."""
    p = bytearray()
    P0, P1, P2 = b"\x20\x00", b"\x20\x01", b"\x20\x02"
    MAGIC_S = i32c(int(os.environ.get("SPY_MAGIC_S", "123456790")))
    MAGIC_D = i32c(int(os.environ.get("SPY_MAGIC_D", "123456791")))
    p += b"\x00"                                  # no locals
    p += P0 + i32c(0) + MAGIC_S + b"\x10\x44"     # (state, 0, MAGIC_S)  -> pre-state
    p += P1 + P2 + MAGIC_D + b"\x10\x44"          # (ptr, len, MAGIC_D)
    p += P0 + P1 + P2 + b"\x10" + uleb(FUNC_114)  # call 114
    p += P0 + i32c(1) + MAGIC_S + b"\x10\x44"     # (state, 1, MAGIC_S)  -> post-state
    p += b"\x0b"
    return bytes(p)


def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not (b & 0x40)) or (n == -1 and (b & 0x40)):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def i32c(v):
    return b"\x41" + sleb(v)


def spy_body():
    """func[320]: log (k0,k1,ptr,end) to JS via import 68 (two calls), then
    tail-call original func[119] and return its result. No memory writes."""
    p = bytearray()
    P0, P1, P2, P3 = b"\x20\x00", b"\x20\x01", b"\x20\x02", b"\x20\x03"
    MAGIC = int(os.environ.get("SPY_MAGIC", "123456789"))
    M = i32c(MAGIC)
    p += b"\x00"                                  # no locals
    # call1: (k0.lo, k0.hi, MAGIC)
    p += P0 + b"\xa7"                             # i32.wrap_i64 k0
    p += P0 + b"\x42\x20\x88" + b"\xa7"           # (k0 >> 32) wrap
    p += M + b"\x10\x44"                          # MAGIC, call 68 (sig (i32,i32,i32)->nil)
    # call2: (k1.lo, k1.hi, MAGIC)
    p += P1 + b"\xa7"
    p += P1 + b"\x42\x20\x88" + b"\xa7"
    p += M + b"\x10\x44"
    # call3: (ptr, end, MAGIC)
    p += P2 + P3 + M + b"\x10\x44"
    # tail: call original 119
    p += P0 + P1 + P2 + P3 + b"\x10" + uleb(FUNC_119)
    p += b"\x0b"
    return bytes(p)


def read_uleb(buf, o):
    v, n = 0, 0
    while True:
        b = buf[o]; o += 1
        v |= (b & 0x7F) << (7 * n); n += 1
        if not (b & 0x80):
            return v, o


def main():
    blob = bytearray(open(SRC, "rb").read())
    # Force stage2 to run: at 0x1da7e replace `br_if 4` (0d 04) with drop;nop (1a 01)
    # so the second HH update (which hashes payload-prefix || extra string) always executes.
    assert blob[0x1da75:0x1da80] == bytes([0x20, 0x0f, 0x41, 0x80, 0x80, 0x80, 0x80, 0x78, 0x46, 0x0d, 0x04]), \
        "unexpected bytes at 0x1da75: " + blob[0x1da75:0x1da80].hex(" ")
    blob[0x1da7e] = 0x1A
    blob[0x1da7f] = 0x01
    blob = bytes(blob)
    for off in CALL_SITES:
        assert blob[off] == 0x10 and blob[off + 1] == 0x77, hex(off)

    pos = 8
    sections = []  # (id, payload_abs, size)
    while pos < len(blob):
        sid = blob[pos]; pos += 1
        size, pos = read_uleb(blob, pos)
        sections.append((sid, pos, size))
        pos += size

    out = bytearray(blob[:8])
    for sid, pabs, size in sections:
        payload = blob[pabs:pabs + size]
        if sid == 3:  # Function section
            count, o = read_uleb(payload, 0)
            assert count == 241, count
            new = uleb(count + 2) + payload[o:] + bytes([21, 4])   # spy119: sig21, spy114: sig4
            out += bytes([sid]) + uleb(len(new)) + new
        elif sid == 10:  # Code section
            count, o = read_uleb(payload, 0)
            assert count == 241, count
            content_abs = pabs + o          # file offset of first body's size LEB
            # pass 1: compute body content offsets
            ranges = []
            o = content_abs - pabs
            cur = content_abs
            for i in range(count):
                sz, o2 = read_uleb(payload, o)
                ranges.append((cur + (o2 - o), sz))     # (file offset of content, size)
                o = o2 + sz
                cur += len(uleb(sz)) + sz
            assert o == len(payload)
            # pass 2: assign each call site to its unique body
            site_w = {}   # body index -> list of (within offset, new func idx)
            for off, target in [(o, NEW_FUNC_IDX) for o in CALL_SITES] + \
                               [(o, NEW_FUNC_IDX2) for o in CALL_SITES_114]:
                owners = [i for i, (a, s) in enumerate(ranges) if a <= off < a + s]
                assert len(owners) == 1, (hex(off), owners)
                i = owners[0]
                w = off - ranges[i][0]
                body = payload[ranges[i][0] - pabs: ranges[i][0] - pabs + ranges[i][1]]
                expect = 0x77 if target == NEW_FUNC_IDX else FUNC_114
                assert body[w] == 0x10 and body[w + 1] == expect, (hex(off), hex(ranges[i][0] + w))
                site_w.setdefault(i, []).append((w, target))
            assert sum(len(v) for v in site_w.values()) == len(CALL_SITES) + len(CALL_SITES_114)
            # pass 3: rebuild bodies with patches (descending offsets!)
            new_bodies = []
            for i in range(count):
                a, sz = ranges[i]
                body = bytearray(payload[a - pabs: a - pabs + sz])
                for w, target in sorted(site_w.get(i, []), reverse=True):
                    body[w:w + 2] = b"\x10" + uleb(target)
                new_bodies.append(uleb(len(body)) + bytes(body))
            sb = spy_body()
            sb2 = spy114_body()
            new_payload = uleb(count + 2) + b"".join(new_bodies)
            new_payload += uleb(len(sb)) + sb
            new_payload += uleb(len(sb2)) + sb2
            out += bytes([sid]) + uleb(len(new_payload)) + new_payload
        else:
            out += bytes([sid]) + uleb(len(payload)) + payload

    open(DST, "wb").write(bytes(out))
    print(f"wrote {DST} ({len(out)} bytes)")
    chk = open(DST, "rb").read()
    pat = b"\x10" + uleb(NEW_FUNC_IDX)
    print(f"call {NEW_FUNC_IDX} occurrences: {chk.count(pat)} (expect 14)")
    print(f"call 119 occurrences: {chk.count(bytes([0x10, 0x77]))} (expect >=1: the spy's tail call)")


if __name__ == "__main__":
    main()
