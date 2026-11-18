#!/usr/bin/env python3
"""Build a minimal wasm module embedding the EXACT HH bodies (func141 update
packet, func169 zipper, func114 streaming update, func121 finalize) extracted
from core.wasm, so JS can call them directly as an oracle."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\seated-vm\out\spy")
from patch_spy import read_uleb, uleb, sleb
import re

SRC = r"C:\Users\Administrator\Desktop\seated-vm\wasm\core.wasm"
DST = r"C:\Users\Administrator\Desktop\seated-vm\out\spy\hh_oracle.wasm"

blob = open(SRC, "rb").read()
pos = 8
secs = {}
while pos < len(blob):
    sid = blob[pos]; pos += 1
    size, pos = read_uleb(blob, pos)
    secs.setdefault(sid, []).append((pos, size))
    pos += size

# code section: get bodies for funcs 114, 121, 141, 169 (indices: 114-79=35, 121-79=42, 141-79=62, 169-79=90)
p, size = secs[10][0]
payload = blob[p:p + size]
count, o = read_uleb(payload, 0)
content = p + o
bodies = {}
cur = content
for i in range(count):
    sz, o2 = read_uleb(payload, o)
    if i in (35, 42, 62, 90):
        bodies[i] = bytearray(payload[o2:o2 + sz])
    cur += len(uleb(sz)) + sz
    o = o2 + sz

# types in ORIGINAL module: t1=(i32,i32)->nil; t4=(i32,i32,i32)->nil; t26=(i64,i64,i32,i32,i32)->nil
# new module types: 0=(i32,i32)->nil  1=(i32,i32,i32)->nil  2=(i64,i64,i32,i32,i32)->nil
types = (uleb(3) + b"\x60" + uleb(2) + b"\x7f\x7f" + b"\x00"
         + b"\x60" + uleb(3) + b"\x7f\x7f\x7f" + b"\x00"
         + b"\x60" + uleb(5) + b"\x7e\x7e\x7f\x7f\x7f" + b"\x00")

def relocate(body, old_call, new_call):
    out = bytearray(body)
    pat = b"\x10" + uleb(old_call)
    rep = b"\x10" + uleb(new_call)
    n = 0
    i = 0
    while True:
        i = out.find(pat, i)
        if i < 0:
            break
        out[i:i + len(pat)] = rep
        n += 1
        i += len(rep)
    return out, n

# funcs: 0=old141(type0) 1=old169(type2) 2=old114(type1) 3=old121(type0)
f141, n1 = relocate(bodies[62], 169, 1)
f114, n2 = relocate(bodies[35], 141, 0)
f121, n3 = relocate(bodies[42], 141, 0)
f169 = bodies[90]
assert n1 == 4 and n2 >= 1 and n3 >= 1, (n1, n2, n3)
# func114 may call other funcs? check remaining calls to >= 79
for name, b in (("f114", f114), ("f141", f141), ("f121", f121)):
    for m in re.finditer(b"\x10.", bytes(b), flags=0):
        pass
print("relocated calls:", n1, n2, n3)

function_sec = uleb(4) + bytes([0, 2, 1, 0])
memory_sec = uleb(1) + b"\x00\x02"     # 2 pages
global_sec = uleb(1) + b"\x7f\x01" + b"\x41" + sleb(65504) + b"\x0b"   # global0 = mutable i32 stack ptr
exports = (uleb(3) + uleb(6) + b"memory" + b"\x02\x00"
           + uleb(6) + b"update" + b"\x00\x02"
           + uleb(3) + b"fin" + b"\x00\x03")

def sec(sid, payload):
    return bytes([sid]) + uleb(len(payload)) + payload

code = uleb(4)
for b in (f141, f169, f114, f121):
    code += uleb(len(b)) + bytes(b)

mod = (b"\x00asm\x01\x00\x00\x00"
       + sec(1, types)
       + sec(3, function_sec)
       + sec(5, memory_sec)
       + sec(6, global_sec)
       + sec(7, exports)
       + sec(10, code))
open(DST, "wb").write(mod)
print("wrote", DST, len(mod), "bytes")
