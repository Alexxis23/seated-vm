#!/usr/bin/env python3
"""Independent audit of the HH oracle (claim 3, faithfulness part).

1. Parse wasm/core.wasm and out/spy/hh_oracle.wasm code sections directly.
2. Fully decode the instruction streams of funcs 114/121/141/169 (proper
   opcode-level decode, no byte-grepping) and list every call target.
3. Re-apply the exact relocation used by out/spy/build_oracle.py to the
   original bodies and compare byte-for-byte with the oracle bodies.
4. Validate the oracle module's structure (types/funcs/memory/global/exports).
"""
import sys, re

sys.path.insert(0, r"C:\Users\Administrator\Desktop\seated-vm\out\spy")
from patch_spy import read_uleb, uleb, sleb

CORE = r"C:\Users\Administrator\Desktop\seated-vm\wasm\core.wasm"
ORACLE = r"C:\Users\Administrator\Desktop\seated-vm\out\spy\hh_oracle.wasm"


def sections(blob):
    pos = 8
    secs = {}
    while pos < len(blob):
        sid = blob[pos]; pos += 1
        size, pos = read_uleb(blob, pos)
        secs.setdefault(sid, []).append(blob[pos:pos + size])
        pos += size
    return secs


def code_bodies(payload):
    count, o = read_uleb(payload, 0)
    bodies = []
    for _ in range(count):
        sz, o = read_uleb(payload, o)
        bodies.append(payload[o:o + sz])
        o += sz
    assert o == len(payload)
    return count, bodies


def split_locals(body):
    n, o = read_uleb(body, 0)
    locals_ = []
    for _ in range(n):
        cnt, o = read_uleb(body, o)
        t = body[o]; o += 1
        locals_.append((cnt, t))
    return locals_, o


# ---- minimal but strict wasm instruction decoder -------------------------
def imm_memarg(b, o):
    _, o = read_uleb(b, o)  # align
    _, o = read_uleb(b, o)  # offset
    return o

def imm_u8(b, o):  return o + 1
def imm_f32(b, o): return o + 4
def imm_f64(b, o): return o + 8

def decode_calls(body, name):
    locals_, o = split_locals(body)
    depth = 1
    calls = []
    ci = []
    unknown = []
    end = len(body)
    while o < end:
        op = body[o]; o += 1
        if op == 0x10:
            t, o = read_uleb(body, o)
            calls.append(t)
        elif op == 0x11:
            t, o = read_uleb(body, o)
            ty, o = read_uleb(body, o)
            ci.append((t, ty))
        elif op in (0x00, 0x01, 0x05, 0x0F, 0x1A, 0x1B):
            pass
        elif op in (0x02, 0x03, 0x04, 0x06, 0x07):
            _, o = sleb_reader(body, o)      # blocktype (signed)
            depth += 1
        elif op == 0x0B:
            depth -= 1
            if depth == 0:
                break
        elif op == 0x0C or op == 0x0D:
            _, o = read_uleb(body, o)
        elif op == 0x0E:
            n, o = read_uleb(body, o)
            for _ in range(n + 1):
                _, o = read_uleb(body, o)
        elif op == 0x1C:
            n, o = read_uleb(body, o)
            o += n
        elif 0x20 <= op <= 0x26:
            _, o = read_uleb(body, o)
        elif 0x28 <= op <= 0x3E:
            o = imm_memarg(body, o)
        elif op in (0x3F, 0x40):
            o = imm_u8(body, o)
        elif op == 0x41:
            _, o = sleb_reader(body, o)
        elif op == 0x42:
            _, o = sleb_reader(body, o)
        elif op == 0x43:
            o = imm_f32(body, o)
        elif op == 0x44:
            o = imm_f64(body, o)
        elif 0x45 <= op <= 0xC4:
            pass
        elif op == 0xD0:
            _, o = sleb_reader(body, o)
        elif op == 0xD1:
            pass
        elif op == 0xD2:
            _, o = read_uleb(body, o)
        elif op == 0xFC:
            sub, o = read_uleb(body, o)
            if sub <= 7:
                pass
            elif sub == 8:      # memory.init
                _, o = read_uleb(body, o); o = imm_u8(body, o)
            elif sub == 9:      # data.drop
                _, o = read_uleb(body, o)
            elif sub == 10:     # memory.copy
                o = imm_u8(body, o); o = imm_u8(body, o)
            elif sub == 11:     # memory.fill
                o = imm_u8(body, o)
            elif sub == 12:     # table.init
                _, o = read_uleb(body, o); _, o = read_uleb(body, o)
            elif sub == 13:
                _, o = read_uleb(body, o)
            elif sub == 14:     # table.copy
                _, o = read_uleb(body, o); _, o = read_uleb(body, o); _, o = read_uleb(body, o)
            elif 15 <= sub <= 17:
                _, o = read_uleb(body, o)
            else:
                unknown.append(("FC", sub, o))
        elif op == 0xFD:
            sub, o = read_uleb(body, o)
            if 0 <= sub <= 11:      # v128 loads / store
                o = imm_memarg(body, o)
            elif sub == 12:         # v128.const
                o += 16
            elif sub == 13:         # i8x16.shuffle
                o += 16
            elif sub in (15,16,17,18,21,22,23,24,27,28,32,33,84,85,86,87,88,89,90,91,92,93):
                o = imm_u8(body, o)  # extract/replace lane
            elif sub in (14,19,20,25,26,29,30,31) or 34 <= sub <= 83 or 94 <= sub <= 175:
                pass
            else:
                unknown.append(("FD", sub, o))
        elif op == 0xFE:
            sub, o = read_uleb(body, o)
            unknown.append(("FE", sub, o))
        else:
            unknown.append((hex(op), None, o))
    if unknown:
        print(f"  !! {name}: UNKNOWN opcodes encountered: {unknown[:5]}")
    if o != end or depth != 0:
        print(f"  !! {name}: decode did not consume body cleanly (o={o}, end={end}, depth={depth})")
    return calls, ci


def sleb_reader(b, o):
    v, sh = 0, 0
    while True:
        c = b[o]; o += 1
        v |= (c & 0x7F) << sh
        sh += 7
        if not (c & 0x80):
            if c & 0x40 and sh < 64:
                v |= -(1 << sh)
            return v, o


def relocate(body, old_call, new_call):
    """EXACT copy of build_oracle.py's relocate()."""
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
    return bytes(out), n


def summarize(tag, calls, ci):
    from collections import Counter
    c = Counter(calls)
    parts = ", ".join(f"call {k} x{v}" for k, v in sorted(c.items())) or "(no calls)"
    if ci:
        parts += "; call_indirect: " + ", ".join(f"{t}/{y}" for t, y in ci)
    print(f"  {tag}: {parts}")


def main():
    core = open(CORE, "rb").read()
    orc = open(ORACLE, "rb").read()
    print(f"core.wasm: {len(core)} bytes   hh_oracle.wasm: {len(orc)} bytes")

    sc = sections(core)
    so = sections(orc)
    print("core sections:", {k: [len(x) for x in v] for k, v in sorted(sc.items())})
    print("oracle sections:", {k: [len(x) for x in v] for k, v in sorted(so.items())})
    assert 2 not in so, "oracle has import section?"
    assert 11 not in so and 9 not in so and 4 not in so and 8 not in so, "oracle has table/elem/data/start?"

    # types of oracle
    tp = so[1][0]
    n, o = read_uleb(tp, 0)
    print(f"oracle types: count={n}")
    for i in range(n):
        assert tp[o] == 0x60; o += 1
        np, o = read_uleb(tp, o)
        params = tp[o:o + np]; o += np
        nr, o = read_uleb(tp, o)
        rets = tp[o:o + nr]; o += nr
        print(f"  type {i}: params={[hex(x) for x in params]} rets={[hex(x) for x in rets]}")
    assert o == len(tp)

    # oracle function section
    fp = so[3][0]
    n, o = read_uleb(fp, 0)
    sigs = [fp[o + i] for i in range(n)]
    print(f"oracle funcs: count={n} type-ids={sigs}")
    assert n == 4 and sigs == [0, 2, 1, 0]

    # oracle global section
    gp = so[6][0]
    n, o = read_uleb(gp, 0)
    assert n == 1
    valtype, mut = gp[o], gp[o + 1]; o += 2
    op = gp[o]
    assert op == 0x41
    gval, o2 = sleb_reader(gp, o + 1)
    assert gp[o2] == 0x0B
    print(f"oracle global0: valtype={hex(valtype)} mut={mut} init=i32.const {gval}")
    assert valtype == 0x7F and mut == 1 and gval == 65504

    # oracle memory
    mp = so[5][0]
    n, o = read_uleb(mp, 0)
    flags = mp[o]
    lim = read_uleb(mp, o + 1)[0]
    print(f"oracle memory: count={n} flags={flags} min={lim}")
    assert flags == 0 and lim == 2

    # oracle exports
    ep = so[7][0]
    n, o = read_uleb(ep, 0)
    exps = {}
    for _ in range(n):
        l, o = read_uleb(ep, o)
        nm = ep[o:o + l].decode(); o += l
        kind = ep[o]; o += 1
        idx, o = read_uleb(ep, o)
        exps[nm] = (kind, idx)
    print(f"oracle exports: {exps}")
    assert exps == {"memory": (2, 0), "update": (0, 2), "fin": (0, 3)}

    # ---- bodies
    _, core_bodies = code_bodies(sc[10][0])
    n_orc, orc_bodies = code_bodies(so[10][0])
    assert n_orc == 4
    # core.wasm: 241 defined funcs, code idx = wasm idx - 79 (79 imports per wat)
    orig114, orig121, orig141, orig169 = (core_bodies[114 - 79], core_bodies[121 - 79],
                                          core_bodies[141 - 79], core_bodies[169 - 79])
    orF141, orF169, orF114, orF121 = orc_bodies

    print("\n-- decoded call targets (opcode-exact) --")
    for name, body in (("core f114", orig114), ("core f121", orig121),
                       ("core f141", orig141), ("core f169", orig169),
                       ("oracle f141(new0)", orF141), ("oracle f169(new1)", orF169),
                       ("oracle f114(new2)", orF114), ("oracle f121(new3)", orF121)):
        calls, ci = decode_calls(body, name)
        summarize(name, calls, ci)

    print("\n-- oracle faithfulness: relocate(originals) vs oracle bodies --")
    ok = True
    for tag, orig, old, new, orc_body in (
            ("f141: 169->1", orig141, 169, 1, orF141),
            ("f114: 141->0", orig114, 141, 0, orF114),
            ("f121: 141->0", orig121, 141, 0, orF121),
            ("f169: (no reloc)", orig169, None, None, orF169)):
        if old is None:
            match = bytes(orig) == bytes(orc_body)
            n = 0
            exp = bytes(orig)
        else:
            exp, n = relocate(orig, old, new)
            match = exp == bytes(orc_body)
        print(f"  {tag}: relocations={n}  byte-exact match={match}  len orig={len(orig)} oracle={len(orc_body)}")
        if not match or (old is not None and n == 0):
            ok = False
    print("\nRESULT:", "ORACLE FAITHFUL (bodies byte-exact modulo the two call-index relocations)" if ok else "MISMATCH")


if __name__ == "__main__":
    main()
