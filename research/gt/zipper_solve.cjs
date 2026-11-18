// Solve the zipper byte-mapping: craft packets, compare oracle zipper outputs
// against pre-zipper values computed from the (verified) non-zipper lanes.
const fs = require('fs');
const m = new WebAssembly.Instance(new WebAssembly.Module(fs.readFileSync(__dirname + '/../spy/hh_oracle.wasm')));
const { memory, update } = m.exports;
const dv = new DataView(memory.buffer);
const init = [0xdbe6d5d5fe4cce2fn, 0xa4093822299f31d0n, 0x13198a2e03707344n, 0x243f6a8885a308d3n,
              0x3bd39e10cb0ef593n, 0xc0acf169b5f18a8cn, 0xbe5466cf34e90c6cn, 0x452821e638d01377n,
              0xdbe6d5d5fe4cce2fn, 0xa4093822299f31d0n, 0x13198a2e03707344n, 0x243f6a8885a308d3n,
              0x3bd39e10cb0ef593n, 0xc0acf169b5f18a8cn, 0xbe5466cf34e90c6cn, 0x452821e638d01377n];
const M = (1n << 64n) - 1n;

// Run exactly one packet on the oracle, return the 16-lane state.
function onePacket(p) {
  init.forEach((v, i) => dv.setBigUint64(4096 + 8 * i, v, true));
  for (let i = 16; i < 22; i++) dv.setBigUint64(4096 + 8 * i, 0n, true);
  const buf = Buffer.alloc(32);
  for (let j = 0; j < 4; j++) buf.writeBigUInt64LE(p[j], 8 * j);
  new Uint8Array(memory.buffer).set(buf, 8192);
  update(4096, 8192, 32);
  const st = [];
  for (let i = 0; i < 16; i++) st.push(dv.getBigUint64(4096 + 8 * i, true));
  return st;
}

// scalar part (loops 1-5) — verified correct (mul0/mul1 match).
function scalar(v0, v1, mul0, mul1, p) {
  for (let j = 0; j < 4; j++) v1[j] = (v1[j] + p[j] + mul0[j]) & M;
  for (let j = 0; j < 4; j++) mul0[j] ^= ((v0[j] >> 32n) * (v1[j] & 0xFFFFFFFFn)) & M;
  for (let j = 0; j < 4; j++) v0[j] = (v0[j] + mul1[j]) & M;
  for (let j = 0; j < 4; j++) mul1[j] ^= ((v1[j] >> 32n) * (v0[j] & 0xFFFFFFFFn)) & M;
  return [v0, v1, mul0, mul1];
}

const samples = [];
let seed = 12345n;
const rnd = () => { seed = (seed * 6364136223846793005n + 1442695040888963407n) & M; return seed >> 16n; };
for (let t = 0; t < 8; t++) {
  const p = [rnd() & M, rnd() & M, rnd() & M, rnd() & M];
  const st = onePacket(p);
  let v0 = init.slice(0, 4), v1 = init.slice(4, 8), mul0 = init.slice(8, 12), mul1 = init.slice(12, 16);
  [v0, v1, mul0, mul1] = scalar(v0, v1, mul0, mul1, p);
  // deltas = zipper outputs applied by the wasm
  const dz0 = [0, 1, 2, 3].map(j => (st[j] - v0[j]) & M);
  const dz1 = [0, 1, 2, 3].map(j => (st[4 + j] - v1[j]) & M);
  // zipper group 1: (a, b) = (v1[1], v1[0]) -> adds to v0[1], v0[0]
  samples.push({ a: v1[1], b: v1[0], z1: dz0[1], z2: dz0[0], hi: false });
  samples.push({ a: v1[3], b: v1[2], z1: dz0[3], z2: dz0[2], hi: false });
  // zipper group 2: (a, b) = (v0[1], v0[0]) -> adds to v1[1], v1[0]
  samples.push({ a: v0[1], b: v0[0], z1: dz1[1], z2: dz1[0], hi: true });
  samples.push({ a: v0[3], b: v0[2], z1: dz1[3], z2: dz1[2], hi: true });
}

// solve per-byte source for z1 and z2: for each output byte position, test
// candidate source expressions against all samples.
const byteOf = (x, i) => (x >> BigInt(8 * i)) & 0xffn;
const cands = [];
for (let i = 0; i < 8; i++) cands.push({ name: `a${i}`, f: (s) => byteOf(s.a, i) });
for (let i = 0; i < 8; i++) cands.push({ name: `b${i}`, f: (s) => byteOf(s.b, i) });
for (let i = 0; i < 8; i++) cands.push({ name: `a${i}|b${i}`, f: (s) => byteOf(s.a, i) | byteOf(s.b, i) });
for (let i = 0; i < 8; i++) cands.push({ name: `a${i}+b${i}`, f: (s) => (byteOf(s.a, i) + byteOf(s.b, i)) & 0xffn });

for (const [zname, key] of [['z1', 'z1'], ['z2', 'z2']]) {
  console.log(`== ${zname} byte sources ==`);
  for (let pos = 0; pos < 8; pos++) {
    let solved = null;
    for (const c of cands) {
      let ok = true;
      for (const s of samples) {
        if (c.f(s) !== byteOf(s[key], pos)) { ok = false; break; }
      }
      if (ok) { solved = c.name; break; }
    }
    console.log(`  ${zname}[${pos}] = ${solved || '??? (no single-byte source)'}`);
  }
}
// dump one sample for reference
const s0 = samples[0];
console.log('sample a=%s b=%s z1=%s z2=%s', s0.a.toString(16), s0.b.toString(16), s0.z1.toString(16), s0.z2.toString(16));
