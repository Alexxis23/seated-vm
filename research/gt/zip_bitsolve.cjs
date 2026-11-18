// Bit-level solve of the zipper: per output bit, find contributing input bits.
const fs = require('fs');
const m = new WebAssembly.Instance(new WebAssembly.Module(fs.readFileSync(__dirname + '/../spy/hh_oracle.wasm')));
const { memory, update } = m.exports;
const dv = new DataView(memory.buffer);
const init = [0xdbe6d5d5fe4cce2fn, 0xa4093822299f31d0n, 0x13198a2e03707344n, 0x243f6a8885a308d3n,
              0x3bd39e10cb0ef593n, 0xc0acf169b5f18a8cn, 0xbe5466cf34e90c6cn, 0x452821e638d01377n,
              0xdbe6d5d5fe4cce2fn, 0xa4093822299f31d0n, 0x13198a2e03707344n, 0x243f6a8885a308d3n,
              0x3bd39e10cb0ef593n, 0xc0acf169b5f18a8cn, 0xbe5466cf34e90c6cn, 0x452821e638d01377n];
const M = (1n << 64n) - 1n;
let seed = 0x123456789abcdefn;
const rnd = () => { seed = (seed * 6364136223846793005n + 1442695040888963407n) & M; return seed; };

const samples = [];
for (let t = 0; t < 24; t++) {
  const p = [rnd(), rnd(), rnd(), rnd()];
  init.forEach((v, i) => dv.setBigUint64(4096 + 8 * i, v, true));
  for (let i = 16; i < 22; i++) dv.setBigUint64(4096 + 8 * i, 0n, true);
  const buf = Buffer.alloc(32);
  for (let j = 0; j < 4; j++) buf.writeBigUInt64LE(p[j], 8 * j);
  new Uint8Array(memory.buffer).set(buf, 8192);
  update(4096, 8192, 32);
  const st = [];
  for (let i = 0; i < 16; i++) st.push(dv.getBigUint64(4096 + 8 * i, true));

  let v0 = init.slice(0, 4), v1 = init.slice(4, 8), mul0 = init.slice(8, 12), mul1 = init.slice(12, 16);
  for (let j = 0; j < 4; j++) v1[j] = (v1[j] + p[j] + mul0[j]) & M;
  for (let j = 0; j < 4; j++) mul0[j] ^= ((v0[j] >> 32n) * (v1[j] & 0xFFFFFFFFn)) & M;
  for (let j = 0; j < 4; j++) v0[j] = (v0[j] + mul1[j]) & M;
  for (let j = 0; j < 4; j++) mul1[j] ^= ((v1[j] >> 32n) * (v0[j] & 0xFFFFFFFFn)) & M;

  // zipper group 1: (a,b) = (v1[1], v1[0]); outputs land in v0[1] (z1), v0[0] (z2)
  samples.push({
    a: v1[1], b: v1[0],
    z1: (st[1] - v0[1]) & M, z2: (st[0] - v0[0]) & M,
  });
  samples.push({ a: v1[3], b: v1[2], z1: (st[3] - v0[3]) & M, z2: (st[2] - v0[2]) & M });
  samples.push({ a: v0[1], b: v0[0], z1: (st[5] - v1[1]) & M, z2: (st[4] - v1[0]) & M });
  samples.push({ a: v0[3], b: v0[2], z1: (st[7] - v1[3]) & M, z2: (st[6] - v1[2]) & M });
}

// bit-level solve: for each z bit, find whether it equals a single input bit,
// or the OR of two input bits (a_i | b_j), tested over all samples.
const bit = (x, i) => (BigInt(x) >> BigInt(Number(i))) & 1n;
function solveBit(key, pos) {
  // single source
  for (let src = 0; src < 16; src++) {
    const fromA = true;
    for (const which of ['a', 'b']) {
      let ok = true;
      for (const s of samples) {
        const v = which === 'a' ? s.a : s.b;
        if (bit(v, src) !== bit(s[key], pos)) { ok = false; break; }
      }
      if (ok) return `${which}${src}`;
    }
  }
  // OR of two (a_i, b_j) and (a_i, a_j)/(b_i, b_j)
  const names = [];
  for (let i = 0; i < 8; i++) names.push(['a', i]);
  for (let i = 0; i < 8; i++) names.push(['b', i]);
  for (let x = 0; x < names.length; x++) {
    for (let y = x + 1; y < names.length; y++) {
      let ok = true;
      for (const s of samples) {
        const va = s.a, vb = s.b;
        const bx = names[x][0] === 'a' ? bit(va, names[x][1]) : bit(vb, names[x][1]);
        const by = names[y][0] === 'a' ? bit(va, names[y][1]) : bit(vb, names[y][1]);
        if ((bx | by) !== bit(s[key], pos)) { ok = false; break; }
      }
      if (ok) return `${names[y][0]}${names[y][1]}|${names[x][0]}${names[x][1]}`;
    }
  }
  return null;
}

for (const key of ['z1', 'z2']) {
  console.log(`== ${key} ==`);
  for (let pos = 0; pos < 64; pos++) {
    const r = solveBit(key, pos);
    if (r === null) { console.log(`  ${key} bit ${pos}: UNSOLVED`); }
    else if (pos % 8 === 0) process.stdout.write(`  ${key} bits ${pos}..${pos + 7}:\n`);
  }
}
// print per-byte summary compactly
for (const key of ['z1', 'z2']) {
  const rows = [];
  for (let pos = 0; pos < 64; pos += 8) {
    const parts = [];
    for (let b = 0; b < 8; b++) {
      parts.push(solveBit(key, pos + b) || '?');
    }
    rows.push(parts.join(' | '));
  }
  console.log(`-- ${key} per-byte (bit0..bit7 of each byte) --`);
  rows.forEach((r, i) => console.log(`  byte${i} (bits ${i*8}..${i*8+7}): ${r}`));
}
