// Compare zipper deltas for the known [1,2,3,4] packet vs the solved mapping.
const fs = require('fs');
const m = new WebAssembly.Instance(new WebAssembly.Module(fs.readFileSync(__dirname + '/../spy/hh_oracle.wasm')));
const { memory, update } = m.exports;
const dv = new DataView(memory.buffer);
const init = [0xdbe6d5d5fe4cce2fn, 0xa4093822299f31d0n, 0x13198a2e03707344n, 0x243f6a8885a308d3n,
              0x3bd39e10cb0ef593n, 0xc0acf169b5f18a8cn, 0xbe5466cf34e90c6cn, 0x452821e638d01377n,
              0xdbe6d5d5fe4cce2fn, 0xa4093822299f31d0n, 0x13198a2e03707344n, 0x243f6a8885a308d3n,
              0x3bd39e10cb0ef593n, 0xc0acf169b5f18a8cn, 0xbe5466cf34e90c6cn, 0x452821e638d01377n];
const M = (1n << 64n) - 1n;
const p = [1n, 2n, 3n, 4n];
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

const byte = (x, i) => Number((x >> BigInt(8 * i)) & 0xffn);
const h = (x) => x.toString(16).padStart(16, '0');
const bytesLE = (x) => Array.from({ length: 8 }, (_, i) => byte(x, i));

// Group1: a = v1[1], b = v1[0] -> v0[1] (z1), v0[0] (z2)
const a = v1[1], b = v1[0];
console.log('a =', h(a), 'bytes LE:', bytesLE(a).join(' '));
console.log('b =', h(b), 'bytes LE:', bytesLE(b).join(' '));
const d0 = [0, 1, 2, 3].map(j => st[j] - ((v0[j]) % (1n << 64n)));
console.log('st[0..3]:', st.slice(0, 4).map(h).join(' '));
console.log('pre v0  :', v0.map(h).join(' '));
const dz0 = [0, 1, 2, 3].map(j => (st[j] - v0[j]) & M);
console.log('dz v0   :', dz0.map(h).join(' '));
console.log('dz v0[0] bytes LE:', bytesLE(dz0[0]).join(' '), '(dest v0[0], param j=0)');
console.log('dz v0[1] bytes LE:', bytesLE(dz0[1]).join(' '), '(dest v0[1], param i=1)');
console.log('dz v0[2] bytes LE:', bytesLE(dz0[2]).join(' '));
console.log('dz v0[3] bytes LE:', bytesLE(dz0[3]).join(' '));
const dz1 = [0, 1, 2, 3].map(j => (st[4 + j] - v1[j]) & M);
console.log('dz v1   :', dz1.map(h).join(' '));
console.log('dz v1[0] bytes LE:', bytesLE(dz1[0]).join(' '));
console.log('dz v1[1] bytes LE:', bytesLE(dz1[1]).join(' '));
console.log('dz v1[2] bytes LE:', bytesLE(dz1[2]).join(' '));
console.log('dz v1[3] bytes LE:', bytesLE(dz1[3]).join(' '));
