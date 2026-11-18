// Independent runtime audit of the HH oracle (claim 3 post-state + claim 5 hashes).
// Usage: node out/verify/oracle_audit.mjs
import fs from 'node:fs';

const ROOT = 'C:/Users/Administrator/Desktop/seated-vm';
const wasm = fs.readFileSync(ROOT + '/out/spy/hh_oracle.wasm');
const leaks = JSON.parse(fs.readFileSync(ROOT + '/out/leaks/real_leaks114.json', 'utf8'));
const real878 = fs.readFileSync(ROOT + '/fixtures/real_input.bin');

// Build the 882-byte wifi buffer from the stage-1 record data
const buf882 = Buffer.from(leaks[0].data, 'hex');
const h1_16 = Buffer.from(leaks[1].data, 'hex');

function fresh() {
  const m = new WebAssembly.Instance(new WebAssembly.Module(wasm));
  return m.exports;
}

// reset state at `sp` to the live 'pre' snapshot (also verifies pre == hh_js.mjs init)
const preBytes = Buffer.from(leaks[0].pre, 'hex');
const PI = [0xdbe6d5d5fe4cce2fn, 0xa4093822299f31d0n, 0x13198a2e03707344n, 0x243f6a8885a308d3n,
            0x3bd39e10cb0ef593n, 0xc0acf169b5f18a8cn, 0xbe5466cf34e90c6cn, 0x452821e638d01377n];
{
  const e = fresh(); const dv = new DataView(e.memory.buffer);
  PI.forEach((v, i) => dv.setBigUint64(4096 + 8 * i, v, true));
  PI.forEach((v, i) => dv.setBigUint64(4096 + 64 + 8 * i, v, true));
  for (let i = 16; i < 22; i++) dv.setBigUint64(4096 + 8 * i, 0n, true);
  const hhjsInit = Buffer.from(e.memory.buffer, 4096, 176);
  console.log('[init] hh_js.mjs-style init == live record[0].pre :', hhjsInit.equals(preBytes));
  console.log('[init] record[0].pre == record[1].pre             :', leaks[0].pre === leaks[1].pre);
  e;
}

function run(data, refPost, tag) {
  const e = fresh();
  const mem = new Uint8Array(e.memory.buffer);
  mem.set(preBytes, 4096);
  mem.set(data, 8192);
  e.update(4096, 8192, data.length);
  const post = Buffer.from(e.memory.buffer, 4096, 176);
  const postMatch = refPost ? post.equals(Buffer.from(refPost, 'hex')) : null;
  e.fin(16384, 4096);
  const h = Buffer.from(e.memory.buffer, 16384, 16).toString('hex');
  console.log(`[${tag}] len=${data.length}`);
  console.log(`    post176 == ${refPost ? 'live record post' : '(no live ref)'} : ${postMatch}`);
  console.log(`    HH = ${h}`);
  return h;
}

console.log('\n== stage-1: 882-byte wifi buffer (record[0]) ==');
const h882 = run(buf882, leaks[0].post, 'stage1/882');

console.log('\n== stage-2: 16-byte h1 blob (record[1]) ==');
const h16 = run(h1_16, leaks[1].post, 'stage2/16');

console.log('\n== 878-byte fixtures/real_input.bin (no live record exists in current JSON) ==');
const h878 = run(real878, null, 'plain/878');

console.log('\n== comparisons (claim 5) ==');
const F9_86 = 'fb777997a04a586c219bb6d424fcc0c4';
const F9_92 = '6716c0f443514fa27326ea3b40cbcacc';
console.log('HH(878) == dab600eacc9120c7724b04f20eb3bdb4 :', h878 === 'dab600eacc9120c7724b04f20eb3bdb4');
console.log('HH(882) == 992f9773b5d20473365bb19b5baa1e7d :', h882 === '992f9773b5d20473365bb19b5baa1e7d');
console.log('record[1].data == HH(882)                   :', h1_16.toString('hex') === h882);
console.log('HH(16-byte h1) == bb47fea7bac126b740efd300ac9fac4e :', h16 === 'bb47fea7bac126b740efd300ac9fac4e');
console.log('HH(878) != f9(sig86) :', h878 !== F9_86, ' != f9(sig92):', h878 !== F9_92);
console.log('HH(882) != f9(sig86) :', h882 !== F9_86, ' != f9(sig92):', h882 !== F9_92);
console.log('HH(16)   != f9(sig86) :', h16 !== F9_86, ' != f9(sig92):', h16 !== F9_92);

// save buffers for the python-side wifi-variant construction check
fs.writeFileSync(ROOT + '/out/verify/h1_16.bin', h1_16);
console.log('\nwrote out/verify/h1_16.bin');
