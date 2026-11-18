import fs from 'node:fs';
import zlib from 'node:zlib';

const store = () => { const m = new Map(); return {
  getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)),
  removeItem: (k) => m.delete(k), clear: () => m.clear(), key: (i) => [...m.keys()][i] ?? null,
  get length() { return m.size; } }; };
globalThis.window = globalThis; globalThis.self = globalThis;
globalThis.addEventListener = () => {}; globalThis.removeEventListener = () => {}; globalThis.isSecureContext = false;
globalThis.localStorage = store(); globalThis.sessionStorage = store();
globalThis.location = new URL('https://go.seated.com/x');
const noopEl = () => ({ setAttribute() {}, appendChild() {}, removeChild() {}, addEventListener() {}, getContext() { throw new Error('x'); } });
globalThis.document = { createElement: noopEl, head: noopEl(), body: { appendChild() {}, removeChild() {} } };
globalThis.getComputedStyle = () => ({ fontFamily: 'Segoe UI' });
globalThis.screen = { width: 2560, height: 1440 }; globalThis.innerWidth = 1280; globalThis.innerHeight = 720; globalThis.devicePixelRatio = 2;
globalThis.Notification = { permission: 'granted' };
const nav = globalThis.navigator;
Object.defineProperty(nav, 'userAgent', { value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', configurable: true });
Object.defineProperty(nav, 'language', { value: 'en-US', configurable: true });
Object.defineProperty(nav, 'languages', { value: ['en-US', 'en'], configurable: true });
Object.defineProperty(nav, 'cookieEnabled', { value: true, configurable: true });
Object.defineProperty(nav, 'doNotTrack', { value: '1', configurable: true });
Object.defineProperty(nav, 'hardwareConcurrency', { value: 12, configurable: true });
Object.defineProperty(nav, 'deviceMemory', { value: 8, configurable: true });
Object.defineProperty(nav, 'maxTouchPoints', { value: 5, configurable: true });
Object.defineProperty(nav, 'webdriver', { value: false, configurable: true });
Object.defineProperty(nav, 'plugins', { value: [{ name: 'PDF Viewer' }, { name: 'Chrome PDF Viewer' }], configurable: true });
Object.defineProperty(nav, 'permissions', { value: { query: async (d) => ({ state: d.name === 'geolocation' ? 'granted' : 'prompt' }) }, configurable: true });
Object.defineProperty(nav, 'mediaCapabilities', { value: { decodingInfo: async (c) => ({ supported: true, smooth: false, powerEfficient: true }) }, configurable: true });
Object.defineProperty(nav, 'connection', { value: { type: 'wifi', rtt: 50 }, configurable: true });
Object.defineProperty(nav, 'userAgentData', { value: { getHighEntropyValues: async () => ({
  architecture: 'x86', bitness: '64', formFactor: 'Desktop',
  fullVersionList: [{ brand: 'Chromium', version: '131.0.0.0' }, { brand: 'Google Chrome', version: '131.0.6830.0' }],
  model: '', platform: 'Windows', platformVersion: '15.0.0', wow64: false }) }, configurable: true });
globalThis.indexedDB = { databases: async () => [] };

let captured = null;
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  if (String(url).startsWith('data:')) return realFetch(url, opts);
  captured = new Uint8Array(await new Blob([opts.body]).arrayBuffer());
  return new Response(null, { status: 200 });
};

// ---- locate wasm, patch call 114 -> import 68 (prototypesetcall) ----
let src = fs.readFileSync('../entry82.js', 'utf8');
const dataUrlRe = /data:application\/wasm;base64,([A-Za-z0-9+/=]+)/;
const m = dataUrlRe.exec(src);
const wasmBuf = Buffer.from(m[1], 'base64');
function codeOffset(w) {
  let i = 8;
  while (i < w.length) {
    const id = w[i]; i++;
    let len = 0, sh = 0;
    while (true) { const b = w[i]; i++; len |= (b & 0x7f) << sh; if (!(b & 0x80)) break; sh += 7; }
    if (id === 10) return i;
    i += len;
  }
}
const callSites = [0x1da4b, 0x1dd6f];
for (const cs of callSites) {
  if (wasmBuf[cs] !== 0x10 || wasmBuf[cs + 1] !== 0x72) {
    console.error('PATCH SITE MISMATCH at', cs.toString(16), wasmBuf[cs].toString(16), wasmBuf[cs + 1].toString(16));
    process.exit(1);
  }
  wasmBuf[cs + 1] = 68; // call import 68
}
console.log('patched calls at file offsets', callSites.map(x => x.toString(16)).join(','));
const patchedB64 = wasmBuf.toString('base64'); console.log('patched in src:', src.indexOf(patchedB64.substring(0, 120)) >= 0, 'orig still:', src.indexOf(m[1].substring(0, 120)) >= 0);
src = src.replace(dataUrlRe, 'data:application/wasm;base64,' + patchedB64);

// ---- spy: capture instance + prototypesetcall args ----
let wasmInstance = null;
const spyCalls = [];
const RealInstantiate = WebAssembly.instantiate;
WebAssembly.instantiate = async function (bytesOrModule, imports) {
  if (imports && imports.wbg && imports.wbg.__wbg_prototypesetcall_3d4a26c1ed734349) {
    const orig = imports.wbg.__wbg_prototypesetcall_3d4a26c1ed734349;
    imports.wbg.__wbg_prototypesetcall_3d4a26c1ed734349 = function (a, b, c) {
      try {
        if (wasmInstance) {
          const mem = Buffer.from(wasmInstance.exports.memory.buffer);
          if (c > 4 && c < 4096 && a > 0 && b > 0 && b + c <= mem.length) {
            spyCalls.push({ a, b, c, data: Buffer.from(mem.subarray(b, b + c)) });
          }
        }
      } catch (e) {}
      try { return orig.call(this, a, b, c); } catch (e) {}
    };
  }
  let probe = bytesOrModule;
  try { if (probe instanceof ArrayBuffer) probe = new Uint8Array(probe); } catch (e) {}
  if (probe && probe.length) console.log('INSTANTIATE bytes len', probe.length, 'byte@1dd70 =', probe.length > 0x1dd71 ? probe[0x1dd70].toString(16) : 'n/a', 'wbg keys:', imports && imports.wbg ? Object.keys(imports.wbg).length : 'none', 'has spy key:', !!(imports && imports.wbg && imports.wbg.__wbg_prototypesetcall_3d4a26c1ed734349));
  const res = await RealInstantiate.call(WebAssembly, bytesOrModule, imports);
  const inst = res.instance || res;
  if (inst && inst.exports && inst.exports.memory) wasmInstance = inst;
  return res;
};

function extractModule(marker) { const start = src.indexOf(marker); const ob = start + marker.length - 1;
  let d = 0, i = ob, e = -1;
  while (i < src.length) { const c = src[i];
    if (c === '"' || c === "'" || c === '`') { const q = c; i++; while (i < src.length && src[i] !== q) { if (src[i] === '\\') i++; i++; } i++; continue; }
    if (c === '{') d++; else if (c === '}') { d--; if (!d) { e = i; break; } } i++; }
  return src.slice(ob + 1, e); }
class L { async acquireLock() { return true; } async releaseLock() {} }
const exp = {}; const mkI = (id) => { if (id === 64563) return { default: function () { return new L(); } }; throw new Error('x'); };
mkI.r = () => {}; mkI.d = (ex, df) => { for (const k of Object.keys(df)) Object.defineProperty(ex, k, { get: df[k], enumerable: true }); };
new Function('A', 'g', 'I', extractModule('95941:function(A,g,I){'))({}, exp, mkI);

try {
  await exp.dispatchSignals('K', { appVersion: '1.2.3' });
} catch (e) {
  console.log('dispatchSignals threw (expected if patch broke flow):', e.message);
}

console.log('spy calls captured:', spyCalls.length);
for (const call of spyCalls.slice(-6)) {
  console.log(`\n=== a=${call.a} ptr=0x${call.b.toString(16)} len=${call.c} ===`);
  const line = call.data;
  const hex = [...line].map(x => x.toString(16).padStart(2, '0')).join(' ');
  const asc = [...line].map(x => (x >= 32 && x < 127) ? String.fromCharCode(x) : '.').join('');
  console.log(hex);
  console.log(asc);
}
if (captured) {
  try {
    const raw = zlib.inflateRawSync(Buffer.from(captured));
    function readVarint(b, i) { let v = 0n, sh = 0n, n = 0; while (true) { const by = b[i + n]; n++; v |= BigInt(by & 0x7f) << sh; if (!(by & 0x80)) return [Number(v), n]; sh += 7n; } }
    function fields(buf) { let i = 0; const o = {};
      while (i < buf.length) { const [t, n] = readVarint(buf, i); i += n; const f = t >>> 3, w = t & 7;
        if (w === 0) { const [, n2] = readVarint(buf, i); i += n2; }
        else if (w === 2) { const [l, n2] = readVarint(buf, i); i += n2; (o[f] = o[f] || []).push(buf.subarray(i, i + l)); i += l; }
        else if (w === 5) i += 4; else i += 8; } return o; }
    const f9 = fields(fields(raw)[9][0]);
    console.log('PATCHED RUN f9.f2 =', Buffer.from(f9[2][0]).toString('hex'));
  } catch (e) { console.log('f9 decode fail', e.message); }
}
if (false) {
  try {
    const raw = zlib.inflateRawSync(Buffer.from(captured));
    console.log('\npayload still produced, len', raw.length);
  } catch (e) { console.log('payload inflate failed:', e.message); }
}


