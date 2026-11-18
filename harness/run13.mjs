import fs from 'node:fs';
import zlib from 'node:zlib';
import crypto from 'node:crypto';

const REAL_FONTS_DIGEST = Buffer.from(process.env.PV_DIGEST || "61052e74ac13cb864ce5331005cdc65836d3c6f1532abf520ae52fa200ecee30", "hex");
if (process.env.PV_WRAP === '1') {
  const realDigest = crypto.subtle.digest.bind(crypto.subtle);
  crypto.subtle.digest = async (alg, data) => {
    const text = Buffer.from(data).toString("latin1");
    if (text.includes("Segoe UI")) return REAL_FONTS_DIGEST.buffer.slice(REAL_FONTS_DIGEST.byteOffset, REAL_FONTS_DIGEST.byteOffset + 32);
    return realDigest(alg, data);
  };
}

const store = () => { const m = new Map(); return {
  getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)),
  removeItem: (k) => m.delete(k), clear: () => m.clear(), key: (i) => [...m.keys()][i] ?? null,
  get length() { return m.size; } }; };
globalThis.window = globalThis; globalThis.self = globalThis;
globalThis.addEventListener = () => {}; globalThis.removeEventListener = () => {}; globalThis.isSecureContext = false;
globalThis.localStorage = store(); globalThis.sessionStorage = store();
globalThis.location = new URL('https://go.seated.com/x');
if (process.env.PV_SETTZ !== '1') { /* keep system tz */ } else { process.env.TZ = 'Europe/Warsaw'; }
const noopEl = () => ({ setAttribute() {}, appendChild() {}, removeChild() {}, addEventListener() {}, getContext() { throw new Error('x'); } });
globalThis.document = { createElement: noopEl, head: noopEl(), body: { appendChild() {}, removeChild() {} } };
globalThis.getComputedStyle = () => ({ fontFamily: 'Segoe UI' });
globalThis.screen = { width: 1920, height: 1080 }; globalThis.innerWidth = 958; globalThis.innerHeight = 896; globalThis.devicePixelRatio = parseFloat(process.env.PV_DPR || '1');
globalThis.Notification = { permission: process.env.PV_NOTIF || 'default' };
const nav = globalThis.navigator;
Object.defineProperty(nav, 'userAgent', { value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36', configurable: true });
Object.defineProperty(nav, 'language', { value: process.env.PV_LOCALE || 'pl-PL', configurable: true });
Object.defineProperty(nav, 'languages', { value: JSON.parse(process.env.PV_LANGS || '["pl-PL","pl","en-US","en"]'), configurable: true });
Object.defineProperty(nav, 'cookieEnabled', { value: true, configurable: true });
Object.defineProperty(nav, 'doNotTrack', { value: process.env.PV_DNT === 'null' ? null : (process.env.PV_DNT || null), configurable: true });
Object.defineProperty(nav, 'hardwareConcurrency', { value: 4, configurable: true });
Object.defineProperty(nav, 'deviceMemory', { value: 16, configurable: true });
Object.defineProperty(nav, 'maxTouchPoints', { value: parseInt(process.env.PV_TOUCH || '0'), configurable: true });
Object.defineProperty(nav, 'webdriver', { value: false, configurable: true });
Object.defineProperty(nav, 'plugins', { value: [
  { name: 'PDF Viewer' }, { name: 'Chrome PDF Viewer' }, { name: 'Chromium PDF Viewer' },
  { name: 'Microsoft Edge PDF Viewer' }, { name: 'WebKit built-in PDF' }], configurable: true });
const GRANTED = new Set(JSON.parse(process.env.PV_GRANTED || '["payment-handler","gyroscope","clipboard-write","screen-wake-lock","accelerometer","background-sync","storage-access","magnetometer"]'));
const THROWING = new Set(JSON.parse(process.env.PV_THROW || '["ambient-light-sensor","bluetooth","compute-pressure","push","top-level-storage-access"]'));
Object.defineProperty(nav, 'permissions', { value: { query: async (d) => {
  if (THROWING.has(d.name)) throw new Error('not supported');
  return { state: GRANTED.has(d.name) ? 'granted' : 'prompt' };
} }, configurable: true });
Object.defineProperty(nav, 'mediaCapabilities', { value: { decodingInfo: async (c) => ({ supported: true, smooth: false, powerEfficient: true }) }, configurable: true });
Object.defineProperty(nav, 'connection', { value: JSON.parse(process.env.PV_CONN || '{"rtt":200}'), configurable: true });
const FVL_DEFAULT = JSON.parse(process.env.PV_FVL || '[{"brand":"Not:A-Brand","version":"8.0.0.0"},{"brand":"Chromium","version":"156.0.8078.80"},{"brand":"Google Chrome","version":"156.0.8078.80"}]');
Object.defineProperty(nav, 'userAgentData', { value: { getHighEntropyValues: async () => ({
  architecture: 'x86', bitness: '64', formFactor: 'Desktop',
  fullVersionList: FVL_DEFAULT,
  model: '', platform: 'Windows', platformVersion: '10.0.0', wow64: false }) }, configurable: true });
globalThis.indexedDB = { databases: async () => [] };

let captured = null;
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  if (String(url).startsWith('data:')) return realFetch(url, opts);
  captured = new Uint8Array(await new Blob([opts.body]).arrayBuffer());
  return new Response(null, { status: 200 });
};

let src = fs.readFileSync('../entry82.js', 'utf8');
const dataUrlRe = /data:application\/wasm;base64,([A-Za-z0-9+/=]+)/;
const m = dataUrlRe.exec(src);
const wasmBuf = Buffer.from(m[1], 'base64');
wasmBuf[0x1da4c] = 68;
src = src.replace(dataUrlRe, 'data:application/wasm;base64,' + wasmBuf.toString('base64'));
let wasmInstance = null;
const RealInstantiate = WebAssembly.instantiate;
WebAssembly.instantiate = async function (bytesOrModule, imports) {
  if (imports && imports.wbg && imports.wbg.__wbg_prototypesetcall_3d4a26c1ed734349) {
    imports.wbg.__wbg_prototypesetcall_3d4a26c1ed734349 = function (a, b, c) {
      try {
        if (wasmInstance && c > 4 && c < 4096 && b > 0) {
          fs.writeFileSync(process.env.PV_OUT || 'real_input.bin', Buffer.from(wasmInstance.exports.memory.buffer, b, c));
        }
      } catch (e) {}
    };
  }
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

try { await exp.dispatchSignals('K', process.env.PV_APPVERSION ? { appVersion: process.env.PV_APPVERSION } : {}); } catch (e) { console.log('dispatch error', e.message); }
if (captured) {
  const raw = zlib.inflateRawSync(Buffer.from(captured));
  fs.writeFileSync('real_payload.proto', raw);
  console.log('payload len', raw.length);
}
console.log('done');





