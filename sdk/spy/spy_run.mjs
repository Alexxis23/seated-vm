// spy_run.mjs - run the SDK with the spy-patched wasm, dump SipHash (k0,k1,ptr,end,data) records.
// Usage: node spy_run.mjs --env base   (run11 131-family defaults)
//        node spy_run.mjs --env real   (real-Chrome-156 defaults, run13 style)
//        node spy_run.mjs --env custom with PV_* overrides (JSON values)
import fs from 'node:fs';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import path from 'node:path';

const here = import.meta.dirname;
const args = process.argv.slice(2);
const envName = args.includes('--env') ? args[args.indexOf('--env') + 1] : 'real';
const outDir = path.join(here, '..', 'leaks');
fs.mkdirSync(outDir, { recursive: true });
const E = (k, d) => (process.env['PV_' + k] !== undefined ? JSON.parse(process.env['PV_' + k]) : d);

const IS_BASE = envName === 'base';

// fonts digest override (real env: force the real Chrome-156 digest like the original capture)
if (!IS_BASE && process.env.PV_WRAP !== '0') {
  const REAL_FONTS_DIGEST = Buffer.from(process.env.PV_DIGEST || "61052e74ac13cb864ce5331005cdc65836d3c6f1532abf520ae52fa200ecee30", "hex");
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
process.env.TZ = IS_BASE ? (E('TZ_SET', 'Europe/Warsaw')) : (process.env.PV_SETTZ === '0' ? process.env.TZ : 'Europe/Warsaw');

const noopEl = () => ({ setAttribute() {}, appendChild() {}, removeChild() {}, addEventListener() {}, getContext() { throw new Error('x'); } });
globalThis.document = { createElement: noopEl, head: noopEl(), body: { appendChild() {}, removeChild() {} } };
if (IS_BASE) {
  globalThis.getComputedStyle = () => ({ fontFamily: E('FONT', 'Segoe UI') });
  globalThis.screen = E('SCREEN', { width: 2560, height: 1440 });
  globalThis.innerWidth = E('INNER_W', 1280); globalThis.innerHeight = E('INNER_H', 720);
  globalThis.devicePixelRatio = E('DPR', 2);
  globalThis.Notification = { permission: E('NOTIF', 'granted') };
} else {
  globalThis.getComputedStyle = () => ({ fontFamily: 'Segoe UI' });
  globalThis.screen = { width: 1920, height: 1080 }; globalThis.innerWidth = 958; globalThis.innerHeight = 896;
  globalThis.devicePixelRatio = parseFloat(process.env.PV_DPR || '1');
  globalThis.Notification = { permission: process.env.PV_NOTIF || 'default' };
}
const nav = globalThis.navigator;
if (IS_BASE) {
  Object.defineProperty(nav, 'userAgent', { value: E('UA', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'), configurable: true });
  Object.defineProperty(nav, 'language', { value: E('LANG', 'en-US'), configurable: true });
  Object.defineProperty(nav, 'languages', { value: E('LANGS', ['en-US', 'en']), configurable: true });
  Object.defineProperty(nav, 'cookieEnabled', { value: E('COOKIES', true), configurable: true });
  Object.defineProperty(nav, 'doNotTrack', { value: E('DNT', '1'), configurable: true });
  Object.defineProperty(nav, 'hardwareConcurrency', { value: E('CPU', 12), configurable: true });
  Object.defineProperty(nav, 'deviceMemory', { value: E('MEM', 8), configurable: true });
  Object.defineProperty(nav, 'maxTouchPoints', { value: E('TOUCH', 5), configurable: true });
  Object.defineProperty(nav, 'webdriver', { value: E('WEBDRIVER', false), configurable: true });
  Object.defineProperty(nav, 'plugins', { value: E('PLUGINS', [{ name: 'PDF Viewer' }, { name: 'Chrome PDF Viewer' }]), configurable: true });
  const granted = E('GEO_GRANTED', 'geolocation');
  Object.defineProperty(nav, 'permissions', { value: { query: async (d) => ({ state: d.name === granted ? 'granted' : 'prompt' }) }, configurable: true });
  Object.defineProperty(nav, 'mediaCapabilities', { value: { decodingInfo: async (c) => ({ supported: E('MEDIA_SUP', true), smooth: false, powerEfficient: true }) }, configurable: true });
  Object.defineProperty(nav, 'connection', { value: E('CONN', { type: 'wifi', rtt: 50 }), configurable: true });
  const FVLB = E('FVL', [{ brand: 'Chromium', version: '131.0.0.0' }, { brand: 'Google Chrome', version: '131.0.6830.0' }]);
  Object.defineProperty(nav, 'userAgentData', { value: { getHighEntropyValues: async () => ({
    architecture: E('ARCH', 'x86'), bitness: '64', formFactor: 'Desktop',
    fullVersionList: FVLB, model: '', platform: E('PLATFORM', 'Windows'),
    platformVersion: E('PLATVER', '15.0.0'), wow64: false }) }, configurable: true });
} else {
  Object.defineProperty(nav, 'userAgent', { value: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36', configurable: true });
  Object.defineProperty(nav, 'language', { value: process.env.PV_LOCALE || 'pl-PL', configurable: true });
  Object.defineProperty(nav, 'languages', { value: JSON.parse(process.env.PV_LANGS || '["pl-PL","pl","en-US","en"]'), configurable: true });
  Object.defineProperty(nav, 'cookieEnabled', { value: true, configurable: true });
  Object.defineProperty(nav, 'doNotTrack', { value: null, configurable: true });
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
    fullVersionList: FVL_DEFAULT, model: '', platform: 'Windows', platformVersion: '10.0.0', wow64: false }) }, configurable: true });
}
globalThis.indexedDB = { databases: async () => [] };

let captured = null;
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts) => {
  if (String(url).startsWith('data:')) return realFetch(url, opts);
  captured = new Uint8Array(await new Blob([opts.body]).arrayBuffer());
  return new Response(null, { status: 200 });
};

let src = fs.readFileSync(path.join(here, '..', '..', 'entry82.js'), 'utf8');
const dataUrlRe = /data:application\/wasm;base64,([A-Za-z0-9+/=]+)/;
const wasmFile = process.env.PV_WASM === 'orig'
  ? path.join(here, '..', '..', 'wasm', 'core.wasm')
  : path.join(here, 'core_spy.wasm');
const spyWasm = fs.readFileSync(wasmFile);
src = src.replace(dataUrlRe, 'data:application/wasm;base64,' + spyWasm.toString('base64'));

const SPY_MAGIC = parseInt(process.env.SPY_MAGIC || '123456789');
const SPY_MAGIC_S = parseInt(process.env.SPY_MAGIC_S || '123456790');
const SPY_MAGIC_D = parseInt(process.env.SPY_MAGIC_D || '123456791');
const spyRecords = [];
const spy114Records = [];
let spyPending = null;
let spy114Pending = null;
let wasmInstance = null;
const RealInstantiate = WebAssembly.instantiate;
WebAssembly.instantiate = async function (bytesOrModule, imports) {
  if (imports && imports.wbg && imports.wbg.__wbg_prototypesetcall_3d4a26c1ed734349) {
    imports.wbg.__wbg_prototypesetcall_3d4a26c1ed734349 = function (a, b, c) {
      try {
        if (c === SPY_MAGIC_S) {
          // func114 spy: (state, 0|1, MAGIC_S) — pre/post-update HH state snapshot
          if (wasmInstance) {
            const st = a >>> 0;
            const snap = Buffer.from(wasmInstance.exports.memory.buffer, st, 176).toString('hex');
            if (b === 0) {
              spy114Pending = { statePtr: st, pre: snap };
            } else if (spy114Pending) {
              spy114Pending.post = snap;
              spy114Records.push(spy114Pending);
              spy114Pending = null;
            }
          }
          return;
        }
        if (c === SPY_MAGIC_D) {
          // func114 spy: (ptr, len, MAGIC_D) — log data slice for pending record
          if (spy114Pending) {
            const ptr = a >>> 0, len = b >>> 0;
            let data = '';
            if (wasmInstance && len > 0 && len < 65536) {
              data = Buffer.from(wasmInstance.exports.memory.buffer, ptr, len).toString('hex');
            }
            spy114Pending.ptr = ptr;
            spy114Pending.len = len;
            spy114Pending.data = data;
          } else {
            // standalone data call (no state pending): standalone record
            const ptr = a >>> 0, len = b >>> 0;
            let data = '';
            if (wasmInstance && len > 0 && len < 65536) {
              data = Buffer.from(wasmInstance.exports.memory.buffer, ptr, len).toString('hex');
            }
            spy114Records.push({ ptr, len, data });
          }
          return;
        }
        if (c === SPY_MAGIC) {
          // spy protocol: (k0lo,k0hi,M) then (k1lo,k1hi,M) then (ptr,end,M)
          if (spyPending === null) {
            spyPending = { k0: (BigInt(b >>> 0) << 32n) | BigInt(a >>> 0) };
          } else if (!('k1' in spyPending)) {
            spyPending.k1 = (BigInt(b >>> 0) << 32n) | BigInt(a >>> 0);
          } else {
            const ptr = a >>> 0, len = b >>> 0;
            let data = '';
            if (wasmInstance && len > 0 && len < 4096) {
              data = Buffer.from(wasmInstance.exports.memory.buffer, ptr, len).toString('hex');
            }
            spyRecords.push({ k0: spyPending.k0.toString(), k1: spyPending.k1.toString(), ptr, len, data });
            spyPending = null;
          }
          return;
        }
        // original HH-input capture path (call 114 redirected to import 68)
        if (wasmInstance && c > 4 && c < 4096 && b > 0) {
          fs.writeFileSync(path.join(outDir, envName + '_input.bin'), Buffer.from(wasmInstance.exports.memory.buffer, b, c));
        }
      } catch (e) {}
    };
  }
  const res = await RealInstantiate.call(WebAssembly, bytesOrModule, imports);
  const inst = res.instance || res;
  if (inst && inst.exports && inst.exports.memory) {
    wasmInstance = inst;
  }
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

const appVersion = process.env.PV_APPVERSION !== undefined ? process.env.PV_APPVERSION : (IS_BASE ? '1.2.3' : null);
const HARD_MS = parseInt(process.env.PV_HARD_MS || '25000');
const killTimer = setTimeout(() => { console.log('HARD TIMEOUT — dumping what we have'); dumpAndExit(); }, HARD_MS);
killTimer.unref?.();

function dumpAndExit() {
  try { dumpLeaks(); } catch (e) { console.log('dump error', e.message); }
  process.exit(0);
}

function dumpLeaks() {
  fs.writeFileSync(path.join(outDir, envName + '_leaks.json'), JSON.stringify(spyRecords, null, 1));
  fs.writeFileSync(path.join(outDir, envName + '_leaks114.json'), JSON.stringify(spy114Records, null, 1));
  console.log('siphash records:', spyRecords.length, ' hh114 records:', spy114Records.length);
  for (const r of spy114Records) {
    console.log(`HH114 state@${r.statePtr} ptr=${r.ptr} len=${r.len}`);
    if (r.data) console.log(`    data=${r.data.length > 160 ? r.data.slice(0, 160) + '...' : r.data}`);
    if (r.pre) console.log(`    pre =${r.pre.slice(0, 128)}...`);
    if (r.post) console.log(`    post=${r.post.slice(0, 128)}...`);
  }
}

console.log('env:', envName, 'dispatching...');
try { await exp.dispatchSignals('K', appVersion ? { appVersion } : {}); } catch (e) { console.log('dispatch error', e.message); }
console.log('dispatch returned');
if (captured) {
  fs.writeFileSync(path.join(outDir, envName + '_payload.proto'), Buffer.from(captured));
}
clearTimeout(killTimer);
dumpAndExit();
