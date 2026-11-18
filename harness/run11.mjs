// run11.mjs - fully env-parametrized input capture
import fs from 'node:fs';
const E = (k, d) => (process.env['PV_' + k] !== undefined ? JSON.parse(process.env['PV_' + k]) : d);
const store = () => { const m = new Map(); return {
  getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)),
  removeItem: (k) => m.delete(k), clear: () => m.clear(), key: (i) => [...m.keys()][i] ?? null,
  get length() { return m.size; } }; };
globalThis.window = globalThis; globalThis.self = globalThis;
globalThis.addEventListener = () => {}; globalThis.removeEventListener = () => {}; globalThis.isSecureContext = false;
globalThis.localStorage = store(); globalThis.sessionStorage = store();
globalThis.location = new URL(E('ORIGIN', 'https://go.seated.com') + '/x');
const noopEl = () => ({ setAttribute() {}, appendChild() {}, removeChild() {}, addEventListener() {}, getContext() { throw new Error('x'); } });
globalThis.document = { createElement: noopEl, head: noopEl(), body: { appendChild() {}, removeChild() {} } };
globalThis.getComputedStyle = () => ({ fontFamily: E('FONT', 'Segoe UI') });
globalThis.screen = E('SCREEN', { width: 2560, height: 1440 });
globalThis.innerWidth = E('INNER_W', 1280); globalThis.innerHeight = E('INNER_H', 720); globalThis.devicePixelRatio = E('DPR', 2);
globalThis.Notification = { permission: E('NOTIF', 'granted') };
const nav = globalThis.navigator;
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
const fvl = E('FVL', [{ brand: 'Chromium', version: '131.0.0.0' }, { brand: 'Google Chrome', version: '131.0.6830.0' }]);
Object.defineProperty(nav, 'userAgentData', { value: { getHighEntropyValues: async () => ({
  architecture: E('ARCH', 'x86'), bitness: '64', formFactor: 'Desktop',
  fullVersionList: fvl, model: '', platform: E('PLATFORM', 'Windows'),
  platformVersion: E('PLATVER', '15.0.0'), wow64: false }) }, configurable: true });
globalThis.indexedDB = { databases: async () => [] };
if (E('TZ', null)) process.env.TZ = E('TZ', '');

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
const spyCalls = [];
const RealInstantiate = WebAssembly.instantiate;
WebAssembly.instantiate = async function (bytesOrModule, imports) {
  if (imports && imports.wbg && imports.wbg.__wbg_prototypesetcall_3d4a26c1ed734349) {
    imports.wbg.__wbg_prototypesetcall_3d4a26c1ed734349 = function (a, b, c) {
      try {
        if (wasmInstance && c > 4 && c < 4096 && b > 0) {
          spyCalls.push({ a, b, c, data: Buffer.from(wasmInstance.exports.memory.buffer, b, c) });
          fs.writeFileSync(process.env.PV_OUT || 'input.bin', spyCalls[spyCalls.length - 1].data);
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
try { await exp.dispatchSignals('K', { appVersion: E('APPVERSION', '1.2.3') }); } catch (e) {}
console.log('done', (spyCalls[0] || {}).c);
