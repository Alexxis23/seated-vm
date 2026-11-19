# seated-vm — full usage guide & dispatch flow

This guide covers everything: the mental model, every parameter you can set
(each mapped to the browser value it emulates), how to collect those values
from a real browser, the complete dispatch flow, and how to verify you did
it right.

---

## 1. Mental model

The Seated/Prelude browser SDK does this on every dispatch:

```
collect browser signals  ──►  signals object (JS)
                                    │
                                    ▼
                    core wasm: generate_payload(signals)
                        ├─ builds an internal byte "buffer"
                        │    (the hash input; obfuscated per-field)
                        ├─ HighwayHash-128 over it  ──► f9.f2 fingerprint
                        ├─ mint dispatch UUID (v7) + timestamps
                        └─ protobuf-serialize + raw-DEFLATE
                                    │
                                    ▼
                    POST  https://edge.prelude.dev
                    Content-Type:        application/vnd.prelude.signals
                    Content-Encoding:    deflate
                    Connection:          close
                    X-SDK-Key:           <your sdk key>
                    X-SDK-DispatchID:    <uuid from step above>
                    X-SDK-User-Agent:    Prelude/0.14.0 Core/0.3.2 (Web)
                    X-SDK-Request-Date:  <RFC3339 now>
                    X-SDK-Implemented-Features: 0
                    <body>
```

seated-vm gives you **two interchangeable paths**:

| Path | What it produces | Use when |
|---|---|---|
| **Static** — `Params.Build()` + `HighwayHash128` | the hash-input buffer + its fingerprint | you only need the fingerprint; smallest dependency footprint |
| **Real core** — `NewCore` + `GeneratePayload` / `PrepareDispatch` | the complete request body + dispatch id + headers, computed by the actual SDK wasm (sha256-pinned blob from chunk.941) | you want the exact bytes the real SDK would send |

Both paths agree byte-exactly (the test suite proves the wasm's own
fingerprint equals `HH128(Build())` for every environment tested).

**The single rule that matters:** the fingerprint is a function of the
environment values only. If your `Params` faithfully describe a coherent
browser, the output is indistinguishable from that browser's dispatch.

---

## 2. Install

```
go get github.com/Alexxis23/seated-vm
```

The wasm blob (`wasm/core.wasm`) is embedded; at first use its SHA-256 is
checked against a pinned constant (`CoreWasmSHA256`) — a mismatch means the
module was tampered with or carries a different SDK build.

---

## 3. Quick start

### 3a. Fingerprint only (static path)

```go
package main

import (
	"encoding/hex"
	"fmt"

	seatedvm "github.com/Alexxis23/seated-vm"
)

func main() {
	p := &seatedvm.Params{
		// REQUIRED
		FontsDigest: "61052e74ac13cb864ce5331005cdc65836d3c6f1532abf520ae52fa200ecee30",
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",

		// A headed Chrome on Windows:
		TZ:       "Europe/Warsaw",
		OSType:   "Windows",
		Arch:     "x86",
		PostPluginsFlag: true, // WebGL present (headed Chrome) — REQUIRED for real Chrome fingerprints!

		FVL: []seatedvm.FVLEntry{ // userAgentData.getHighEntropyValues(["fullVersionList"])
			{"Not:A-Brand", "8.0.0.0"},
			{"Chromium", "156.0.8078.80"},
			{"Google Chrome", "156.0.8078.80"},
		},
		Locale:              "pl-PL",
		Languages:           []string{"pl-PL", "pl", "en-US", "en"},
		HardwareConcurrency: 4,
		MemoryGiB:           16,
		ScreenW:             1920, ScreenH: 1080,
		InnerW: 958, InnerH: 896,
		DevicePixelRatio: 1.0,
		RTT:              200,
		Cookies:          true, LocalStorage: true, IndexedDB: true,
		MediaDigest:   "0607b220ecb0c6fe48506008a804d0d8a7eb64cf6ea168f241c590575ae88a01",
		PluginsDigest: "0382071da078da8ea4375d7681b9138b86deb8023303ef804196ec3c0f78e80a",
		Hostname:      "go.seated.com",
		OSRelease:     "10.0.0",
		Notification:  "default",
		Granted:       []string{"payment-handler", "gyroscope", "clipboard-write", "screen-wake-lock", "accelerometer", "background-sync", "storage-access", "magnetometer"},
		Throwing:      []string{"ambient-light-sensor", "bluetooth", "compute-pressure", "push", "top-level-storage-access"},
	}

	buf := p.Build()                    // 878-byte hash-input buffer
	h := seatedvm.HighwayHash128(buf)   // = the payload's f9.f2
	fmt.Println(hex.EncodeToString(h[:])) // fb777997a04a586c219bb6d424fcc0c4
}
```

Anything you leave empty is filled by `Params.Defaults()` with a
Chrome-156-like profile — but for a *specific* target browser set the real
values (see §5).

### 3b. Full payload with the real wasm

```go
ctx := context.Background()
core, err := seatedvm.NewCore(ctx)      // instantiates the pinned wasm
if err != nil { panic(err) }
defer core.Close(ctx)

body, dispatchID, err := core.GeneratePayload(ctx, p)
// body       = raw-DEFLATE protobuf, the exact POST body
// dispatchID = the wasm-minted UUID v7 (also inside the payload as field 1)
```

Notes on the core:

- One `Core` = one wasm instance. **Not thread-safe** — use one per goroutine
  or guard with a mutex (matching the browser, which dispatches sequentially).
- Reuse the instance across payloads; each `GeneratePayload` mints a fresh
  dispatch id and timestamp.
- Instantiation is fast (~ms); call `Close(ctx)` when done.

---

## 4. The complete dispatch (HTTP)

`PrepareDispatch` assembles everything the SDK sends:

```go
dr, err := core.PrepareDispatch(ctx, p, "prld_live_yourkey")
if err != nil { panic(err) }

req, _ := http.NewRequestWithContext(ctx, http.MethodPost, dr.Endpoint, bytes.NewReader(dr.Body))
dr.SetHeaders(req)

resp, err := http.DefaultClient.Do(req)
if err != nil { panic(err) }
defer resp.Body.Close()
if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
	b, _ := io.ReadAll(resp.Body)
	panic(fmt.Sprintf("dispatch failed: %s %s", resp.Status, b))
}
return dr.DispatchID
```

Header map produced (identical to `entry82.js dispatchSignals`):

| Header | Value | Source |
|---|---|---|
| `Content-Type` | `application/vnd.prelude.signals` | fixed |
| `Content-Encoding` | `deflate` (raw DEFLATE — **not** zlib/gzip) | fixed |
| `Connection` | `close` | fixed |
| `X-SDK-Key` | your SDK key | argument |
| `X-SDK-DispatchID` | the dispatch UUID | wasm (`get_dispatch_id`) or `Params.DispatchID` |
| `X-SDK-User-Agent` | `Prelude/0.14.0 Core/0.3.2 (Web)` | `Params.SDKVersion` + wasm `get_version` |
| `X-SDK-Request-Date` | current UTC time, `2006-01-02T15:04:05.000Z` | generated |
| `X-SDK-Implemented-Features` | `0` | `Params.ImplementedFeatures` |

> TLS/JA3/HTTP2-fingerprint caveats are **out of scope** here — the payload
> is only one signal the server sees. Use a client whose TLS stack matches
> your claimed browser if the endpoint checks it.
>
> Header casing: `SetHeaders` writes header names verbatim (`X-SDK-…`),
> bypassing Go's canonicalization (`X-Sdk-…`). HTTP header names are
> case-insensitive, but this keeps the wire bytes identical to the SDK.

---

## 5. Params reference — every value the wasm consumes

Legend: **HASH** = goes into the fingerprint buffer; **payload** = in the
serialized protobuf; **hdr** = only in request headers. "3-state" fields use
pointers/emptiness to express absent-vs-value like JS `undefined` vs value.

### Environment (hashed)

| Params field | Browser source | Kind | Notes |
|---|---|---|---|
| `UserAgent` | `navigator.userAgent` | HASH | REQUIRED; must agree with FVL/OSType/Arch/OSRelease |
| `TZ` | `Intl.DateTimeFormat().resolvedOptions().timeZone` | HASH | IANA name, e.g. `Europe/Warsaw` |
| `FontsDigest` | sha256 of the font probe string (§6.1) | HASH | REQUIRED; 64 hex chars |
| `Locale` | `navigator.language` | HASH | e.g. `pl-PL` |
| `Languages` | `navigator.languages` | HASH | same first element as Locale |
| `FVL` | `userAgentData.getHighEntropyValues().fullVersionList` | HASH | drives manufacturer/model/systemName/systemVersion zones |
| `OSType` | uaData.platform or UA sniff (`Windows`, `MacOS`, `Linux`, `Android`, `Chrome OS`, `iPad`, `iPhone`, `iOS`, `Unknown`) | HASH | |
| `Arch` | uaData.architecture (`x86`, `x86_64`, `arm`) | HASH | written twice (two zones) |
| `HardwareConcurrency` | `navigator.hardwareConcurrency` | HASH | 0 → treated as absent by JS (`cpuCount` undefined) |
| `MemoryGiB` | `navigator.deviceMemory` | HASH | GiB; sent as exact bytes (`GiB * 1024³`) |
| `ScreenW/H` | `screen.width/height` | HASH | physical |
| `InnerW/H` | `innerWidth/innerHeight` | HASH | window |
| `DevicePixelRatio` | `devicePixelRatio` | HASH | written twice (displayScale + physical) |
| `ConnType` | `connection.type` | HASH | empty → zone absent (Chrome often leaves it undefined!) |
| `RTT` | `connection.rtt` | HASH | |
| `Cookies` | `navigator.cookieEnabled` | HASH | |
| `LocalStorage` | `!!window.localStorage` | HASH | |
| `IndexedDB` | `indexedDB.databases()` success | HASH | |
| `DoNotTrack` | `navigator.doNotTrack` | HASH | empty → absent (Chrome default: absent) |
| `MultiTouch` | `navigator.maxTouchPoints > 1` | HASH | |
| `MediaDigest` | sha256 of media-capabilities codec list (§6.2) | HASH | empty → Defaults() = all-supported Chrome set |
| `PluginsDigest` | sha256 of plugin names (§6.3) | HASH | empty → Defaults() = Chrome PDF plugin set |
| `PostPluginsFlag` | WebGL context creation success | HASH | **1 for any headed Chrome; 0 = headless/no-WebGL** |
| `Automation` | `navigator.webdriver` | HASH | false on normal Chrome |
| `Notification` | `Notification.permission` (`default`/`granted`/`denied`) | HASH | |
| `Granted` / `Throwing` / `PermissionStates` | `permissions.query()` per name | HASH | see below |
| `Hostname` | `location.hostname` (site being verified) | HASH | e.g. `go.seated.com` |
| `OSRelease` | uaData `platformVersion` (`"10.0.0"` on Win) | HASH | empty → null (JS `?? null`) |
| `AppVersion` | dispatcher `appVersion` option | HASH | empty → absent (always absent in real web dispatches) |
| `DevicePlatform` | `device.platform` — always `"web"` | HASH | **equality marker**: buffer writes `len("web")` iff value is exactly `"web"`, else 0. Leave empty. |
| `CellularData` | `connection.type` ∈ cellular → true; bluetooth/ethernet/none/wifi/wimax → false; unknown/absent → undefined | HASH | *bool: nil = undefined (real default); true/false = raw 0/1 byte |

### Permission states

```go
PermissionStates: map[string]byte{ // exact per-name control
	"camera": 3, "microphone": 1, "push": 2, // 1=granted 2=denied 3=prompt
},
// or the simpler form:
Granted:  []string{"geolocation", "camera"}, // these -> granted
Throwing: []string{"push", "midi"},          // these -> ABSENT (query threw)
// names in neither list -> prompt
```

The 24 queryable names (pre-sorted in `PermNames`): accelerometer,
ambient-light-sensor, background-sync, bluetooth, camera,
captured-surface-control, clipboard-read, clipboard-write, compute-pressure,
display-capture, geolocation, gyroscope, local-fonts, magnetometer,
microphone, midi, notifications, payment-handler, persistent-storage, push,
screen-wake-lock, storage-access, top-level-storage-access,
window-management.

### Identity / metadata (NOT hashed)

| Params field | Default | Lands in |
|---|---|---|
| `DispatchID` | wasm-minted UUID v7 | payload field 1 + `X-SDK-DispatchID` |
| `SDKVersion` | `0.14.0` | sdkInfo + `X-SDK-User-Agent` |
| `CoreVersion` | wasm `get_version()` | sdkInfo + `X-SDK-User-Agent` |
| `Origin` | `https://` + Hostname | device.hostname (unread by core 0.3.2) |
| `ImplementedFeatures` | 0 | application.implementedFeatures (unread) + `X-SDK-Implemented-Features` |
| `MaybeHeadless` (*bool) | nil = absent | **must stay nil** — the real SDK never sends it; a value inserts an extra buffer byte |

---

## 6. Collecting the values from a real browser

Run these inside the target browser/context (DevTools console, CDP
`Runtime.evaluate`, or your automation framework) and copy the outputs into
`Params` / the env JSON.

### 6.1 fontsDigest

The SDK probes system fonts via CSS and hashes the result:

```js
// Exact replica of the SDK's probe (entry82.js):
async function fontsDigest() {
  const div = document.createElement("div");
  document.body.appendChild(div);
  try {
    const styles = ["caption","icon","menu","message-box","small-caption","status-bar"];
    const seen = new Set();
    for (const s of styles) {
      div.setAttribute("style", `font: ${s} !important`);
      seen.add(getComputedStyle(div).fontFamily);
    }
    // String([array]) joins with "," — this exact string is hashed:
    const probe = String([...seen]);              // e.g. "Segoe UI,monospace"
    const known = {"-apple-system":"MacOS","Segoe UI":"Windows","Tahoma":"Windows",
      "Yu Gothic UI":"Windows","Microsoft JhengHei UI":"Windows","Microsoft YaHei UI":"Windows",
      "Meiryo UI":"Windows","Cantarell":"Linux","Ubuntu":"Linux","Sans":"Linux",
      "sans-serif":"Linux","Fira Sans":"Linux","Roboto":"Android"};
    const withOS = known[probe] ? `${probe}:${known[probe]}` : probe;
    const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(withOS));
    return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2,"0")).join("");
  } finally { div.remove(); }
}
```

If you emulate a standard Windows Chrome, the value is stable — capture it
once per profile/OS combination and reuse it.

### 6.2 mediaDigest

```js
async function mediaDigest() {
  // Exact list & order from entry82.js:
  const codecs = ["audio/ogg; codecs=vorbis",
                  "audio/ogg; codecs=flac",
                  'audio/mp4; codecs="mp4a.40.2"',
                  'audio/mpeg; codecs="mp3"',
                  "video/mp4; codecs=avc1.42E01E"];
  const jobs = codecs.map(async c => {
    const info = { type: "file",
      video: c.startsWith("video") ? {contentType:c,width:1920,height:1080,bitrate:120000,framerate:60} : undefined,
      audio: c.startsWith("audio") ? {contentType:c,channels:"2",bitrate:300000,samplerate:5200} : undefined };
    try { return { codec: c, ...(await navigator.mediaCapabilities.decodingInfo(info)) }; }
    catch { return null; }
  });
  const results = (await Promise.all(jobs)).filter(Boolean)
    .map(r => `${r.codec}:${r.supported}`);
  const joined = results.sort().join("::");
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(joined));
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2,"0")).join("");
}
```

On any normal Chrome all five codecs are supported — `MediaDigest(true)`
(`seatedvm.MediaDigest(true)`) already produces this constant.

### 6.3 pluginsDigest

```js
async function pluginsDigest() {
  const names = [...navigator.plugins].map(p => p.name.toLowerCase());
  const joined = names.sort().join("::");
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(joined));
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2,"0")).join("");
}
```

### 6.4 Everything else (one snapshot)

```js
const uaData = await navigator.userAgentData?.getHighEntropyValues(
  ["architecture","bitness","formFactor","fullVersionList","model","platform","platformVersion","wow64"]);
const snapshot = {
  userAgent: navigator.userAgent,
  tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
  locale: navigator.language,
  languages: [...navigator.languages],
  hardwareConcurrency: navigator.hardwareConcurrency,
  deviceMemory: navigator.deviceMemory,
  screen: [screen.width, screen.height],
  inner: [innerWidth, innerHeight],
  devicePixelRatio: devicePixelRatio,
  rtt: navigator.connection?.rtt,
  connType: navigator.connection?.type,        // often undefined on Chrome!
  cookies: navigator.cookieEnabled,
  doNotTrack: navigator.doNotTrack,            // usually null -> omit
  multiTouch: navigator.maxTouchPoints > 1,
  osType: uaData?.platform,                    // "Windows"
  arch: uaData?.architecture,                  // "x86"
  osRelease: uaData?.platformVersion,          // "10.0.0"
  fullVersionList: uaData?.fullVersionList,
  notification: Notification.permission,
  automation: navigator.webdriver,
  webGlEnabled: (() => {                       // any context counts
    try { const c = document.createElement("canvas");
      return !!c.getContext("webgl"); } catch { return false; }
  })(),
};
console.log(JSON.stringify(snapshot, null, 2));
// + permissions states:
const names = ["accelerometer","ambient-light-sensor","background-sync","bluetooth",
 "camera","captured-surface-control","clipboard-read","clipboard-write","compute-pressure",
 "display-capture","geolocation","gyroscope","local-fonts","magnetometer","microphone",
 "midi","notifications","payment-handler","persistent-storage","push","screen-wake-lock",
 "storage-access","top-level-storage-access","window-management"];
const states = {};
await Promise.all(names.map(async n => {
  try { states[n] = (await navigator.permissions.query({name:n})).state; } catch {}
}));
console.log(JSON.stringify(states, null, 2));
// granted -> Params.Granted ; denied -> PermissionStates{n:2} ; prompt -> default 3
// names that THREW -> Params.Throwing (absent)
```

`hostname` is not a browser value — it's the site you're verifying against
(e.g. `go.seated.com`).

---

## 7. Env JSON schema (CLI + `ParamsFromJSON`)

```jsonc
{
  // hashed environment
  "userAgent": "…", "tz": "Europe/Warsaw", "fontsDigest": "<64 hex>",
  "locale": "pl-PL", "languages": ["pl-PL","pl","en-US","en"],
  "fullVersionList": [{"brand":"Chromium","version":"156.0.8078.80"}, …],
  "osType": "Windows", "arch": "x86", "osRelease": "10.0.0",
  "hardwareConcurrency": 4, "deviceMemory": 16,
  "screen": [1920,1080], "inner": [958,896], "devicePixelRatio": 1.0,
  "connection": {"rtt": 200, "type": "wifi"},   // omit "type" if undefined
  "cookies": true, "localStorage": true, "indexedDB": true,
  "doNotTrack": null,                            // omit key or empty -> absent
  "multiTouch": false,
  "mediaDigest": "<64 hex>", "pluginsDigest": "<64 hex>",
  "postPluginsFlag": true,                       // == webGlEnabled
  "automation": false,
  "notification": "default",
  "hostname": "go.seated.com",
  "granted": ["…"], "throwing": ["…"],
  "permissionStates": {"camera": 1, "push": 3},  // exact control (optional)
  "maybeHeadless": null,                          // LEAVE OUT (see docs)

  // identity / metadata overrides (all optional)
  "dispatchId": "01a1f39a-…",       // replay a specific dispatch
  "sdkVersion": "0.14.0",
  "coreVersion": "0.3.2",
  "devicePlatform": "web",
  "origin": "https://go.seated.com",
  "cellularData": null,             // true/false forces the raw byte
  "implementedFeatures": 0
}
```

CLI:

```
go run ./cmd/buffergen --env examples/env_sig86.json --out buffer.bin --hh   # static
go run ./cmd/buffergen --env examples/env_sig86.json --wasm --out payload.bin # real core
```

---

## 8. Flow, end to end (what a bot does)

```
1. (once per profile/OS) collect §6 values, store as env JSON
2. per dispatch:
   a. load Params (fresh copy — Defaults()/GeneratePayload mutate)
   b. optionally bump RTT, re-mint DispatchID etc.
   c. dr, _ := core.PrepareDispatch(ctx, p, sdkKey)
   d. POST dr.Body to dr.Endpoint with dr.SetHeaders(req)
   e. 200/204 -> done, dispatch id = dr.DispatchID
   f. 4xx/5xx -> the body is a JSON error object {code, message};
      map codes via the SDK's PrldErrors taxonomy if you need to retry
3. rotate/refresh: fontsDigest & permission states change rarely; rtt,
   timestamps and dispatch id change per dispatch. Keep everything coherent.
```

Timing note: the payload embeds its own timestamps (from `Date.now()` inside
the wasm), so generate right before sending — don't cache bodies.

### Coherence checklist (the server's cross-checks)

- UA string ⟷ FVL brands/versions ⟷ OSType/OSRelease/Arch
- Locale ⟷ Languages[0]; TZ ⟷ (geo/IP if they correlate)
- `PostPluginsFlag=true` for headed Chrome (a real headed Chrome ALWAYS
  succeeds at WebGL)
- `DevicePlatform` stays `"web"` (empty is fine)
- headless farms: keep `PostPluginsFlag=false` ONLY if your UA/headless
  story is genuinely WebGL-less (Node-harness-like), else emulate WebGL = 1
- never set `MaybeHeadless` (real SDK never does)
- permission sets should match a plausible profile (a fresh Chrome has
  mostly prompt + a few granted)

---

## 9. Verifying your setup

Built-in gates (`go test ./...`):

- `TestCoreGeneratePayload` — wasm fingerprint == `HH128(Build())` == the
  real sig86 capture (`fb777997…`)
- `TestCoreRTTSwitch` — rtt=100 reproduces sig92 (`6716c0f4…`)
- `TestSpyHashSpan` — the span the wasm hashes equals `Build()` byte-exact

Manual gate for any environment you build:

```
go run ./cmd/buffergen --env myenv.json --wasm --out payload.bin
# prints: f9.f2 : <hex> (static HH128(Build()) = <hex>, match=true)
```

`match=true` means the wasm and the static builder agree. Compare the
fingerprint against a real capture from your target browser to prove the
profile.

---

## 10. Adapting to another browser / SDK version

**Another browser profile** (Firefox-ish, Mac, mobile…):

1. Collect §6 values in that browser.
2. Fill every `Params` field from the snapshot (don't rely on `Defaults()`
   — it's a Chrome-156/Windows profile).
3. Watch the coherence checklist in §8 (e.g. Firefox has no
   `userAgentData` → the real SDK sends `osType` from its UA-sniff fallback,
   `osRelease`/`systemName`/`systemVersion`/manufacturer/model as null, and
   `arch` from its fallback heuristic — set those fields accordingly).
4. Verify: fingerprint from your real browser capture must equal
   `HH128(Build())` of your Params.

**A new SDK/core version** (new chunk.941):

1. Save the new chunk; `ExtractCoreWasmVerified(chunk, "")` to get the blob
   and its sha256; drop it into `wasm/core.wasm` and update
   `CoreWasmSHA256`.
2. Run `TestSpyHashSpan` — if the hashed span diverges from `Build()`, the
   buffer layout changed: use the spy dump (first-divergence offset) to
   locate the new/changed zone and adjust `fp.go`.
3. Re-check the getter list (`wasm/headers.txt` import section) for new
   `__wbg_*` getters — add fields to `signals.go`/`Params` for anything new.
4. Re-run the suite; the wasm and static paths must agree again.
