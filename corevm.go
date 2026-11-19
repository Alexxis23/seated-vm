package seatedvm

// corevm.go — hosts the REAL Prelude core wasm (the exact blob embedded in
// chunk.941) under wazero and drives it exactly the way the SDK's
// wasm-bindgen glue (entry82.js module 95941) does:
//
//	ret = add_to_stack_pointer(-16)
//	generate_payload(ret, addHeapObject(signals))
//	ptr, len = i32[ret], i32[ret+4]; body = memory[ptr:ptr+len]; free(ptr,len,1)
//
// The wasm never touches a browser: it pulls every environment value through
// the 79 `wbg` imports, which this host implements on top of Params. The
// returned bytes are the raw-deflate protobuf the SDK POSTs to
// /v1/signals with Content-Type: application/vnd.prelude.signals — including
// the internally computed HighwayHash-128 and dispatch UUID.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
	"unicode/utf16"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// jsUndefined/jsNull — the glue heap is initialized as
// `new Array(128).fill(undefined)` then `push(undefined, null, true, false)`,
// so refs 0..127 are the JS-stack zone, 128=undefined, 129=null, 130/131=bools.
const (
	jsStackTop  = 128 // glue's G: stack slots grow down from here
	jsUndefRef  = 128
	jsNullRef   = 129
	jsHeapStart = 132 // first allocatable heap slot
)

const (
	boolNone  = 16777215 // Option<bool> null sentinel returned by bool getters
	f64None   = 4294967297.0
	sdkJSVer  = "0.14.0" // `fA` constant in entry82.js (X-SDK-User-Agent / sdkInfo)
	nullObjRt = 0        // glue object getters return literal 0 (= heap slot 0, undefined) for null
)

// ---------- JS value model (only what the wasm can observe) ----------

type jsUndefT struct{}
type jsNullT struct{}
type jsSymIter struct{}               // Symbol.iterator sentinel
type jsDate struct{ ms float64 }      // new Date()
type jsBytes struct{ data []byte }    // Uint8Array
type jsArrayBuf struct{ data []byte } // ArrayBuffer
type jsIter struct {
	items []any
	i     int
} // array iterator
type jsIterResult struct {
	done  bool
	value any
} // {done, value}
type jsMethod struct {
	kind string
	recv *jsIter
} // bound method ref ("next"|"iterator")
type jsErr struct{ msg string }
type jsSymbol struct{ desc string }

// jsObject is an insertion-ordered object (Go maps are not; the wasm reads
// Object.entries() order verbatim).
type jsObject struct {
	keys []string
	vals map[string]any
}

func newJSObject() *jsObject { return &jsObject{vals: map[string]any{}} }

func (o *jsObject) set(k string, v any) {
	if _, exists := o.vals[k]; !exists {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *jsObject) get(k string) any {
	v, ok := o.vals[k]
	if !ok {
		return jsUndefT{}
	}
	return v
}

func jsUndefined() any { return jsUndefT{} }
func jsNull() any      { return jsNullT{} }

// jsThrow mirrors the glue's `__wbindgenthrow` (wasm panic → host error).
type jsThrow struct{ msg string }

func (e *jsThrow) Error() string { return "wasm throw: " + e.msg }

// ---------- Core ----------

// Core is one instantiated core wasm. It is stateful (the wasm keeps its own
// globals) and NOT safe for concurrent use; sequential payload generation on
// a single Core matches the browser's usage exactly.
type Core struct {
	rt  wazero.Runtime
	mod api.Module
	mem api.Memory

	h        []any // the glue's heap/stack array `t`
	free     []int // dropped-slot free list (glue's `a` chain)
	next     int   // next fresh heap slot
	stkDepth int   // glue's G bookkeeping (stack slots in use, growing down from jsStackTop)

	coreVersion string

	// spyPrototypesetcall, when set, observes prototype-set copies before
	// they land in memory (used by the hash-span spy test and for debugging).
	spyPrototypesetcall func(dst, dstLen, src uint32)
	// spySpan / spyOnly support the spy-patched module tests.
	spySpan *[]byte
	spyOnly bool
}

// NewCore instantiates the embedded chunk.941 core wasm (sha-verified).
func NewCore(ctx context.Context) (*Core, error) {
	blob, err := CoreWasm()
	if err != nil {
		return nil, err
	}
	return NewCoreFromWasm(ctx, blob)
}

// NewCoreFromWasm instantiates an explicit core wasm blob (e.g. extracted
// fresh from a new chunk.941 via ExtractCoreWasmVerified).
func NewCoreFromWasm(ctx context.Context, blob []byte) (*Core, error) {
	c := &Core{}
	// Mirror the glue heap exactly.
	c.h = make([]any, jsStackTop)
	for i := range c.h {
		c.h[i] = jsUndefined()
	}
	c.h = append(c.h, jsUndefined(), jsNull(), true, false)
	c.next = len(c.h)

	rt := wazero.NewRuntime(ctx)
	c.rt = rt
	if err := c.registerHost(ctx); err != nil {
		rt.Close(ctx)
		return nil, err
	}
	mod, err := rt.Instantiate(ctx, blob)
	if err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("instantiating core wasm: %w", err)
	}
	c.mod = mod
	c.mem = mod.Memory()
	c.coreVersion, err = c.GetVersion(ctx)
	if err != nil {
		rt.Close(ctx)
		return nil, err
	}
	return c, nil
}

// Close releases the runtime.
func (c *Core) Close(ctx context.Context) error { return c.rt.Close(ctx) }

// CoreVersion is the wasm's own core version (get_version export).
func (c *Core) CoreVersion() string { return c.coreVersion }

// SDKUserAgent mirrors the JS `uA()`: "Prelude/0.14.0 Core/x.y.z (Web)".
func (c *Core) SDKUserAgent() string {
	return "Prelude/" + sdkJSVer + " Core/" + c.coreVersion + " (Web)"
}

// ---------- heap helpers (mirror the glue's addHeapObject/getObject/dropRef) ----------

func (c *Core) addHeap(v any) int {
	if n := len(c.free); n > 0 {
		i := c.free[n-1]
		c.free = c.free[:n-1]
		c.h[i] = v
		return i
	}
	c.h = append(c.h, v)
	return len(c.h) - 1
}

func (c *Core) dropHeap(i int) {
	// Glue: slots below jsHeapStart are never recycled.
	if i < jsHeapStart || i >= len(c.h) {
		return
	}
	c.h[i] = c.next // free-list: slot holds the next free index
	c.next = i
	c.free = append(c.free, i)
}

func (c *Core) obj(i int) any {
	if i < 0 || i >= len(c.h) {
		return jsUndefined()
	}
	return c.h[i]
}

// pushJSStack/pullJSStack mirror the glue's `t[--G]=A` / `t[G++]=void 0`.
func (c *Core) pushJSStack(v any) int {
	idx := jsStackTop - 1 - c.stkDepth
	c.stkDepth++
	c.h[idx] = v
	return idx
}

func (c *Core) popJSStack(idx int) {
	c.stkDepth--
	c.h[idx] = jsUndefined()
}

// ---------- memory helpers ----------

func (c *Core) readI32(off uint32) uint32 {
	v, ok := c.mem.ReadUint32Le(off)
	if !ok {
		panic(&jsThrow{msg: fmt.Sprintf("memory read oob at %#x", off)})
	}
	return v
}

func (c *Core) writeI32(off uint32, v uint32) {
	if !c.mem.WriteUint32Le(off, v) {
		panic(&jsThrow{msg: fmt.Sprintf("memory write oob at %#x", off)})
	}
}

func (c *Core) writeBytes(off uint32, b []byte) {
	if !c.mem.Write(off, b) {
		panic(&jsThrow{msg: "memory write oob"})
	}
}

func (c *Core) writeF64(off uint32, v float64) {
	if !c.mem.WriteFloat64Le(off, v) {
		panic(&jsThrow{msg: "memory write oob"})
	}
}

// malloc calls the wasm allocator (__wbindgen_export_0).
func (c *Core) malloc(n, align uint32) uint32 {
	r, err := c.mod.ExportedFunction("__wbindgen_export_0").Call(context.Background(), uint64(n), uint64(align))
	if err != nil {
		panic(&jsThrow{msg: "malloc failed: " + err.Error()})
	}
	return uint32(r[0])
}

// freeMem calls __wbindgen_export_3 (best effort).
func (c *Core) freeMem(ptr, n, align uint32) {
	_, _ = c.mod.ExportedFunction("__wbindgen_export_3").Call(context.Background(), uint64(ptr), uint64(n), uint64(align))
}

// passString mirrors the glue's passStringToWasm0 (TextEncoder path).
func (c *Core) passString(s string) (ptr, n uint32) {
	b := []byte(s)
	n = uint32(len(b))
	ptr = c.malloc(n, 1)
	c.writeBytes(ptr, b)
	return
}

// writeStrRef writes a (ptr,len) string return slot; null → (0,0).
func (c *Core) writeStrRef(ret uint32, v any) {
	if s, ok := v.(string); ok && v != nil {
		ptr, n := c.passString(s)
		c.writeI32(ret+4, n)
		c.writeI32(ret, ptr)
		return
	}
	c.writeI32(ret+4, 0)
	c.writeI32(ret, 0)
}

// toF64 coerces a heap value like JS `0|g` (ToInt32) / fround per the getter.
func toI32(v any) uint32 {
	f, ok := v.(float64)
	if !ok {
		return 0 // JS null→0 through ToInt32 result coercion
	}
	return uint32(int32(f)) // truncation like the JS-to-wasm i32 conversion
}

func fround(v any) float64 {
	f, ok := v.(float64)
	if !ok {
		return 0
	}
	return float64(float32(f))
}

// ---------- host module: all 79 wbg imports ----------

func (c *Core) registerHost(ctx context.Context) error {
	b := c.rt.NewHostModuleBuilder("wbg")
	reg := func(name string, fn any) {
		b.NewFunctionBuilder().WithFunc(fn).Export(name)
	}

	// --- string getters: (retPtr, objRef) ---
	strGet := map[string]string{
		"__wbg_id_132bff2019d54f9b":                        "id",                        // root
		"__wbg_name_cc5ee25f09ba3aa8":                      "name",                      // application
		"__wbg_version_c9fa65a09e8f1a30":                   "version",                   // application
		"__wbg_useragent_6505dcf270d57903":                 "userAgent",                 // platform
		"__wbg_connectiontype_3112fd0d98ac3dec":            "connectionType",            // platform
		"__wbg_donottrack_f5c2455e439e075c":                "doNotTrack",                // platform
		"__wbg_mediacapabilities_3a72fdc21f3e886d":         "mediaCapabilities",         // platform (digest string)
		"__wbg_pluginsdigest_6a73e60e9437e249":             "pluginsDigest",             // platform
		"__wbg_sdkversion_249a89e640383480":                "sdkVersion",                // sdkInfo
		"__wbg_coreversion_e5fe91a030e0b256":               "coreVersion",               // sdkInfo
		"__wbg_platform_9fc8f7c7d727e853":                  "platform",                  // device ("web")
		"__wbg_osrelease_d0a467fa92cc59f4":                 "osRelease",                 // device
		"__wbg_ostype_634dc3998a49316b":                    "osType",                    // device
		"__wbg_systemname_4156ebc863a941ea":                "systemName",                // device
		"__wbg_systemversion_00a31990d1f546a4":             "systemVersion",             // device
		"__wbg_localecurrent_b12bfe81ca410a64":             "localeCurrent",             // device
		"__wbg_timezonecurrent_a0885f8ab4eb1620":           "timeZoneCurrent",           // device
		"__wbg_fontsdigest_27a46e6d62f85684":               "fontsDigest",               // device
		"__wbg_notificationapipermission_20fd5f68d6d62dd4": "notificationApiPermission", // webProperties
		"__wbg_manufacturer_b2fd6b5807e9a476":              "manufacturer",              // hardware
		"__wbg_model_0557b36f0cb2a747":                     "model",                     // hardware
		"__wbg_architecture_5082b6fda62b519c":              "architecture",              // hardware
	}
	for name, field := range strGet {
		reg(name, func(_ context.Context, ret, obj uint32) {
			c.writeStrRef(ret, fieldOf(c.obj(int(obj)), field))
		})
	}

	// --- bool getters: (objRef) -> i32, null sentinel 16777215 ---
	boolGet := map[string]string{
		"__wbg_cookiesenabled_0504c5d66902be97":       "cookiesEnabled",       // platform
		"__wbg_indexeddbenabled_27be5f165a578051":     "indexedDbEnabled",     // platform
		"__wbg_localstorageenabled_242246564737f8c4":  "localStorageEnabled",  // platform
		"__wbg_maybeheadless_8463675a9d52dd1e":        "maybeHeadless",        // platform
		"__wbg_multitouchdevice_e77de3dc92f84486":     "multiTouchDevice",     // platform
		"__wbg_webglenabled_4f1be6c840a847fb":         "webGlEnabled",         // platform
		"__wbg_automationcontrolled_815c329da612acbe": "automationControlled", // webProperties
		"__wbg_cellulardata_88db2dbb9f1c2b5a":         "cellular_data",        // network
	}
	for name, field := range boolGet {
		reg(name, func(_ context.Context, obj uint32) uint32 {
			switch v := fieldOf(c.obj(int(obj)), field).(type) {
			case bool:
				if v {
					return 1
				}
				return 0
			default:
				return boolNone // null/undefined/absent
			}
		})
	}

	// --- f64 getters: (objRef) -> f64 ---
	reg("__wbg_rtt_8ab385160aa3c9db", func(_ context.Context, obj uint32) float64 {
		return numOrNone(fieldOf(c.obj(int(obj)), "rtt"), true) // 0|g
	})
	reg("__wbg_cpucount_6ab9d000acffaa72", func(_ context.Context, obj uint32) float64 {
		return numOrNone(fieldOf(c.obj(int(obj)), "cpuCount"), true) // 0|g
	})
	reg("__wbg_displayscale_5c32b543658613df", func(_ context.Context, obj uint32) float64 {
		return numOrNone(fieldOf(c.obj(int(obj)), "displayScale"), false) // fround
	})
	reg("__wbg_displayphysicalscale_2c378b70a99e0b07", func(_ context.Context, obj uint32) float64 {
		return numOrNone(fieldOf(c.obj(int(obj)), "displayPhysicalScale"), false)
	})

	// --- i32 getters: width/height of a resolution object ---
	for _, nf := range [][2]string{{"__wbg_width_dd2866e2f34b27be", "width"}, {"__wbg_height_112346791e7c4d38", "height"}} {
		reg(nf[0], func(_ context.Context, obj uint32) uint32 {
			return toI32(fieldOf(c.obj(int(obj)), nf[1]))
		})
	}

	// --- object getters ---
	plainObjGet := map[string]string{ // null -> addHeapObject(null) (=129)
		"__wbg_application_4961057d054b547c":            "application",            // root
		"__wbg_platform_faeee9b8706420f5":               "platform",               // application (browser env obj)
		"__wbg_sdkinfo_88266dc7cc257da1":                "sdkInfo",                // application
		"__wbg_device_5ae6fbe5be4395d8":                 "device",                 // root
		"__wbg_hardware_b867d3be28b41431":               "hardware",               // root
		"__wbg_network_e1d708fa91f32257":                "network",                // root
		"__wbg_permissionsapistatuses_e4cb71caeac85df4": "permissionsApiStatuses", // webProperties
	}
	for name, field := range plainObjGet {
		reg(name, func(_ context.Context, obj uint32) uint32 {
			return uint32(c.addHeap(fieldOf(c.obj(int(obj)), field)))
		})
	}
	nullToZeroObjGet := map[string]string{ // null -> literal 0 (undefined ref), per the glue
		"__wbg_webproperties_095d36cc44901b5f":             "webProperties",             // device
		"__wbg_displayresolution_25871ac4ed4a63b5":         "displayResolution",         // hardware
		"__wbg_displayphysicalresolution_fe38c68fe13e128c": "displayPhysicalResolution", // hardware
	}
	for name, field := range nullToZeroObjGet {
		reg(name, func(_ context.Context, obj uint32) uint32 {
			v := fieldOf(c.obj(int(obj)), field)
			if v == nil {
				return nullObjRt
			}
			return uint32(c.addHeap(v))
		})
	}

	// --- localePreferred: array of strings -> u32 array of heap refs ---
	reg("__wbg_localepreferred_4ba0512585290373", func(_ context.Context, ret, obj uint32) {
		v := fieldOf(c.obj(int(obj)), "localePreferred")
		arr, ok := v.([]any)
		if !ok || v == nil {
			c.writeI32(ret+4, 0)
			c.writeI32(ret, 0)
			return
		}
		refs := c.malloc(uint32(4*len(arr)), 4)
		for i, s := range arr {
			c.writeI32(refs+uint32(4*i), uint32(c.addHeap(s)))
		}
		c.writeI32(ret+4, uint32(len(arr)))
		c.writeI32(ret, refs)
	})

	// --- memorySize: (retPtr, objRef); flag(ret+0)=isSome, i64(ret+8) ---
	reg("__wbg_memorysize_fb155033c73b6144", func(_ context.Context, ret, obj uint32) {
		if v, ok := fieldOf(c.obj(int(obj)), "memorySize").(int64); ok {
			c.writeI32(ret, 1)
			if !c.mem.WriteUint64Le(ret+8, uint64(v)) {
				panic(&jsThrow{msg: "memory write oob"})
			}
			return
		}
		c.writeI32(ret, 0)
		if !c.mem.WriteUint64Le(ret+8, 0) {
			panic(&jsThrow{msg: "memory write oob"})
		}
	})

	// --- wbindgen generic machinery ---
	reg("__wbindgen_object_drop_ref", func(_ context.Context, ref uint32) {
		c.dropHeap(int(ref))
	})
	reg("__wbg_new0_b0a0a38c201e6df5", func(_ context.Context) uint32 {
		return uint32(c.addHeap(jsDate{ms: float64(time.Now().UnixMilli())}))
	})
	reg("__wbg_getTime_6bb3f64e0f18f817", func(_ context.Context, ref uint32) float64 {
		if d, ok := c.obj(int(ref)).(jsDate); ok {
			return d.ms
		}
		return 0
	})
	reg("__wbg_now_c0af25a617c25393", func(_ context.Context) float64 {
		return float64(time.Now().UnixMilli())
	})
	reg("__wbg_iterator_f370b34483c71a1c", func(_ context.Context) uint32 {
		return uint32(c.addHeap(jsSymIter{}))
	})
	reg("__wbg_get_458e874b43b18b25", func(_ context.Context, obj, key uint32) uint32 {
		// Reflect.get(getObject(obj), getObject(key))
		target := c.obj(int(obj))
		switch k := c.obj(int(key)).(type) {
		case jsSymIter:
			return uint32(c.addHeap(&jsMethod{kind: "iterator"}))
		case string:
			if o, ok := target.(*jsObject); ok {
				return uint32(c.addHeap(o.get(k)))
			}
			return uint32(c.addHeap(jsUndefined()))
		default:
			return uint32(c.addHeap(jsUndefined()))
		}
	})
	reg("__wbg_call_13410aac570ffff7", func(_ context.Context, f, this uint32) uint32 {
		// f.call(getObject(this))
		m, ok := c.obj(int(f)).(*jsMethod)
		if !ok {
			panic(&jsThrow{msg: "call on non-function"})
		}
		switch m.kind {
		case "iterator":
			target := c.obj(int(this))
			items, ok := iterableItems(target)
			if !ok {
				panic(&jsThrow{msg: "object is not iterable"})
			}
			return uint32(c.addHeap(&jsIter{items: items}))
		case "next":
			if m.recv == nil {
				if it, ok := c.obj(int(this)).(*jsIter); ok {
					return uint32(c.addHeap(it.next()))
				}
				panic(&jsThrow{msg: "next() on non-iterator"})
			}
			return uint32(c.addHeap(m.recv.next()))
		default:
			panic(&jsThrow{msg: "unknown method call " + m.kind})
		}
	})
	reg("__wbg_next_5b3530e612fde77d", func(_ context.Context, it uint32) uint32 {
		// returns the iterator's `next` method as a heap ref
		iter, ok := c.obj(int(it)).(*jsIter)
		if !ok {
			panic(&jsThrow{msg: "next getter on non-iterator"})
		}
		return uint32(c.addHeap(&jsMethod{kind: "next", recv: iter}))
	})
	reg("__wbg_next_692e82279131b03c", func(_ context.Context, it uint32) uint32 {
		iter, ok := c.obj(int(it)).(*jsIter)
		if !ok {
			panic(&jsThrow{msg: "next() on non-iterator"})
		}
		return uint32(c.addHeap(iter.next()))
	})
	reg("__wbg_done_75ed0ee6dd243d9d", func(_ context.Context, res uint32) uint32 {
		if r, ok := c.obj(int(res)).(*jsIterResult); ok && r.done {
			return 1
		}
		return 0
	})
	reg("__wbg_value_dd9372230531eade", func(_ context.Context, res uint32) uint32 {
		if r, ok := c.obj(int(res)).(*jsIterResult); ok {
			return uint32(c.addHeap(r.value))
		}
		return uint32(c.addHeap(jsUndefined()))
	})
	reg("__wbg_entries_2be2f15bd5554996", func(_ context.Context, obj uint32) uint32 {
		// Object.entries(getObject(obj))
		o, ok := c.obj(int(obj)).(*jsObject)
		if !ok {
			panic(&jsThrow{msg: "entries on non-object"})
		}
		pairs := make([]any, 0, len(o.keys))
		for _, k := range o.keys {
			pairs = append(pairs, []any{k, o.vals[k]})
		}
		return uint32(c.addHeap(pairs))
	})
	for _, name := range []string{"__wbg_length_186546c51cd61acd", "__wbg_length_6bb7e81f9d7713e4"} {
		reg(name, func(_ context.Context, obj uint32) uint32 {
			return uint32(jsLength(c.obj(int(obj))))
		})
	}
	reg("__wbg_get_0da715ceaecea5c8", func(_ context.Context, obj, idx uint32) uint32 {
		// getObject(obj)[idx>>>0]
		switch v := c.obj(int(obj)).(type) {
		case []any:
			if int(idx) < len(v) {
				return uint32(c.addHeap(v[idx]))
			}
		case jsBytes:
			if int(idx) < len(v.data) {
				return uint32(c.addHeap(float64(v.data[idx])))
			}
		}
		return uint32(c.addHeap(jsUndefined()))
	})
	reg("__wbg_wbindgenisnull_f3037694abe4d97a", func(_ context.Context, ref uint32) uint32 {
		if _, ok := c.obj(int(ref)).(jsNullT); ok {
			return 1
		}
		return 0
	})
	reg("__wbg_wbindgenisundefined_c4b71d073b92f3c5", func(_ context.Context, ref uint32) uint32 {
		if _, ok := c.obj(int(ref)).(jsUndefT); ok {
			return 1
		}
		return 0
	})
	reg("__wbg_wbindgenisfunction_8cee7dce3725ae74", func(_ context.Context, ref uint32) uint32 {
		if _, ok := c.obj(int(ref)).(*jsMethod); ok {
			return 1
		}
		return 0
	})
	reg("__wbg_wbindgenisobject_307a53c6bd97fbf8", func(_ context.Context, ref uint32) uint32 {
		switch c.obj(int(ref)).(type) {
		case *jsObject, []any, jsBytes, *jsArrayBuf, jsDate, *jsErr, *jsIter, *jsIterResult:
			return 1
		}
		return 0
	})
	reg("__wbg_wbindgenjsvallooseeq_9bec8c9be826bed1", func(_ context.Context, a, b uint32) uint32 {
		if jsLooseEq(c.obj(int(a)), c.obj(int(b))) {
			return 1
		}
		return 0
	})
	reg("__wbg_wbindgenbooleanget_3fe6f642c7d97746", func(_ context.Context, ref uint32) uint32 {
		if v, ok := c.obj(int(ref)).(bool); ok {
			if v {
				return 1
			}
			return 0
		}
		return boolNone
	})
	reg("__wbg_wbindgennumberget_f74b4c7525ac05cb", func(_ context.Context, ret, obj uint32) {
		if v, ok := c.obj(int(obj)).(float64); ok {
			c.writeI32(ret, 1) // isSome
			c.writeF64(ret+8, v)
			return
		}
		c.writeI32(ret, 0)
		c.writeF64(ret+8, 0)
	})
	reg("__wbg_wbindgenstringget_0f16a6ddddef376f", func(_ context.Context, ret, obj uint32) {
		c.writeStrRef(ret, c.obj(int(obj)))
	})
	reg("__wbg_wbindgenthrow_451ec1a8469d7eb6", func(_ context.Context, ptr, n uint32) {
		b, ok := c.mem.Read(ptr, n)
		if !ok {
			b = []byte("(unreadable)")
		}
		panic(&jsThrow{msg: string(b)})
	})
	reg("__wbg_wbindgendebugstring_99ef257a3ddda34d", func(_ context.Context, ret, obj uint32) {
		ptr, n := c.passString(jsDebugString(c.obj(int(obj))))
		c.writeI32(ret+4, n)
		c.writeI32(ret, ptr)
	})
	reg("__wbg_instanceof_Uint8Array_9a8378d955933db7", func(_ context.Context, ref uint32) uint32 {
		if _, ok := c.obj(int(ref)).(jsBytes); ok {
			return 1
		}
		return 0
	})
	reg("__wbg_instanceof_ArrayBuffer_67f3012529f6a2dd", func(_ context.Context, ref uint32) uint32 {
		if _, ok := c.obj(int(ref)).(*jsArrayBuf); ok {
			return 1
		}
		return 0
	})
	reg("__wbg_new_638ebfaedbf32a5e", func(_ context.Context, ref uint32) uint32 {
		// new Uint8Array(getObject(ref))
		switch v := c.obj(int(ref)).(type) {
		case float64:
			n := int(v)
			if n < 0 {
				panic(&jsThrow{msg: "negative Uint8Array length"})
			}
			return uint32(c.addHeap(jsBytes{data: make([]byte, n)}))
		case *jsArrayBuf:
			d := make([]byte, len(v.data))
			copy(d, v.data)
			return uint32(c.addHeap(jsBytes{data: d}))
		case jsBytes:
			d := make([]byte, len(v.data))
			copy(d, v.data)
			return uint32(c.addHeap(jsBytes{data: d}))
		default:
			panic(&jsThrow{msg: "new Uint8Array from unsupported value"})
		}
	})
	reg("__wbg_getRandomValues_38097e921c2494c3", func(_ context.Context, ptr, n uint32) {
		// crypto.getRandomValues(memory[ptr:ptr+n])
		if n == 0 {
			return
		}
		buf, ok := c.mem.Read(ptr, n)
		if !ok {
			panic(&jsThrow{msg: "getRandomValues slice oob"})
		}
		if _, err := rand.Read(buf); err != nil {
			panic(&jsThrow{msg: "crypto/rand failed: " + err.Error()})
		}
	})
	reg("__wbg_prototypesetcall_3d4a26c1ed734349", func(_ context.Context, dst, dstLen, src uint32) {
		// Uint8Array.prototype.set.call(memory[dst:dst+dstLen], getObject(src)).
		// In spy mode the import is a pure observer (the hash-span spy
		// redirects HH-update call sites here with non-object args).
		if c.spyPrototypesetcall != nil {
			c.spyPrototypesetcall(dst, dstLen, src)
			if c.spyOnly {
				return
			}
		}
		v, ok := c.obj(int(src)).(jsBytes)
		if !ok {
			panic(&jsThrow{msg: "prototype set from non-Uint8Array"})
		}
		n := uint32(len(v.data))
		if n > dstLen {
			n = dstLen
		}
		c.writeBytes(dst, v.data[:n])
	})
	reg("__wbg_Error_e17e777aac105295", func(_ context.Context, ptr, n uint32) uint32 {
		b, ok := c.mem.Read(ptr, n)
		if !ok {
			b = nil
		}
		return uint32(c.addHeap(&jsErr{msg: string(b)}))
	})

	_, err := b.Instantiate(ctx)
	return err
}

// fieldOf reads a property off a heap object the way the glue does
// (`w(idx).field`); missing/absent properties read as Go nil (JS undefined).
func fieldOf(v any, field string) any {
	o, ok := v.(*jsObject)
	if !ok {
		return nil
	}
	out := o.get(field)
	if _, isU := out.(jsUndefT); isU {
		return nil
	}
	return out
}

func numOrNone(v any, toInt32 bool) float64 {
	f, ok := v.(float64)
	if !ok {
		return f64None
	}
	if toInt32 {
		return float64(int32(f))
	}
	return float64(float32(f))
}

func iterableItems(v any) ([]any, bool) {
	switch t := v.(type) {
	case []any:
		return t, true
	case *jsObject:
		pairs := make([]any, 0, len(t.keys))
		for _, k := range t.keys {
			pairs = append(pairs, []any{k, t.vals[k]})
		}
		return pairs, true
	default:
		return nil, false
	}
}

func (it *jsIter) next() *jsIterResult {
	if it.i >= len(it.items) {
		return &jsIterResult{done: true, value: jsUndefined()}
	}
	v := it.items[it.i]
	it.i++
	return &jsIterResult{done: false, value: v}
}

func jsLength(v any) int {
	switch t := v.(type) {
	case []any:
		return len(t)
	case jsBytes:
		return len(t.data)
	case string:
		// JS .length counts UTF-16 code units.
		n := 0
		for _, r := range t {
			n += utf16.RuneLen(r)
		}
		return n
	default:
		return 0
	}
}

func jsLooseEq(a, b any) bool {
	if _, ok := a.(jsNullT); ok {
		if _, ok2 := b.(jsNullT); ok2 {
			return true
		}
		if _, ok2 := b.(jsUndefT); ok2 {
			return true
		}
	}
	if _, ok := a.(jsUndefT); ok {
		if _, ok2 := b.(jsNullT); ok2 {
			return true
		}
	}
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case float64:
		bv, ok := b.(float64)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	}
	return a == b
}

func jsDebugString(v any) string {
	switch t := v.(type) {
	case nil:
		return "undefined"
	case jsUndefT:
		return "undefined"
	case jsNullT:
		return "null"
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case int64:
		return strconv.FormatInt(t, 10)
	case *jsErr:
		return "Error: " + t.msg
	case *jsObject:
		out := "Object({"
		for i, k := range t.keys {
			if i > 0 {
				out += ", "
			}
			out += strconv.Quote(k) + ":" + jsDebugString(t.vals[k])
		}
		return out + "})"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// ---------- wasm export wrappers ----------

// callStringExport runs a () -> string export (get_version / get_dispatch_id /
// get_default_endpoint) using the glue's ret-slot convention.
func (c *Core) callStringExport(ctx context.Context, name string) (ret string, err error) {
	defer func() {
		if r := recover(); r != nil {
			if te, ok := r.(*jsThrow); ok {
				err = te
			} else {
				panic(r)
			}
		}
	}()
	slot := c.addStackPointer(ctx, -16)
	defer c.addStackPointer(ctx, 16)
	if _, err := c.mod.ExportedFunction(name).Call(ctx, uint64(slot)); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	ptr, n := c.readI32(slot), c.readI32(slot+4)
	b, ok := c.mem.Read(ptr, n)
	if !ok {
		return "", fmt.Errorf("%s: result span oob", name)
	}
	ret = string(b)
	c.freeMem(ptr, n, 1)
	return ret, nil
}

func (c *Core) addStackPointer(ctx context.Context, delta int32) uint32 {
	r, err := c.mod.ExportedFunction("__wbindgen_add_to_stack_pointer").Call(ctx, uint64(uint32(delta)))
	if err != nil {
		panic(&jsThrow{msg: "add_to_stack_pointer: " + err.Error()})
	}
	return uint32(r[0])
}

// GetVersion returns the core's own version string (X-SDK-User-Agent "Core/…").
func (c *Core) GetVersion(ctx context.Context) (string, error) {
	return c.callStringExport(ctx, "get_version")
}

// GetDefaultEndpoint returns the signals endpoint the SDK POSTs to.
func (c *Core) GetDefaultEndpoint(ctx context.Context) (string, error) {
	return c.callStringExport(ctx, "get_default_endpoint")
}

// GetDispatchID returns a fresh dispatch UUID from the core itself (the same
// value the SDK puts in X-SDK-DispatchID and payload field 1).
func (c *Core) GetDispatchID(ctx context.Context) (string, error) {
	return c.callStringExport(ctx, "get_dispatch_id")
}

// GeneratePayload drives the real core exactly like the SDK: builds the
// signals object from Params, fetches a dispatch id (unless Params.DispatchID
// overrides it), and runs generate_payload. It returns the raw-deflate
// request body the SDK sends as application/vnd.prelude.signals, plus the
// dispatch id.
func (c *Core) GeneratePayload(ctx context.Context, p *Params) (body []byte, dispatchID string, err error) {
	p.Defaults()
	dispatchID = p.DispatchID
	if dispatchID == "" {
		if dispatchID, err = c.GetDispatchID(ctx); err != nil {
			return nil, "", err
		}
	}
	signals := c.buildSignals(p, dispatchID)

	defer func() {
		if r := recover(); r != nil {
			if te, ok := r.(*jsThrow); ok {
				body, dispatchID, err = nil, "", te
			} else {
				panic(r)
			}
		}
	}()

	slot := c.addStackPointer(ctx, -16)
	ref := c.pushJSStack(signals)
	_, callErr := c.mod.ExportedFunction("generate_payload").Call(ctx, uint64(slot), uint64(ref))
	c.popJSStack(ref)
	c.addStackPointer(ctx, 16)
	if callErr != nil {
		return nil, dispatchID, fmt.Errorf("generate_payload: %w", callErr)
	}
	ptr, n := c.readI32(slot), c.readI32(slot+4)
	out := make([]byte, n)
	if b, ok := c.mem.Read(ptr, n); ok {
		copy(out, b)
	} else {
		return nil, dispatchID, errors.New("generate_payload: result span oob")
	}
	c.freeMem(ptr, n, 1)
	return out, dispatchID, nil
}

// ---------- full dispatch request ----------

// DispatchRequest is everything needed to POST the payload the way the SDK
// does (entry82.js dispatchSignals/Bg). Body is the exact request bytes.
type DispatchRequest struct {
	// Endpoint is the signals URL from the wasm's get_default_endpoint
	// (unless Params overridden — the SDK allows opts.url).
	Endpoint string

	// Body is the raw-deflate protobuf returned by generate_payload: send it
	// verbatim as the request body.
	Body []byte

	// Headers, exactly as the SDK sets them:
	ContentType         string // "application/vnd.prelude.signals"
	ContentEncoding     string // "deflate" (raw DEFLATE, no zlib header)
	Connection          string // "close"
	SDKUserAgent        string // X-SDK-User-Agent  "Prelude/<sdk> Core/<core> (Web)"
	DispatchID          string // X-SDK-DispatchID  = payload field 1
	SDKKey              string // X-SDK-Key         (your key, passed through)
	RequestDate         string // X-SDK-Request-Date (RFC3339/ISO, like Date.toISOString())
	ImplementedFeatures string // X-SDK-Implemented-Features ("0" unless configured)
}

// PrepareDispatch assembles the complete HTTP request for the params: a
// fresh dispatch id (or Params.DispatchID), the payload body, endpoint and
// every header. The returned struct maps 1:1 onto an http.Request:
//
//	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, dr.Endpoint, bytes.NewReader(dr.Body))
//	dr.SetHeaders(req)
//	resp, _ := http.DefaultClient.Do(req)
func (c *Core) PrepareDispatch(ctx context.Context, p *Params, sdkKey string) (*DispatchRequest, error) {
	p.Defaults()
	endpoint, err := c.GetDefaultEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	body, dispatchID, err := c.GeneratePayload(ctx, p)
	if err != nil {
		return nil, err
	}
	dr := &DispatchRequest{
		Endpoint:            endpoint,
		Body:                body,
		ContentType:         "application/vnd.prelude.signals",
		ContentEncoding:     "deflate",
		Connection:          "close",
		SDKUserAgent:        c.SDKUserAgentOf(p),
		DispatchID:          dispatchID,
		SDKKey:              sdkKey,
		RequestDate:         time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		ImplementedFeatures: "0",
	}
	if p.ImplementedFeatures != 0 {
		dr.ImplementedFeatures = strconv.FormatUint(uint64(p.ImplementedFeatures), 10)
	}
	return dr, nil
}

// SetHeaders applies the SDK's header set onto req (the body/URL are yours
// to attach, see PrepareDispatch). Header names are set verbatim — bypassing
// Go's canonicalization — so the wire casing matches the SDK exactly.
func (dr *DispatchRequest) SetHeaders(req *http.Request) {
	h := map[string]string{
		"Content-Type":               dr.ContentType,
		"Content-Encoding":           dr.ContentEncoding,
		"Connection":                 dr.Connection,
		"X-SDK-User-Agent":           dr.SDKUserAgent,
		"X-SDK-DispatchID":           dr.DispatchID,
		"X-SDK-Key":                  dr.SDKKey,
		"X-SDK-Request-Date":         dr.RequestDate,
		"X-SDK-Implemented-Features": dr.ImplementedFeatures,
	}
	for k, v := range h {
		req.Header[k] = []string{v} // direct map assignment: preserves casing
	}
}

// SDKUserAgent mirrors the JS `uA()`: "Prelude/<sdk> Core/<core> (Web)",
// honouring Params overrides when set. (Convenience form using the wasm's
// own versions.)
func (c *Core) SDKUserAgentOf(p *Params) string {
	sdk := p.SDKVersion
	if sdk == "" {
		sdk = sdkJSVer
	}
	coreVer := p.CoreVersion
	if coreVer == "" {
		coreVer = c.coreVersion
	}
	return "Prelude/" + sdk + " Core/" + coreVer + " (Web)"
}
