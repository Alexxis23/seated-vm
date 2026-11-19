package seatedvm

// signals.go — builds the "signals" object exactly the way the SDK's JS
// collector classes do (entry82.js: Ig/OA/_A/jA/VA/Ag/gg) before handing it
// to the wasm's generate_payload. Field names are the wasm's own read keys
// (the __wbg_* getter names), so any mismatch shows up as a missing value in
// the payload rather than silently diverging bytes.

// StateName maps a numeric permission state (the Params.PermissionStates
// encoding: 1=granted, 3=prompt) to the JS PermissionStatus.state string the
// browser reports. 2 is treated as "denied" (no live capture has exercised
// it; if you have a browser reporting a denied permission, verify against it).
func StateName(b byte) string {
	switch b {
	case 1:
		return "granted"
	case 2:
		return "denied"
	default:
		return "prompt"
	}
}

// buildSignals mirrors Ig.collect: {id, application, device, hardware, network}.
// Every field resolves as: explicit Params override → browser-accurate
// derivation → absent/null, so any real-browser value can be pinned down.
func (c *Core) buildSignals(p *Params, dispatchID string) *jsObject {
	root := newJSObject()
	root.set("id", dispatchID)
	root.set("application", buildApplication(p, c.coreVersion))
	root.set("device", buildDevice(p))
	root.set("hardware", buildHardware(p))
	root.set("network", buildNetwork(p))
	return root
}

// buildApplication mirrors OA.collect(name=location.hostname, version=appVersion,
// platform=await _A.collect(), implementedFeatures=0, sdkInfo={sdkVersion: fA, coreVersion}).
func buildApplication(p *Params, wasmCoreVersion string) *jsObject {
	app := newJSObject()
	app.set("name", p.Hostname) // window.location.hostname
	if p.AppVersion == "" {
		app.set("version", nil) // I ?? null
	} else {
		app.set("version", p.AppVersion)
	}
	app.set("platform", buildPlatformEnv(p)) // _A.collect()
	app.set("implementedFeatures", float64(p.ImplementedFeatures))
	sdkInfo := newJSObject()
	if p.SDKVersion != "" {
		sdkInfo.set("sdkVersion", p.SDKVersion)
	} else {
		sdkInfo.set("sdkVersion", sdkJSVer)
	}
	if p.CoreVersion != "" {
		sdkInfo.set("coreVersion", p.CoreVersion)
	} else {
		sdkInfo.set("coreVersion", wasmCoreVersion)
	}
	app.set("sdkInfo", sdkInfo)
	return app
}

// buildPlatformEnv mirrors _A.collect(): the browser-environment object read
// through the platform.* getters (connectionType/rtt/…/userAgent/webGlEnabled).
func buildPlatformEnv(p *Params) *jsObject {
	env := newJSObject()
	hasConn := p.ConnType != "" || p.RTT > 0 // navigator.connection present?
	if hasConn && p.ConnType != "" {
		env.set("connectionType", p.ConnType)
	} else {
		env.set("connectionType", nil) // I.type is undefined when absent
	}
	env.set("cookiesEnabled", p.Cookies)
	if p.DoNotTrack == "" {
		env.set("doNotTrack", nil)
	} else {
		env.set("doNotTrack", p.DoNotTrack)
	}
	env.set("indexedDbEnabled", p.IndexedDB)
	env.set("localStorageEnabled", p.LocalStorage)
	if p.MaybeHeadless != nil {
		env.set("maybeHeadless", *p.MaybeHeadless)
	} else {
		// The real collector never assigns maybeHeadless — leave the
		// property absent (undefined); the wasm then skips its buffer byte.
		env.set("maybeHeadless", nil)
	}
	env.set("mediaCapabilities", p.MediaDigest) // sha256 hex string from getMediaCapabilities()
	env.set("multiTouchDevice", p.MultiTouch)
	if p.PluginsDigest == "" {
		env.set("pluginsDigest", nil) // getPlugins() returned null
	} else {
		env.set("pluginsDigest", p.PluginsDigest)
	}
	if hasConn {
		env.set("rtt", float64(p.RTT))
	} else {
		env.set("rtt", nil)
	}
	env.set("userAgent", p.UserAgent)
	env.set("webGlEnabled", p.PostPluginsFlag) // the buffer's "post-plugins flag" byte
	return env
}

// buildDevice mirrors jA.collect(uaData): fonts/locale/os/system/timezone/webProperties.
func buildDevice(p *Params) *jsObject {
	id := identityOf(p)

	dev := newJSObject()
	dev.set("fontsDigest", p.FontsDigest)
	if p.Origin != "" {
		dev.set("hostname", p.Origin) // window.location.origin (never read by the wasm)
	} else {
		dev.set("hostname", "https://"+p.Hostname)
	}
	dev.set("localeCurrent", p.Locale) // navigator.language
	langs := make([]any, len(p.Languages))
	for i, l := range p.Languages {
		langs[i] = l
	}
	dev.set("localePreferred", langs) // navigator.languages.slice()
	if p.OSRelease == "" {
		dev.set("osRelease", nil) // uaData?.platformVersion ?? null
	} else {
		dev.set("osRelease", p.OSRelease)
	}
	dev.set("osType", p.OSType)
	if p.DevicePlatform != "" {
		dev.set("platform", p.DevicePlatform) // always "web" in the real SDK
	} else {
		dev.set("platform", "web")
	}
	if id.SystemName == "" {
		dev.set("systemName", nil) // fullVersionList[0]?.brand ?? null
	} else {
		dev.set("systemName", id.SystemName)
	}
	if id.SystemVersion == "" {
		dev.set("systemVersion", nil) // fullVersionList[0]?.version ?? null
	} else {
		dev.set("systemVersion", id.SystemVersion)
	}
	dev.set("timeZoneCurrent", p.TZ)
	dev.set("webProperties", buildWebProperties(p))
	return dev
}

// buildWebProperties mirrors VA.collect(): automation + notification +
// per-name permission states (a plain object; throwing names are absent).
func buildWebProperties(p *Params) *jsObject {
	wp := newJSObject()
	wp.set("automationControlled", p.Automation) // "webdriver" in navigator ? navigator.webdriver : null
	if p.Notification == "" {
		wp.set("notificationApiPermission", nil)
	} else {
		wp.set("notificationApiPermission", p.Notification)
	}
	wp.set("permissionsApiStatuses", buildPermissionStatuses(p))
	return wp
}

// buildPermissionStatuses mirrors VA.queryPermissions(): {name: state-string},
// throwing names absent entirely; names sorted for deterministic iteration
// (the wasm serializes them into its own HashMap anyway).
func buildPermissionStatuses(p *Params) *jsObject {
	granted := map[string]bool{}
	for _, g := range p.Granted {
		granted[g] = true
	}
	throwing := map[string]bool{}
	for _, t := range p.Throwing {
		throwing[t] = true
	}
	states := newJSObject()
	for _, n := range PermNames {
		if throwing[n] {
			continue
		}
		state := byte(3)
		if granted[n] {
			state = 1
		}
		if p.PermissionStates != nil {
			if s, ok := p.PermissionStates[n]; ok {
				state = s
			}
		}
		states.set(n, StateName(state))
	}
	return states
}

// buildHardware mirrors Ag.collect(uaData): arch/cpu/displays/memory/model.
func buildHardware(p *Params) *jsObject {
	id := identityOf(p)

	hw := newJSObject()
	if p.Arch == "" {
		hw.set("architecture", nil)
	} else {
		hw.set("architecture", p.Arch)
	}
	if p.HardwareConcurrency > 0 { // JS: navigator.hardwareConcurrency && (cpuCount = …)
		hw.set("cpuCount", float64(p.HardwareConcurrency))
	} else {
		hw.set("cpuCount", nil)
	}
	hw.set("displayPhysicalResolution", resolution(float64(p.ScreenW), float64(p.ScreenH)))
	hw.set("displayPhysicalScale", float64(float32(p.DevicePixelRatio))) // Math.fround
	hw.set("displayResolution", resolution(float64(p.InnerW), float64(p.InnerH)))
	hw.set("displayScale", float64(float32(p.DevicePixelRatio)))
	hw.set("manufacturer", id.Manufacturer) // vA(brands) = sort().join("::")
	if p.MemoryGiB > 0 {                    // JS: "deviceMemory" in navigator && (memorySize = BigInt)
		hw.set("memorySize", int64(p.MemoryGiB)*1024*1024*1024) // bytes; 16 GiB = 17179869184
	} else {
		hw.set("memorySize", nil)
	}
	hw.set("model", id.Model) // vA(brand-version)
	return hw
}

// buildNetwork mirrors gg.collect(): cellularData only when connection.type is known.
func buildNetwork(p *Params) *jsObject {
	net := newJSObject()
	if p.CellularData != nil {
		// explicit override wins (adapting to a browser whose connection
		// classification differs from the type string)
		net.set("cellular_data", *p.CellularData)
		return net
	}
	switch p.ConnType {
	case "cellular":
		net.set("cellular_data", true)
	case "bluetooth", "ethernet", "none", "wifi", "wimax":
		net.set("cellular_data", false)
	default:
		// field stays undefined (connection absent or unknown type)
	}
	return net
}

func resolution(w, h float64) *jsObject {
	r := newJSObject()
	r.set("width", w)
	r.set("height", h)
	return r
}

// identityOf resolves the FVL-derived identity, honouring Params' explicit
// overrides the same way Build() does.
func identityOf(p *Params) FVLIdentity {
	if len(p.FVL) > 0 {
		return FVLIdentityOf(p.FVL)
	}
	id := FVLIdentity{Model: p.Model, Keystream: Keystream(p.Model)}
	id.SystemName, id.SystemVersion = p.SystemName, p.SystemVersion
	id.Manufacturer = p.Manufacturer
	return id
}
