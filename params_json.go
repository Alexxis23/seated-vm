package seatedvm

// ParamsFromJSON maps the bot-friendly env JSON (same schema as
// out/env_example.json) into Params. Explicit fields (model/manufacturer/
// systemName/systemVersion) override the fullVersionList derivation.
func ParamsFromJSON(j map[string]any) *Params {
	p := &Params{}
	getS := func(k string) string {
		if v, ok := j[k].(string); ok {
			return v
		}
		return ""
	}
	getU32 := func(k string) uint32 {
		if v, ok := j[k].(float64); ok {
			return uint32(v)
		}
		return 0
	}
	if v, ok := j["appVersion"].(string); ok {
		p.AppVersion = v
	}
	p.TZ = getS("tz")
	if fvl, ok := j["fullVersionList"].([]any); ok {
		for _, e := range fvl {
			em, _ := e.(map[string]any)
			b, _ := em["brand"].(string)
			v, _ := em["version"].(string)
			p.FVL = append(p.FVL, FVLEntry{Brand: b, Version: v})
		}
	}
	if m := getS("model"); m != "" {
		p.Model = m
	}
	p.Manufacturer = getS("manufacturer")
	p.SystemName = getS("systemName")
	p.SystemVersion = getS("systemVersion")
	p.OSType = getS("osType")
	p.Arch = getS("arch")
	p.FontsDigest = getS("fontsDigest")
	p.UserAgent = getS("userAgent")
	p.Locale = getS("locale")
	if langs, ok := j["languages"].([]any); ok {
		for _, l := range langs {
			if s, ok := l.(string); ok {
				p.Languages = append(p.Languages, s)
			}
		}
	}
	p.HardwareConcurrency = getU32("hardwareConcurrency")
	p.MemoryGiB = getU32("deviceMemory")
	if sc, ok := j["screen"].([]any); ok && len(sc) == 2 {
		w, _ := sc[0].(float64)
		h, _ := sc[1].(float64)
		p.ScreenW, p.ScreenH = uint32(w), uint32(h)
	}
	if in, ok := j["inner"].([]any); ok && len(in) == 2 {
		w, _ := in[0].(float64)
		h, _ := in[1].(float64)
		p.InnerW, p.InnerH = uint32(w), uint32(h)
	}
	if d, ok := j["devicePixelRatio"].(float64); ok {
		p.DevicePixelRatio = float32(d)
	}
	if conn, ok := j["connection"].(map[string]any); ok {
		if r, ok := conn["rtt"].(float64); ok {
			p.RTT = uint32(r)
		}
		p.ConnType = getS("connType")
		if t, ok := conn["type"].(string); ok {
			p.ConnType = t
		}
	}
	p.Cookies = getBool(j, "cookies", true)
	p.LocalStorage = getBool(j, "localStorage", true)
	p.IndexedDB = getBool(j, "indexedDB", true)
	p.DoNotTrack = getS("doNotTrack")
	if mt, ok := j["multiTouch"].(bool); ok {
		p.MultiTouch = mt
	}
	p.MediaDigest = getS("mediaDigest")
	p.PluginsDigest = getS("pluginsDigest")
	p.Hostname = getS("hostname")
	p.OSRelease = getS("osRelease")
	if a, ok := j["automation"].(bool); ok {
		p.Automation = a
	}
	p.Notification = getS("notification")
	if g, ok := j["granted"].([]any); ok {
		for _, x := range g {
			if s, ok := x.(string); ok {
				p.Granted = append(p.Granted, s)
			}
		}
	}
	if th, ok := j["throwing"].([]any); ok {
		for _, x := range th {
			if s, ok := x.(string); ok {
				p.Throwing = append(p.Throwing, s)
			}
		}
	}
	return p
}

func getBool(j map[string]any, k string, def bool) bool {
	if v, ok := j[k].(bool); ok {
		return v
	}
	return def
}
