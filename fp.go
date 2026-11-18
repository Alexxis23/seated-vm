// Package fpbot generates the Prelude (Seated) SDK hash-input buffer from
// per-browser parameters, and computes the SDK's HighwayHash-128 exactly as
// the wasm core does (4-lane layout, zero key). Everything here was reversed
// from the wasm core and validated byte-exact against the real implementation.
//
// Core rule for the fonts zone (the previously unknown part):
//
//	model   = join("::", sort(brand + "-" + version for fullVersionList))
//	k[i]    = (-modelUTF8[i mod len(model)]) & 7
//	zone[i] = rotl8(digestASCII[i], k[i])   for i = 0..63
package seatedvm

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sort"
	"strings"
)

// ---------- byte transforms (same semantics as the wasm builders) ----------

var (
	bitrevTable [256]byte
	rol1Table   [256]byte
	ror1Table   [256]byte
	rol2Table   [256]byte
	ror2Table   [256]byte
)

func init() {
	for i := 0; i < 256; i++ {
		bitrevTable[i] = revBits(byte(i))
		rol1Table[i] = rotl8(byte(i), 1)
		ror1Table[i] = rotr8(byte(i), 1)
		rol2Table[i] = rotl8(byte(i), 2)
		ror2Table[i] = rotr8(byte(i), 2)
	}
}

func revBits(b byte) byte {
	var r byte
	for k := 0; k < 8; k++ {
		r |= ((b >> uint(k)) & 1) << uint(7-k)
	}
	return r
}

func rotl8(b byte, k int) byte {
	k &= 7
	if k == 0 {
		return b
	}
	return (b << uint(k)) | (b >> uint(8-k))
}

func rotr8(b byte, k int) byte {
	k &= 7
	if k == 0 {
		return b
	}
	return (b >> uint(k)) | (b << uint(8-k))
}

func mapBytes(s string, t [256]byte) []byte {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		out[i] = t[s[i]]
	}
	return out
}

// ---------- locale cipher (cracked: fixed per-position rotations) ----------

var localeKeys = [5]byte{3, 0, 2, 7, 5}

func localeCipher(locale string) []byte {
	out := make([]byte, 5)
	for i := 0; i < 5 && i < len(locale); i++ {
		out[i] = rotl8(locale[i], int(localeKeys[i]))
	}
	return out
}

// ---------- FVL-derived identity ----------

// FVLEntry is one fullVersionList entry.
type FVLEntry struct {
	Brand   string
	Version string
}

// FVLIdentity carries everything the buffer needs from fullVersionList.
type FVLIdentity struct {
	SystemName      string   // FVL[0].brand
	SystemVersion   string   // FVL[0].version
	Manufacturer    string   // sorted brands joined by "::"
	Model           string   // sorted "brand-version" joined by "::"
	Keystream       []byte   // fonts-zone rotations, derived from Model
}

func FVLIdentityOf(fvl []FVLEntry) FVLIdentity {
	brands := make([]string, len(fvl))
	bv := make([]string, len(fvl))
	for i, e := range fvl {
		brands[i] = e.Brand
		bv[i] = e.Brand + "-" + e.Version
	}
	sort.Strings(brands)
	sort.Strings(bv)
	id := FVLIdentity{
		SystemName:    fvl[0].Brand,
		SystemVersion: fvl[0].Version,
		Manufacturer:  strings.Join(brands, "::"),
		Model:         strings.Join(bv, "::"),
	}
	id.Keystream = Keystream(id.Model)
	return id
}

// Keystream returns the fonts-zone rotation schedule:
// k[i] = (-modelUTF8[i mod len(model)]) & 7
func Keystream(model string) []byte {
	m := []byte(model)
	k := make([]byte, len(m))
	for i, c := range m {
		k[i] = (-c) & 7
	}
	return k
}

// FontsZone rotates the 64-char hex digest with the keystream.
func FontsZone(digestHex string, model string) []byte {
	k := Keystream(model)
	d := []byte(digestHex)
	z := make([]byte, 64)
	for i := 0; i < 64; i++ {
		z[i] = rotl8(d[i], int(k[i%len(k)]))
	}
	return z
}

// ---------- optional digest helpers ----------

// MediaDigest is sha256 over the codec:support list (default Chrome set).
func MediaDigest(allSupported bool) string {
	codecs := []string{
		"audio/ogg; codecs=vorbis",
		"audio/ogg; codecs=flac",
		`audio/mp4; codecs="mp4a.40.2"`,
		`audio/mpeg; codecs="mp3"`,
		`video/mp4; codecs="avc1.42E01E"`,
	}
	val := "false"
	if allSupported {
		val = "true"
	}
	parts := make([]string, len(codecs))
	for i, c := range codecs {
		parts[i] = c + ":" + val
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "::")))
	return hexStr(sum[:])
}

// PluginsDigest is sha256 over lowercased sorted plugin names joined by "::".
func PluginsDigest(names []string) string {
	low := make([]string, len(names))
	for i, n := range names {
		low[i] = strings.ToLower(n)
	}
	sort.Strings(low)
	sum := sha256.Sum256([]byte(strings.Join(low, "::")))
	return hexStr(sum[:])
}

func hexStr(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0xF]
	}
	return string(out)
}

// ---------- permissions ----------

// PermNames is the full query list, already sorted (buffer order = sorted).
var PermNames = []string{
	"accelerometer", "ambient-light-sensor", "background-sync", "bluetooth",
	"camera", "captured-surface-control", "clipboard-read", "clipboard-write",
	"compute-pressure", "display-capture", "geolocation", "gyroscope",
	"local-fonts", "magnetometer", "microphone", "midi", "notifications",
	"payment-handler", "persistent-storage", "push", "screen-wake-lock",
	"storage-access", "top-level-storage-access", "window-management",
}

// ---------- parameters ----------

// Params: every field that can differ per browser/profile. Zero-value plus
// the required fields (FontsDigest, UserAgent) is a valid Chrome-156-like
// profile after Defaults() fills the optionals.
type Params struct {
	AppVersion  string    // optional; empty -> absent from buffer
	TZ          string    // IANA timezone, e.g. "Europe/Warsaw"
	FVL         []FVLEntry // fullVersionList (overrides the 4 explicit fields below)
	Model       string    // explicit override (if FVL empty)
	Manufacturer string
	SystemName  string
	SystemVersion string

	OSType string // "Windows", "MacOS", ... (written bitrev'd)
	Arch   string // "x86", "arm" ... (written rol2'd)

	FontsDigest string // 64 hex chars (sha256 of the font-probe string) — REQUIRED
	UserAgent   string // REQUIRED

	Locale    string   // 5 chars, e.g. "pl-PL"
	Languages []string // concatenated raw into the buffer

	HardwareConcurrency uint32
	MemoryGiB           uint32 // written as GiB/8

	ScreenW, ScreenH   uint32 // physical
	InnerW, InnerH     uint32 // window
	DevicePixelRatio   float32

	ConnType string // optional; presence adds 4 bytes to the buffer
	RTT      uint32

	Cookies      bool
	LocalStorage bool
	IndexedDB    bool
	DoNotTrack   string // optional; empty -> absent
	MultiTouch   bool

	MediaDigest   string // 64 hex; empty -> default Chrome set
	PluginsDigest string // 64 hex; empty -> default Chrome PDF plugins

	Hostname     string
	OSRelease    string // e.g. "10.0.0" (platformVersion); default "10.0.0"
	Automation   bool
	Notification string // "default" | "granted" | "denied"

	Granted  []string // permission names with state 1 (others 3)
	Throwing []string // permission names ABSENT from the buffer (query threw)
}

// Defaults fills a Chrome-156-like profile into p (only fills empty fields).
func (p *Params) Defaults() {
	if p.TZ == "" {
		p.TZ = "Europe/Warsaw"
	}
	if len(p.FVL) == 0 && p.Model == "" {
		p.FVL = []FVLEntry{
			{"Not:A-Brand", "8.0.0.0"},
			{"Chromium", "156.0.8078.80"},
			{"Google Chrome", "156.0.8078.80"},
		}
	}
	if p.OSType == "" {
		p.OSType = "Windows"
	}
	if p.Arch == "" {
		p.Arch = "x86"
	}
	if p.Locale == "" {
		p.Locale = "pl-PL"
	}
	if len(p.Languages) == 0 {
		lang := strings.SplitN(p.Locale, "-", 2)[0]
		p.Languages = []string{p.Locale, lang, "en-US", "en"}
	}
	if p.HardwareConcurrency == 0 {
		p.HardwareConcurrency = 4
	}
	if p.MemoryGiB == 0 {
		p.MemoryGiB = 16
	}
	if p.ScreenW == 0 {
		p.ScreenW, p.ScreenH = 1920, 1080
	}
	if p.InnerW == 0 {
		p.InnerW, p.InnerH = 958, 896
	}
	if p.DevicePixelRatio == 0 {
		p.DevicePixelRatio = 1.0
	}
	if p.RTT == 0 {
		p.RTT = 200
	}
	if p.MediaDigest == "" {
		p.MediaDigest = MediaDigest(true)
	}
	if p.PluginsDigest == "" {
		p.PluginsDigest = PluginsDigest([]string{
			"PDF Viewer", "Chrome PDF Viewer", "Chromium PDF Viewer",
			"Microsoft Edge PDF Viewer", "WebKit built-in PDF"})
	}
	if p.Hostname == "" {
		p.Hostname = "go.seated.com"
	}
	if p.Notification == "" {
		p.Notification = "default"
	}
	if p.OSRelease == "" {
		p.OSRelease = "10.0.0"
	}
	if len(p.Granted) == 0 && len(p.Throwing) == 0 {
		p.Granted = []string{"payment-handler", "gyroscope", "clipboard-write",
			"screen-wake-lock", "accelerometer", "background-sync",
			"storage-access", "magnetometer"}
		p.Throwing = []string{"ambient-light-sensor", "bluetooth",
			"compute-pressure", "push", "top-level-storage-access"}
	}
}

// Build produces the full hash-input buffer.
func (p *Params) Build() []byte {
	p.Defaults()

	id := FVLIdentityOf(p.FVL)
	if len(p.FVL) == 0 { // explicit model override
		id = FVLIdentity{Model: p.Model, Keystream: Keystream(p.Model)}
		id.SystemName, id.SystemVersion = p.SystemName, p.SystemVersion
		id.Manufacturer = p.Manufacturer
	}

	var out []byte
	put := func(b ...byte) { out = append(out, b...) }
	putStr := func(s string) { out = append(out, s...) }

	if p.AppVersion != "" {
		out = append(out, mapBytes(p.AppVersion, rol2Table)...)
	}
	putStr(p.TZ)
	out = append(out, mapBytes(id.Manufacturer, ror1Table)...)
	out = append(out, mapBytes(p.OSType, bitrevTable)...)
	put(0x03, 0x00, 0x00, 0x00)
	out = append(out, mapBytes(p.Arch, rol2Table)...)
	out = append(out, FontsZone(p.FontsDigest, id.Model)...)
	put(byte(p.HardwareConcurrency), 0, 0, 0)
	out = append(out, localeCipher(p.Locale)...)
	for _, l := range p.Languages {
		putStr(l)
	}
	out = append(out, mapBytes(p.UserAgent, bitrevTable)...)
	if p.ConnType != "" {
		out = append(out, mapBytes(p.ConnType, bitrevTable)...)
	}
	put(0, 0, 0, bitrevTable[byte(p.RTT)])
	if p.Cookies {
		put(bitrevTable[1])
	} else {
		put(0)
	}
	if p.LocalStorage {
		put(bitrevTable[1])
	} else {
		put(0)
	}
	if p.IndexedDB {
		put(bitrevTable[1])
	} else {
		put(0)
	}
	if p.DoNotTrack != "" {
		out = append(out, mapBytes(p.DoNotTrack, bitrevTable)...)
	}
	if p.MultiTouch {
		put(bitrevTable[1])
	} else {
		put(0)
	}
	out = append(out, mapBytes(p.MediaDigest, bitrevTable)...)
	out = append(out, mapBytes(p.PluginsDigest, bitrevTable)...)
	put(0)
	out = append(out, mapBytes(id.SystemName, ror2Table)...)
	putStr(p.Hostname)
	out = append(out, mapBytes(p.Arch, rol2Table)...)
	putStr(id.SystemVersion)
	out = append(out, u32le(p.ScreenW)...)
	out = append(out, u32le(p.ScreenH)...)
	mem := p.MemoryGiB / 8
	put(0, 0, 0, 0, byte(mem), 0, 0, 0)
	putStr(p.OSRelease)
	putStr(id.Model)
	out = append(out, mapU32BytesBitrev(p.InnerW)...)
	out = append(out, mapU32BytesBitrev(p.InnerH)...)
	out = append(out, f32le(p.DevicePixelRatio)...)
	out = append(out, f32le(p.DevicePixelRatio)...)
	if p.Automation {
		put(bitrevTable[1])
	} else {
		put(0)
	}
	out = append(out, mapBytes(p.Notification, ror1Table)...)

	granted := map[string]bool{}
	for _, g := range p.Granted {
		granted[g] = true
	}
	throwing := map[string]bool{}
	for _, t := range p.Throwing {
		throwing[t] = true
	}
	names := append([]string{}, PermNames...)
	sort.Strings(names)
	for _, n := range names {
		if throwing[n] {
			continue
		}
		out = append(out, mapBytes(n, ror1Table)...)
		state := byte(3)
		if granted[n] {
			state = 1
		}
		put(0, 0, 0, ror1Table[state])
	}
	return out
}

func u32le(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

func f32le(v float32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], math.Float32bits(v))
	return b[:]
}

func mapU32BytesBitrev(v uint32) []byte {
	b := u32le(v)
	for i := range b {
		b[i] = bitrevTable[b[i]]
	}
	return b
}
