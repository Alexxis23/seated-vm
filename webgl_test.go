package seatedvm

import (
	"testing"
)

// TestWebGLByteHypothesis: the real browser captures (sig86/sig92) should be
// HH128 over the same buffer but with the webGlEnabled byte set (bitrev(1)),
// since a real Chrome has WebGL while the Node harness used for the spy
// captures does not.
func TestWebGLByteHypothesis(t *testing.T) {
	p := sig86Params()

	// Node-harness variant (webGl off) — what the repo's golden captured.
	bufNoGL := p.Build()
	hNoGL := HHHex(bufNoGL)
	t.Logf("HH(buffer, webGl=0) = %s", hNoGL)

	// Real-browser variant (webGl on).
	p2 := sig86Params()
	p2.PostPluginsFlag = true
	bufGL := p2.Build()
	hGL := HHHex(bufGL)
	t.Logf("HH(buffer, webGl=1) = %s", hGL)

	if len(bufGL) != len(bufNoGL) {
		t.Fatalf("lengths differ: %d vs %d", len(bufGL), len(bufNoGL))
	}
	diffs := []int{}
	for i := range bufGL {
		if bufGL[i] != bufNoGL[i] {
			diffs = append(diffs, i)
		}
	}
	t.Logf("buffer diffs at offsets %v", diffs)

	if hGL != "fb777997a04a586c219bb6d424fcc0c4" {
		t.Errorf("webGl=1 fingerprint = %s, want fb777997… (real sig86)", hGL)
	}

	// sig92: same env, rtt=100.
	p3 := sig86Params()
	p3.PostPluginsFlag = true
	p3.RTT = 100
	if h := HHHex(p3.Build()); h != "6716c0f443514fa27326ea3b40cbcacc" {
		t.Errorf("rtt=100 webGl=1 fingerprint = %s, want 6716c0f4… (real sig92)", h)
	}
}
