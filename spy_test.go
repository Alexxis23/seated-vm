package seatedvm

import (
	"bytes"
	"context"
	"fmt"
	"testing"
)

// spyCore builds a core with the two `call 114` (HH update) call sites at
// code offsets 0x1da4b / 0x1dd6f redirected to import 68
// (__wbg_prototypesetcall) — the same binary-patch technique the repo used
// in harness_tmp/run11.mjs. Our own import then observes the exact spans the
// wasm feeds into HighwayHash. This is the tool that cracked the
// webGlEnabled/maybeHeadless byte semantics; keep it for future SDK versions.
func spyCore(ctx context.Context, log *bytes.Buffer) (*Core, error) {
	blob, err := CoreWasm()
	if err != nil {
		return nil, err
	}
	patched := make([]byte, len(blob))
	copy(patched, blob)
	patched[0x1da4c] = 68 // call 114 -> call 68
	patched[0x1dd70] = 68 // call 114 -> call 68 (2nd site)

	core, err := NewCoreFromWasm(ctx, patched)
	if err != nil {
		return nil, err
	}
	core.spyOnly = true
	var span []byte
	core.spyPrototypesetcall = func(a, b, c uint32) {
		m := core.mod.Memory()
		fmt.Fprintf(log, "spy args: a=%d b=%d c=%d\n", a, b, c)
		// run13-proven interpretation: the span is memory[b .. b+c].
		if c > 4 && c < 65536 && b > 0 && int(b)+int(c) <= int(m.Size()) {
			if raw, ok := m.Read(b, c); ok {
				keep := make([]byte, len(raw))
				copy(keep, raw)
				span = keep
			}
		}
	}
	core.spySpan = &span
	return core, nil
}

// TestSpyHashSpan dumps the span the real wasm hashes for the sig86 capture
// environment and asserts it equals Params.Build() byte-for-byte.
func TestSpyHashSpan(t *testing.T) {
	ctx := context.Background()
	log := &bytes.Buffer{}
	core, err := spyCore(ctx, log)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close(ctx)

	p := sig86Params()
	p.PostPluginsFlag = true // real headed Chrome: WebGL present
	if _, _, err := core.GeneratePayload(ctx, p); err != nil {
		t.Fatalf("GeneratePayload: %v", err)
	}
	t.Logf("spy events:\n%s", log.String())

	span := *core.spySpan
	if span == nil {
		t.Fatal("spy captured no span")
	}
	buf := p.Build()
	t.Logf("span: %d bytes, Build(): %d bytes", len(span), len(buf))
	if !bytes.Equal(span, buf) {
		n := len(span)
		if len(buf) < n {
			n = len(buf)
		}
		for i := 0; i < n; i++ {
			if span[i] != buf[i] {
				t.Fatalf("span diverges from Build() at %d: wasm=%02x build=%02x", i, span[i], buf[i])
			}
		}
		t.Fatalf("span (%d) and Build() (%d) differ in length", len(span), len(buf))
	}
}
