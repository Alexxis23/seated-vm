package seatedvm

// HighwayHash-128 exactly as implemented in the SDK wasm (funcs 114/141/169/121):
// 4-lane state v0[4], v1[4], mul0[4], mul1[4], zero key (the pi constants),
// 32-byte packets, scalar-emulated AVX2 zipper-merge, 6 permute rounds on
// finalization. Validated byte-exact against the live wasm (sdk/oracle/hh_oracle.wasm).

import "encoding/binary"

var hhInit0 = [4]uint64{0xdbe6d5d5fe4cce2f, 0xa4093822299f31d0, 0x13198a2e03707344, 0x243f6a8885a308d3}
var hhInit1 = [4]uint64{0x3bd39e10cb0ef593, 0xc0acf169b5f18a8c, 0xbe5466cf34e90c6c, 0x452821e638d01377}

type hhState struct {
	v0, v1, mul0, mul1 [4]uint64
	buf                [32]byte
	fill               int
}

func newHH() *hhState {
	s := &hhState{}
	s.v0 = hhInit0
	s.v1 = hhInit1
	s.mul0 = hhInit0
	s.mul1 = hhInit1
	return s
}

// zipperMerge is the exact byte-shuffle performed by wasm func 169 (scalar
// emulation of the AVX2 ZipperMergeAndAdd), solved empirically against the
// oracle and validated on multiple packets.
// Returns (zOdd, zEven): the addends for the upper/lower destination lanes.
func zipperMerge(a, b uint64) (zOdd, zEven uint64) {
	a0, a1, a2, a3, a4, a5, a6, a7 := byteAt(a, 0), byteAt(a, 1), byteAt(a, 2), byteAt(a, 3), byteAt(a, 4), byteAt(a, 5), byteAt(a, 6), byteAt(a, 7)
	b0, b1, b2, b3, b4, b5, b6, b7 := byteAt(b, 0), byteAt(b, 1), byteAt(b, 2), byteAt(b, 3), byteAt(b, 4), byteAt(b, 5), byteAt(b, 6), byteAt(b, 7)
	zEven = uint64(a3) | uint64(b4)<<8 | uint64(a2)<<16 | uint64(a5)<<24 |
		uint64(a1)<<32 | uint64(b6)<<40 | uint64(a0)<<48 | uint64(b7)<<56
	zOdd = uint64(b3) | uint64(a4)<<8 | uint64(b2)<<16 | uint64(b5)<<24 |
		uint64(a6)<<32 | uint64(b1)<<40 | uint64(a7)<<48 | uint64(b0)<<56
	return
}

func byteAt(x uint64, i int) byte {
	return byte(x >> (8 * uint(i)))
}

func (s *hhState) packet(p [4]uint64) {
	for j := 0; j < 4; j++ {
		s.v1[j] += p[j] + s.mul0[j]
	}
	for j := 0; j < 4; j++ {
		s.mul0[j] ^= (s.v0[j] >> 32) * (s.v1[j] & 0xFFFFFFFF)
	}
	for j := 0; j < 4; j++ {
		s.v0[j] += s.mul1[j]
	}
	for j := 0; j < 4; j++ {
		s.mul1[j] ^= (s.v1[j] >> 32) * (s.v0[j] & 0xFFFFFFFF)
	}
	for j := 0; j < 4; j += 2 {
		zOdd, zEven := zipperMerge(s.v1[j+1], s.v1[j])
		s.v0[j+1] += zEven // odd lane
		s.v0[j] += zOdd    // even lane
	}
	for j := 0; j < 4; j += 2 {
		zOdd, zEven := zipperMerge(s.v0[j+1], s.v0[j])
		s.v1[j+1] += zEven // odd lane
		s.v1[j] += zOdd    // even lane
	}
}

// Write absorbs data (wasm func 114: streaming into a 32-byte buffer).
func (s *hhState) Write(data []byte) {
	for _, b := range data {
		s.buf[s.fill] = b
		s.fill++
		if s.fill == 32 {
			var p [4]uint64
			for j := 0; j < 4; j++ {
				p[j] = binary.LittleEndian.Uint64(s.buf[8*j : 8*j+8])
			}
			s.packet(p)
			s.fill = 0
		}
	}
}

func rotl64(x uint64, n uint) uint64 {
	if n == 0 {
		return x
	}
	return (x << n) | (x >> (64 - n))
}

func rotl32(x uint32, n uint) uint32 {
	if n == 0 {
		return x
	}
	return (x << n) | (x >> (32 - n))
}

// finalize128 is wasm func 121: remainder padding, 6 permute rounds, 128-bit fold.
func (s *hhState) finalize128() (o0, o1 uint64) {
	fill := s.fill
	if fill != 0 {
		addend := uint64(fill) * 0x100000001
		for j := 0; j < 4; j++ {
			s.v0[j] += addend
		}
		for j := 0; j < 4; j++ {
			lo := rotl32(uint32(s.v1[j]), uint(fill))
			hi := rotl32(uint32(s.v1[j]>>32), uint(fill))
			s.v1[j] = uint64(hi)<<32 | uint64(lo)
		}
		var scratch [32]byte
		n := fill
		if n > 32 {
			n = 32
		}
		nb := n & 60
		copy(scratch[:nb], s.buf[:nb])
		if n&16 == 0 {
			if n&3 != 0 {
				// NOTE: the wasm mutates its pointer local via tee:
				// local2 = buf + nb, and local4 = n & 3, so the three
				// trailing loads are buf[nb], buf[nb+((n&3)>>1)],
				// buf[nb+((n&3)-1)].
				scratch[16] = s.buf[nb]
				scratch[17] = s.buf[nb+((n&3)>>1)]
				scratch[18] = s.buf[nb+(n&3)-1]
			}
		} else {
			copy(scratch[28:32], s.buf[n-4:n])
		}
		var p [4]uint64
		for j := 0; j < 4; j++ {
			p[j] = binary.LittleEndian.Uint64(scratch[8*j : 8*j+8])
		}
		s.packet(p)
	}
	for round := 0; round < 6; round++ {
		var p [4]uint64
		p[0] = rotl64(s.v0[2], 32)
		p[1] = rotl64(s.v0[3], 32)
		p[2] = rotl64(s.v0[0], 32)
		p[3] = rotl64(s.v0[1], 32)
		s.packet(p)
	}
	o0 = s.mul1[2] + s.v1[2] + s.mul0[0] + s.v0[0]
	o1 = s.mul1[3] + s.v1[3] + s.mul0[1] + s.v0[1]
	return
}

// HighwayHash128 computes the SDK's HighwayHash-128 (zero key) over data.
func HighwayHash128(data []byte) [16]byte {
	s := newHH()
	s.Write(data)
	o0, o1 := s.finalize128()
	var out [16]byte
	binary.LittleEndian.PutUint64(out[0:8], o0)
	binary.LittleEndian.PutUint64(out[8:16], o1)
	return out
}

// HHHex is HighwayHash128 formatted like the payload field (hex).
func HHHex(data []byte) string {
	h := HighwayHash128(data)
	return hexStr(h[:])
}
