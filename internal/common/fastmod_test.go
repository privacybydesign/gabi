package common

import (
	"github.com/privacybydesign/gabi/big"

	"math/rand"
	"testing"
)

var rnd *rand.Rand = rand.New(rand.NewSource(37))

func testFastMod(t *testing.T, p *big.Int) {
	var a, r1, r2, l, iBi big.Int
	var fm FastMod
	if p.Sign() == 0 {
		return
	}
	fm.Set(p)
	for i := 0; i < 10; i++ {
		l.Set(p)
		iBi.SetUint64(uint64(i))
		l.Mul(&l, &iBi)
		a.Rand(rnd, &l)
		r1.Mod(&a, p)
		fm.Mod(&r2, &a)
		if r1.Cmp(&r2) != 0 {
			t.Fatalf("%v mod %v = %v != %v", &a, p, &r1, &r2)
		}
	}
}

func TestFastModFast(t *testing.T) {
	var p, l, m big.Int
	m.SetUint64(0xffffff)
	for j := 1; j < 12; j++ {
		l.SetUint64(1)
		l.Lsh(&l, 1<<uint(j))
		for i := 0; i < 10; i++ {
			p.Rand(rnd, &l)
			p.And(&p, &m)
			p.Sub(&l, &p)
			testFastMod(t, &p)
		}
	}
}

func TestFastModSlow(t *testing.T) {
	var p, l big.Int
	for j := 1; j < 12; j++ {
		l.SetUint64(1)
		l.Lsh(&l, 1<<uint(j))
		for i := 0; i < 10; i++ {
			p.Rand(rnd, &l)
			testFastMod(t, &p)
		}
	}
}

func benchmarkFastMod(b *testing.B, f float32, bits uint) {
	var fm FastMod
	var l, bi12345, n, r big.Int
	bi12345.SetUint64(12345)
	l.SetUint64(1)
	n.Lsh(&l, uint(f*float32(bits)))
	n.Rand(rnd, &n)
	l.Lsh(&l, uint(bits))
	l.Sub(&l, &bi12345)
	fm.Set(&l)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fm.Mod(&r, &n)
	}
}
func benchmarkMod(b *testing.B, f float32, bits uint) {
	var l, bi12345, n, r big.Int
	bi12345.SetUint64(12345)
	l.SetUint64(1)
	n.Lsh(&l, uint(f*float32(bits)))
	n.Rand(rnd, &n)
	l.Lsh(&l, uint(bits))
	l.Sub(&l, &bi12345)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Mod(&n, &l)
	}
}

func BenchmarkFastMod1024_1(b *testing.B)    { benchmarkFastMod(b, 1.0, 1024) }
func BenchmarkFastMod1024_1_5(b *testing.B)  { benchmarkFastMod(b, 1.5, 1024) }
func BenchmarkFastMod1024_2(b *testing.B)    { benchmarkFastMod(b, 2.0, 1024) }
func BenchmarkFastMod1024_half(b *testing.B) { benchmarkFastMod(b, .5, 1024) }
func BenchmarkFastMod2048_1(b *testing.B)    { benchmarkFastMod(b, 1.0, 2048) }
func BenchmarkFastMod2048_1_5(b *testing.B)  { benchmarkFastMod(b, 1.5, 2048) }
func BenchmarkFastMod2048_2(b *testing.B)    { benchmarkFastMod(b, 2.0, 2048) }
func BenchmarkFastMod2048_half(b *testing.B) { benchmarkFastMod(b, .5, 2048) }
func BenchmarkFastMod4096_1(b *testing.B)    { benchmarkFastMod(b, 1.0, 4096) }
func BenchmarkFastMod4096_1_5(b *testing.B)  { benchmarkFastMod(b, 1.5, 4096) }
func BenchmarkFastMod4096_2(b *testing.B)    { benchmarkFastMod(b, 2.0, 4096) }
func BenchmarkFastMod4096_half(b *testing.B) { benchmarkFastMod(b, .5, 4096) }
func BenchmarkMod1024_1(b *testing.B)        { benchmarkMod(b, 1.0, 1024) }
func BenchmarkMod1024_1_5(b *testing.B)      { benchmarkMod(b, 1.5, 1024) }
func BenchmarkMod1024_2(b *testing.B)        { benchmarkMod(b, 2.0, 1024) }
func BenchmarkMod1024_half(b *testing.B)     { benchmarkMod(b, .5, 1024) }
func BenchmarkMod2048_1(b *testing.B)        { benchmarkMod(b, 1.0, 2048) }
func BenchmarkMod2048_1_5(b *testing.B)      { benchmarkMod(b, 1.5, 2048) }
func BenchmarkMod2048_2(b *testing.B)        { benchmarkMod(b, 2.0, 2048) }
func BenchmarkMod2048_half(b *testing.B)     { benchmarkMod(b, .5, 2048) }
func BenchmarkMod4096_1(b *testing.B)        { benchmarkMod(b, 1.0, 4096) }
func BenchmarkMod4096_1_5(b *testing.B)      { benchmarkMod(b, 1.5, 4096) }
func BenchmarkMod4096_2(b *testing.B)        { benchmarkMod(b, 2.0, 4096) }
func BenchmarkMod4096_half(b *testing.B)     { benchmarkMod(b, .5, 4096) }
