package common

import (
	"math/rand"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/assert"
)

func BenchmarkFourSquares256(b *testing.B) {
	randomSource := rand.New(rand.NewSource(1))
	limit := new(big.Int).Lsh(big.NewInt(1), 256)
	for i := 0; i < b.N; i++ {
		val := new(big.Int).Rand(randomSource, limit)
		x, y, z, w := SumFourSquare(val)
		s := new(big.Int).Mul(x, x)
		t := new(big.Int).Mul(y, y)
		s.Add(s, t)
		t.Mul(z, z)
		s.Add(s, t)
		t.Mul(w, w)
		s.Add(s, t)
		assert.True(b, s.Cmp(val) == 0)
	}
}

func BenchmarkFourSquares128(b *testing.B) {
	randomSource := rand.New(rand.NewSource(1))
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for i := 0; i < b.N; i++ {
		val := new(big.Int).Rand(randomSource, limit)
		x, y, z, w := SumFourSquare(val)
		s := new(big.Int).Mul(x, x)
		t := new(big.Int).Mul(y, y)
		s.Add(s, t)
		t.Mul(z, z)
		s.Add(s, t)
		t.Mul(w, w)
		s.Add(s, t)
		assert.True(b, s.Cmp(val) == 0)
	}
}

func BenchmarkFourSquares64(b *testing.B) {
	randomSource := rand.New(rand.NewSource(1))
	limit := new(big.Int).Lsh(big.NewInt(1), 64)
	for i := 0; i < b.N; i++ {
		val := new(big.Int).Rand(randomSource, limit)
		x, y, z, w := SumFourSquare(val)
		s := new(big.Int).Mul(x, x)
		t := new(big.Int).Mul(y, y)
		s.Add(s, t)
		t.Mul(z, z)
		s.Add(s, t)
		t.Mul(w, w)
		s.Add(s, t)
		assert.True(b, s.Cmp(val) == 0)
	}
}

func BenchmarkFourSquares32(b *testing.B) {
	randomSource := rand.New(rand.NewSource(1))
	limit := new(big.Int).Lsh(big.NewInt(1), 32)
	for i := 0; i < b.N; i++ {
		val := new(big.Int).Rand(randomSource, limit)
		x, y, z, w := SumFourSquare(val)
		s := new(big.Int).Mul(x, x)
		t := new(big.Int).Mul(y, y)
		s.Add(s, t)
		t.Mul(z, z)
		s.Add(s, t)
		t.Mul(w, w)
		s.Add(s, t)
		assert.True(b, s.Cmp(val) == 0)
	}
}

func BenchmarkFourSquares16(b *testing.B) {
	randomSource := rand.New(rand.NewSource(1))
	limit := new(big.Int).Lsh(big.NewInt(1), 16)
	for i := 0; i < b.N; i++ {
		val := new(big.Int).Rand(randomSource, limit)
		x, y, z, w := SumFourSquare(val)
		s := new(big.Int).Mul(x, x)
		t := new(big.Int).Mul(y, y)
		s.Add(s, t)
		t.Mul(z, z)
		s.Add(s, t)
		t.Mul(w, w)
		s.Add(s, t)
		assert.True(b, s.Cmp(val) == 0)
	}
}

func BenchmarkFourSquares8(b *testing.B) {
	randomSource := rand.New(rand.NewSource(1))
	limit := new(big.Int).Lsh(big.NewInt(1), 8)
	for i := 0; i < b.N; i++ {
		val := new(big.Int).Rand(randomSource, limit)
		x, y, z, w := SumFourSquare(val)
		s := new(big.Int).Mul(x, x)
		t := new(big.Int).Mul(y, y)
		s.Add(s, t)
		t.Mul(z, z)
		s.Add(s, t)
		t.Mul(w, w)
		s.Add(s, t)
		assert.True(b, s.Cmp(val) == 0)
	}
}
