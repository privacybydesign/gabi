// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package common

import (
	"crypto/rand"
	mathRand "math/rand"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
)

// Some utility code (mostly math stuff) useful in various places in this
// package.

// Often we need to refer to the same small constant big numbers, no point in
// creating them again and again.
var (
	bigZERO  = big.NewInt(0)
	bigONE   = big.NewInt(1)
	bigTWO   = big.NewInt(2)
	bigTHREE = big.NewInt(3)
	bigFOUR  = big.NewInt(4)
	bigFIVE  = big.NewInt(5)
	bigEIGHT = big.NewInt(8)
)

// ModInverse returns ia, the inverse of a in the multiplicative group of prime
// order n. It requires that a be a member of the group (i.e. less than n).
// This function was taken from Go's RSA implementation
func ModInverse(a, n *big.Int) (ia *big.Int, ok bool) {
	g := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	g.GCD(x, y, a, n)
	if g.Cmp(bigONE) != 0 {
		// In this case, a and n aren't coprime and we cannot calculate
		// the inverse. This happens because the values of n are nearly
		// prime (being the product of two primes) rather than truly
		// prime.
		return
	}

	if x.Cmp(bigONE) < 0 {
		// 0 is not the multiplicative inverse of any element so, if x
		// < 1, then x is negative.
		x.Add(x, n)
	}

	return x, true
}

var ErrNoModInverse = errors.New("modular inverse does not exist")

// ModPow computes x^y mod m. The exponent (y) can be negative, in which case it
// uses the modular inverse to compute the result (in contrast to Go's Exp
// function).
func ModPow(x, y, m *big.Int) (*big.Int, error) {
	if y.Sign() == -1 {
		t := new(big.Int).ModInverse(x, m)
		if t == nil {
			return nil, ErrNoModInverse
		}
		return t.Exp(t, new(big.Int).Neg(y), m), nil
	}
	return new(big.Int).Exp(x, y, m), nil
}

// RepresentToBases returns a representation of the given exponents in terms of the R bases
// from the public key. For example given exponents exps[1],...,exps[k] this function returns
//
//	R[1]^{exps[1]}*...*R[k]^{exps[k]} (mod N)
//
// with R and N coming from the public key. The exponents are hashed if their length
// exceeds the maximum message length from the public key.
func RepresentToBases(bases, exps []*big.Int, modulus *big.Int, maxMessageLength uint) *big.Int {
	r := big.NewInt(1)
	tmp := new(big.Int)
	for i := 0; i < len(exps); i++ {
		exp := exps[i]
		if exp.BitLen() > int(maxMessageLength) {
			exp = IntHashSha256(exp.Bytes())
		}
		// tmp = bases_i ^ exps_i (mod modulus), with exps_i hashed if it exceeds maxMessageLength
		tmp.Exp(bases[i], exp, modulus)
		// r = r * tmp (mod modulus)
		r.Mul(r, tmp).Mod(r, modulus)
	}
	return r
}

// RandomBigInt returns a random big integer value in the range
// [0,(2^numBits)-1], inclusive.
func RandomBigInt(numBits uint) (*big.Int, error) {
	t := new(big.Int).Lsh(bigONE, numBits)
	return big.RandInt(rand.Reader, t)
}

// LegendreSymbol calculates the Legendre symbol (a/p).
func LegendreSymbol(a, p *big.Int) int {
	// Adapted from: https://programmingpraxis.com/2012/05/01/legendres-symbol/
	j := 1

	// Make a copy of the arguments
	// rule 5
	n := new(big.Int).Mod(a, p)
	m := new(big.Int).Set(p)

	tmp := new(big.Int)
	for n.Cmp(bigZERO) != 0 {
		// rules 3 and 4
		t := 0
		for n.Bit(0) == 0 {
			n.Rsh(n, 1)
			t++
		}
		tmp.Mod(m, bigEIGHT)
		if t&1 == 1 && (tmp.Cmp(bigTHREE) == 0 || tmp.Cmp(bigFIVE) == 0) {
			j = -j
		}

		// rule 6
		if tmp.Mod(m, bigFOUR).Cmp(bigTHREE) == 0 && tmp.Mod(n, bigFOUR).Cmp(bigTHREE) == 0 {
			j = -j
		}

		// rules 5 and 6
		m.Mod(m, n)
		n, m = m, n
	}
	if m.Cmp(bigONE) == 0 {
		return j
	}
	return 0
}

// Crt finds a number x (mod pa*pb) such that x = a (mod pa) and x = b (mod pb)
func Crt(a *big.Int, pa *big.Int, b *big.Int, pb *big.Int) *big.Int {
	s1 := new(big.Int)
	s2 := new(big.Int)
	z := new(big.Int).GCD(s2, s1, pa, pb)
	if z.Cmp(bigONE) != 0 {
		panic("Incorrect input to CRT")
	}
	result := new(big.Int).Add(
		new(big.Int).Mul(new(big.Int).Mul(a, s1), pb),
		new(big.Int).Mul(new(big.Int).Mul(b, s2), pa))

	n := new(big.Int).Mul(pa, pb)
	result.Mod(result, n)
	return result
}

// SumFourSquares expresses a number as sum of four squares
// algorithm from "Randomized algorithms in number theory" by M. Rabin and J. Shallit
func SumFourSquares(n *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int) {
	if n.BitLen() == 0 {
		return big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)
	}
	temp := new(big.Int).And(n, bigTHREE)
	if temp.Int64() == 2 {
		return sumFourSquaresSpecial(n)
	} else if temp.Int64() == 0 {
		// extract out 2^2k, then calculate subanswer and modify it by multiplying all values by 2^k
		d := uint(1)
		temp.Rsh(n, 1)
		temp2 := new(big.Int).And(temp, bigTHREE)
		for temp2.Int64() != 2 {
			temp.Rsh(temp, 1)
			d++
			temp2.And(temp, bigTHREE)
		}
		if d%2 == 1 {
			temp.Rsh(temp, 1)
			d++
		}
		x, y, z, w := SumFourSquares(temp)
		x.Lsh(x, d/2)
		y.Lsh(y, d/2)
		z.Lsh(z, d/2)
		w.Lsh(w, d/2)
		return x, y, z, w
	} else {
		temp.Lsh(n, 1)
		x, y, z, w := sumFourSquaresSpecial(temp)
		temp.And(x, bigONE)
		xOdd := temp.Int64()
		temp.And(y, bigONE)
		yOdd := temp.Int64()
		if xOdd != yOdd {
			temp.And(z, bigONE)
			zOdd := temp.Int64()
			if xOdd == zOdd {
				y, z = z, y
			} else {
				y, w = w, y
			}
		}
		if x.Cmp(y) < 0 {
			x, y = y, x
		}
		if z.Cmp(w) < 0 {
			z, w = w, z
		}

		temp.Sub(x, y)
		x.Add(x, y)
		x.Rsh(x, 1)
		y.Rsh(temp, 1)
		temp.Sub(z, w)
		z.Add(z, w)
		z.Rsh(z, 1)
		w.Rsh(temp, 1)
		return x, y, z, w
	}
}

func sumFourSquaresSpecial(n *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int) {
	if n.IsInt64() && n.Int64() < 4 {
		return big.NewInt(1), big.NewInt(1), big.NewInt(0), big.NewInt(0)
	}
	rootN := new(big.Int).Sqrt(n)
	x := new(big.Int)
	y := new(big.Int)
	z := new(big.Int)
	w := new(big.Int)
	p := new(big.Int)
	t1 := new(big.Int)

	// We do need randomness, but only because the polynomial time algorithm
	// is randomized, so using mathRand is significantly faster and poses
	// no security risks here
	randomSource := mathRand.New(mathRand.NewSource(1))
	for {
		x.Rand(randomSource, rootN)
		y.Rand(randomSource, rootN)

		z.Mul(x, x)
		z.Sub(n, z)
		w.Mul(y, y)
		z.Sub(z, w)

		if z.IsInt64() && z.Int64() == 2 {
			return x, y, big.NewInt(1), big.NewInt(1)
		}

		if z.BitLen() == 0 || z.Bits()[0]&3 != 1 {
			continue // z unsuitable
		}

		if !z.ProbablyPrime(10) {
			continue // z unsuitable
		}

		p.Set(z)

		w.Sub(z, bigONE)
		w.ModSqrt(w, z)

		if 2*w.BitLen()-1 <= p.BitLen() {
			t1.Mul(w, w)
			if p.Cmp(t1) > 0 {
				z.Mod(z, w)
				return x, y, z, w
			}
		}

		for {
			z.Mod(z, w)
			if z.BitLen() == 0 {
				break
			}
			if 2*z.BitLen()-1 <= p.BitLen() {
				t1.Mul(z, z)
				if p.Cmp(t1) > 0 {
					w.Mod(w, z)
					return x, y, z, w
				}
			}

			w.Mod(w, z)
			if w.BitLen() == 0 {
				break
			}
			if 2*w.BitLen()-1 <= p.BitLen() {
				t1.Mul(w, w)
				if p.Cmp(t1) > 0 {
					z.Mod(z, w)
					return x, y, z, w
				}
			}
		}
	}
}

// PrimeSqrt calculates sqrt modulo a prime
func PrimeSqrt(a *big.Int, pa *big.Int) (*big.Int, bool) {
	// Handle the case a == 0
	if a.Cmp(bigZERO) == 0 {
		return big.NewInt(0), true // should be a new big int!
	}

	// Check number is a square
	validation := new(big.Int).Exp(a, new(big.Int).Rsh(pa, 1), pa)
	if validation.Cmp(bigONE) != 0 {
		return nil, false
	}

	// Shortcut when pa = 3 (mod 4)
	rem := new(big.Int).Mod(pa, bigFOUR)
	if rem.Cmp(bigTHREE) == 0 {
		result := new(big.Int).Exp(a, new(big.Int).Add(new(big.Int).Rsh(pa, 2), big.NewInt(1)), pa)
		return result, true
	}

	// Find a non-residue
	z := big.NewInt(2) // Should be a new big int!
	for LegendreSymbol(new(big.Int).Set(z), new(big.Int).Set(pa)) != -1 {
		z.Add(z, bigONE)
	}

	// Split pa-1 as 2^S*Q
	Q := new(big.Int).Sub(pa, big.NewInt(1))
	M := 0
	for Q.Bit(0) == 0 {
		Q.Rsh(Q, 1)
		M++
	}

	// Setup for main loop
	c := new(big.Int).Exp(z, Q, pa)
	t := new(big.Int).Exp(a, Q, pa)
	R := new(big.Int).Exp(a, new(big.Int).Add(new(big.Int).Rsh(Q, 1), big.NewInt(1)), pa)

	// Main loop
	for t.Cmp(bigONE) != 0 {
		tp := new(big.Int).Set(t)
		i := 0
		for tp.Cmp(bigONE) != 0 {
			tp.Exp(tp, big.NewInt(2), pa)
			i++
		}
		b := new(big.Int).Exp(c, new(big.Int).Lsh(bigONE, uint(M-i-1)), pa)
		M = i
		c.Exp(b, bigTWO, pa)
		t.Mod(new(big.Int).Mul(t, c), pa)
		R.Mod(new(big.Int).Mul(R, b), pa)
	}

	return R, true
}

// ModSqrt calculates Sqrt modulo a number with given prime factors. Also allows 4 as a factor
// All factors should be relatively prime to each other!
func ModSqrt(a *big.Int, factors []*big.Int) (*big.Int, bool) {
	n := big.NewInt(1) // Should be new big int!
	res := new(big.Int)

	// Solve problem one factor at a time
	for i, fac := range factors {
		var locRes *big.Int
		if fac.Cmp(bigFOUR) == 0 {
			// Special case for 4
			if a.Bit(1) != 0 {
				return nil, false
			}
			if a.Bit(0) == 0 {
				locRes = big.NewInt(2) // For safety sake, keep new
			} else {
				locRes = big.NewInt(1) // For safety sake, keep new
			}
		} else {
			var ok bool
			locRes, ok = PrimeSqrt(new(big.Int).Mod(a, fac), fac)
			if !ok {
				return nil, false
			}
		}
		if i == 0 {
			res = locRes
		} else {
			res = Crt(res, n, locRes, fac)
		}
		n.Mul(n, fac)
	}
	return res, true
}
