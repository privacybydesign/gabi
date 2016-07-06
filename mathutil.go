package credential

// TODO: properly comment all data structures and functions
import (
	"crypto/rand"
	"math/big"
)

// Some utility code (mostly math stuff) useful in various places in this
// package
var (
	bigZERO = big.NewInt(0)
	bigONE  = big.NewInt(1)
	bigTWO  = big.NewInt(2)
)

// modInverse returns ia, the inverse of a in the multiplicative group of prime
// order n. It requires that a be a member of the group (i.e. less than n).
// This function was taken from Go's RSA implementation
func modInverse(a, n *big.Int) (ia *big.Int, ok bool) {
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

// modPow computes x^y mod m. The exponent (y) can be negative, in which case it
// uses the modular inverse to compute the result (in contrast to Go's Exp
// function).
func modPow(x, y, m *big.Int) *big.Int {
	if y.Sign() == -1 {
		t := new(big.Int).ModInverse(x, m)
		return t.Exp(t, new(big.Int).Neg(y), m)
	}
	return new(big.Int).Exp(x, y, m)
}

// representToBases returns a representation of the given exponents in terms of
// the given bases. For given bases bases[1],...,bases[k]; exponents
// exps[1],...,exps[k] and modulus this function returns
// bases[k]^{exps[1]}*...*bases[k]^{exps[k]} (mod modulus).
func representToBases(bases, exps []*big.Int, modulus *big.Int) *big.Int {
	r := big.NewInt(1)
	tmp := new(big.Int)
	for i := 0; i < len(exps); i++ {
		// tmp = bases_i ^ exps_i (mod modulus)
		tmp.Exp(bases[i], exps[i], modulus)
		// r = r * tmp (mod modulus)
		r.Mul(r, tmp).Mod(r, modulus)
	}
	return r
}

// randomBigInt returns a random big integer value in the range
// [0,(2^numBits)-1], inclusive.
func randomBigInt(numBits uint) (*big.Int, error) {
	t := new(big.Int).Lsh(bigONE, numBits)
	return rand.Int(rand.Reader, t)
}
