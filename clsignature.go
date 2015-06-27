package credential

import (
	"crypto/rand"
	"math/big"
)

// CLSignature is a datastructure for holding a Camenisch-Lysyanskaya signature.
type CLSignature struct {
	A, E, V *big.Int
}

var (
	bigZERO = big.NewInt(0)
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

// SignMessageBlock signs a message block (ms) and a commitment (U) using
// Camenisch-Lysyanskaya signature scheme as used in the IdeMix system.
func signMessageBlockAndCommitment(sk *SecretKey, pk *PublicKey, U *big.Int, ms []*big.Int, Rs []*big.Int) (*CLSignature, error) {
	R := representToBases(Rs, ms, &pk.N)

	vTilde, _ := randomBigInt(pk.Params.Lv - 1)
	twoLv := new(big.Int).Lsh(bigONE, pk.Params.Lv-1)
	v := new(big.Int).Add(twoLv, vTilde)

	// Q = inv( S^v * R * U) * Z

	numerator := new(big.Int).Exp(&pk.S, v, &pk.N)
	numerator.Mul(numerator, R).Mul(numerator, U).Mod(numerator, &pk.N)

	invNumerator, _ := modInverse(numerator, &pk.N)
	Q := new(big.Int).Mul(&pk.Z, invNumerator)
	Q.Mod(Q, &pk.N)

	e, err := randomPrimeInRange(rand.Reader, pk.Params.Le-1, pk.Params.LePrime-1)
	if err != nil {
		return nil, err
	}

	order := new(big.Int).Mul(&sk.PPrime, &sk.QPrime)
	d, _ := modInverse(e, order)
	A := new(big.Int).Exp(Q, d, &pk.N)

	// TODO: this is probably open to side channel attacks, maybe use a
	// safe (raw) RSA signature?

	return &CLSignature{A: A, E: e, V: v}, nil
}

// SignMessageBlock signs a message block (ms) using Camenisch-Lysyanskaya signature scheme as used in the IdeMix system.
func SignMessageBlock(sk *SecretKey, pk *PublicKey, ms []*big.Int) (*CLSignature, error) {
	return signMessageBlockAndCommitment(sk, pk, big.NewInt(1), ms, pk.R)
}

// Verify checks whether the signature is correct while being given a public key
// and the messages.
func (s *CLSignature) Verify(pk *PublicKey, ms []*big.Int) bool {
	// First check that e is in the range [2^{l_e - 1}, 2^{l_e - 1} + 2^{l_e_prime - 1}]
	start := new(big.Int).Lsh(bigONE, pk.Params.Le-1)
	end := new(big.Int).Lsh(bigONE, pk.Params.LePrime-1)
	end.Add(end, start)
	if s.E.Cmp(start) < 0 || s.E.Cmp(end) > 0 {
		return false
	}

	// Q = A^e * R * S^v
	Ae := new(big.Int).Exp(s.A, s.E, &pk.N)
	R := representToBases(pk.R, ms, &pk.N)
	Sv := modPow(&pk.S, s.V, &pk.N)
	Q := new(big.Int).Mul(Ae, R)
	Q.Mul(Q, Sv).Mod(Q, &pk.N)

	// Signature verifies if Q == Z
	return pk.Z.Cmp(Q) == 0
}

// Randomize returns a randomized (copy) of the signature.
func (s *CLSignature) Randomize(pk *PublicKey) *CLSignature {
	r, _ := randomBigInt(pk.Params.LRA)
	APrime := new(big.Int).Mul(s.A, new(big.Int).Exp(&pk.S, r, &pk.N))
	APrime.Mod(APrime, &pk.N)
	t := new(big.Int).Mul(s.E, r)
	VPrime := new(big.Int).Sub(s.V, t)
	return &CLSignature{A: APrime, E: new(big.Int).Set(s.E), V: VPrime}
}
