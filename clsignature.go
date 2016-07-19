package gabi

import (
	"crypto/rand"
	"math/big"
)

// CLSignature is a data structure for holding a Camenisch-Lysyanskaya signature.
type CLSignature struct {
	A, E, V *big.Int
}

// SignMessageBlock signs a message block (ms) and a commitment (U) using the
// Camenisch-Lysyanskaya signature scheme as used in the IdeMix system.
func signMessageBlockAndCommitment(sk *PrivateKey, pk *PublicKey, U *big.Int, ms []*big.Int, Rs []*big.Int) (*CLSignature, error) {
	R := representToBases(Rs, ms, pk.N)

	vTilde, _ := randomBigInt(pk.Params.Lv - 1)
	twoLv := new(big.Int).Lsh(bigONE, pk.Params.Lv-1)
	v := new(big.Int).Add(twoLv, vTilde)

	// Q = inv( S^v * R * U) * Z

	numerator := new(big.Int).Exp(pk.S, v, pk.N)
	numerator.Mul(numerator, R).Mul(numerator, U).Mod(numerator, pk.N)

	invNumerator, _ := modInverse(numerator, pk.N)
	Q := new(big.Int).Mul(pk.Z, invNumerator)
	Q.Mod(Q, pk.N)

	e, err := randomPrimeInRange(rand.Reader, pk.Params.Le-1, pk.Params.LePrime-1)
	if err != nil {
		return nil, err
	}

	order := new(big.Int).Mul(sk.PPrime, sk.QPrime)
	d, _ := modInverse(e, order)
	A := new(big.Int).Exp(Q, d, pk.N)

	// TODO: this is probably open to side channel attacks, maybe use a
	// safe (raw) RSA signature?

	return &CLSignature{A: A, E: e, V: v}, nil
}

// SignMessageBlock signs a message block (ms) using the Camenisch-Lysyanskaya
// signature scheme as used in the IdeMix system.
func SignMessageBlock(sk *PrivateKey, pk *PublicKey, ms []*big.Int) (*CLSignature, error) {
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
	Ae := new(big.Int).Exp(s.A, s.E, pk.N)
	R := representToBases(pk.R, ms, pk.N)
	Sv := modPow(pk.S, s.V, pk.N)
	Q := new(big.Int).Mul(Ae, R)
	Q.Mul(Q, Sv).Mod(Q, pk.N)

	// Signature verifies if Q == Z
	return pk.Z.Cmp(Q) == 0
}

// Randomize returns a randomized copy of the signature.
func (s *CLSignature) Randomize(pk *PublicKey) *CLSignature {
	r, _ := randomBigInt(pk.Params.LRA)
	APrime := new(big.Int).Mul(s.A, new(big.Int).Exp(pk.S, r, pk.N))
	APrime.Mod(APrime, pk.N)
	t := new(big.Int).Mul(s.E, r)
	VPrime := new(big.Int).Sub(s.V, t)
	return &CLSignature{A: APrime, E: new(big.Int).Set(s.E), V: VPrime}
}
