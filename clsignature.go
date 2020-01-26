// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"crypto/rand"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
)

// RepresentToPublicKey returns a representation of the given exponents in terms of the R bases
// from the public key. For example given exponents exps[1],...,exps[k] this function returns
//   R[1]^{exps[1]}*...*R[k]^{exps[k]} (mod N)
// with R and N coming from the public key. The exponents are hashed if their length
// exceeds the maximum message length from the public key.
func RepresentToPublicKey(pk *PublicKey, exps []*big.Int, revocationAttr *big.Int) (*big.Int, error) {
	R := common.RepresentToBases(pk.R, exps, pk.N, pk.Params.Lm)
	if revocationAttr != nil {
		if !pk.RevocationSupported() {
			return nil, errors.New("revocation not supported by this public key")
		}
		R.Mul(R, common.ModPow(pk.T, revocationAttr, pk.N)).Mod(R, pk.N)
	}
	return R, nil
}

// CLSignature is a data structure for holding a Camenisch-Lysyanskaya signature.
type CLSignature struct {
	A         *big.Int
	E         *big.Int `json:"e"`
	V         *big.Int `json:"v"`
	KeyshareP *big.Int `json:"KeyshareP"` // R_0^{keysharesecret}, necessary for verification
}

// SignMessageBlock signs a message block (ms) and a commitment (U) using the
// Camenisch-Lysyanskaya signature scheme as used in the IdeMix system.
func signMessageBlockAndCommitment(sk *PrivateKey, pk *PublicKey, U *big.Int, ms []*big.Int, revocationAttr *big.Int) (
	*CLSignature, error) {
	R, err := RepresentToPublicKey(pk, ms, revocationAttr)
	if err != nil {
		return nil, err
	}

	vTilde, _ := common.RandomBigInt(pk.Params.Lv - 1)
	twoLv := new(big.Int).Lsh(big.NewInt(1), pk.Params.Lv-1)
	v := new(big.Int).Add(twoLv, vTilde)

	// Q = inv( S^v * R * U) * Z

	numerator := new(big.Int).Exp(pk.S, v, pk.N)
	numerator.Mul(numerator, R).Mul(numerator, U).Mod(numerator, pk.N)

	invNumerator, _ := common.ModInverse(numerator, pk.N)
	Q := new(big.Int).Mul(pk.Z, invNumerator)
	Q.Mod(Q, pk.N)

	e, err := common.RandomPrimeInRange(rand.Reader, pk.Params.Le-1, pk.Params.LePrime-1)
	if err != nil {
		return nil, err
	}

	order := new(big.Int).Mul(sk.PPrime, sk.QPrime)
	d, _ := common.ModInverse(e, order)
	A := new(big.Int).Exp(Q, d, pk.N)

	// TODO: this is probably open to side channel attacks, maybe use a
	// safe (raw) RSA signature?

	return &CLSignature{A: A, E: e, V: v}, nil
}

// SignMessageBlock signs a message block (ms) using the Camenisch-Lysyanskaya
// signature scheme as used in the IdeMix system.
func SignMessageBlock(sk *PrivateKey, pk *PublicKey, ms []*big.Int, revocationAttr *big.Int) (*CLSignature, error) {
	return signMessageBlockAndCommitment(sk, pk, big.NewInt(1), ms, revocationAttr)
}

// Verify checks whether the signature is correct while being given a public key
// and the messages.
func (s *CLSignature) Verify(pk *PublicKey, ms []*big.Int, revocationAttr *big.Int) bool {
	// First check that e is in the range [2^{l_e - 1}, 2^{l_e - 1} + 2^{l_e_prime - 1}]
	start := new(big.Int).Lsh(big.NewInt(1), pk.Params.Le-1)
	end := new(big.Int).Lsh(big.NewInt(1), pk.Params.LePrime-1)
	end.Add(end, start)
	if s.E.Cmp(start) < 0 || s.E.Cmp(end) > 0 {
		return false
	}

	// Q = A^e * R * S^v
	Ae := new(big.Int).Exp(s.A, s.E, pk.N)
	R, err := RepresentToPublicKey(pk, ms, revocationAttr)
	if err != nil {
		return false
	}
	if s.KeyshareP != nil {
		R.Mul(R, s.KeyshareP)
	}
	Sv := common.ModPow(pk.S, s.V, pk.N)
	Q := new(big.Int).Mul(Ae, R)
	Q.Mul(Q, Sv).Mod(Q, pk.N)

	// Signature verifies if Q == Z
	return pk.Z.Cmp(Q) == 0
}

// Randomize returns a randomized copy of the signature.
func (s *CLSignature) Randomize(pk *PublicKey) *CLSignature {
	r, _ := common.RandomBigInt(pk.Params.LRA)
	APrime := new(big.Int).Mul(s.A, new(big.Int).Exp(pk.S, r, pk.N))
	APrime.Mod(APrime, pk.N)
	t := new(big.Int).Mul(s.E, r)
	VPrime := new(big.Int).Sub(s.V, t)
	return &CLSignature{A: APrime, E: new(big.Int).Set(s.E), V: VPrime}
}
