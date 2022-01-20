// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"crypto/rand"

	"github.com/go-errors/errors"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/revocation"
)

// Issuer holds the key material for a credential issuer.
type Issuer struct {
	Sk      *gabikeys.PrivateKey
	Pk      *gabikeys.PublicKey
	Context *big.Int
}

// NewIssuer creates a new credential issuer.
func NewIssuer(sk *gabikeys.PrivateKey, pk *gabikeys.PublicKey, context *big.Int) *Issuer {
	return &Issuer{Sk: sk, Pk: pk, Context: context}
}

// IssueSignature produces an IssueSignatureMessage for the attributes based on
// the IssueCommitmentMessage provided. Note that this function DOES NOT check
// the proofs containted in the IssueCommitmentMessage! That needs to be done at
// a higher level!
func (i *Issuer) IssueSignature(U *big.Int, attributes []*big.Int, witness *revocation.Witness, nonce2 *big.Int, blind []int) (*IssueSignatureMessage, error) {
	signature, mIssuer, err := i.signCommitmentAndAttributes(U, attributes, blind)
	if err != nil {
		return nil, err
	}
	proof, err := i.proveSignature(signature, nonce2)
	if err != nil {
		return nil, err
	}
	return &IssueSignatureMessage{Signature: signature, Proof: proof, NonRevocationWitness: witness, MIssuer: mIssuer}, nil
}

// signCommitmentAndAttributes produces a (partial) signature on the commitment
// and the attributes (some of which might be unknown to the issuer).
// Arg "blind" is a list of indices representing the random blind attributes.
// The signature does not verify (yet) due to blinding factors present.
func (i *Issuer) signCommitmentAndAttributes(U *big.Int, attributes []*big.Int, blind []int) (*CLSignature, map[int]*big.Int, error) {
	mIssuer := make(map[int]*big.Int)
	ms := append([]*big.Int{big.NewInt(0)}, attributes...)

	for _, j := range blind {
		if attributes[j] != nil {
			return nil, nil, errors.New("attribute at random blind index should be nil before issuance")
		}
		// Replace attribute value with issuer's share
		r, err := common.RandomBigInt(i.Pk.Params.Lm - 1)
		if err != nil {
			return nil, nil, err
		}
		mIssuer[j+1] = r
		ms[j+1] = r
	}

	cl, err := signMessageBlockAndCommitment(i.Sk, i.Pk, U, ms)
	if err != nil {
		return nil, nil, err
	}

	return cl, mIssuer, nil
}

// randomElementMultiplicativeGroup returns a random element in the
// multiplicative group Z_{modulus}^*.
func randomElementMultiplicativeGroup(modulus *big.Int) (*big.Int, error) {
	r := big.NewInt(0)
	t := new(big.Int)
	var err error
	for r.Sign() <= 0 || t.GCD(nil, nil, r, modulus).Cmp(big.NewInt(1)) != 0 {
		// TODO: for memory/cpu efficiency re-use r's memory. See Go's
		// implementation for finding a random prime.
		r, err = big.RandInt(rand.Reader, modulus)
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

// proveSignature returns a proof of knowledge of $e^{-1}$ in the signature.
func (i *Issuer) proveSignature(signature *CLSignature, nonce2 *big.Int) (*ProofS, error) {
	Q := new(big.Int).Exp(signature.A, signature.E, i.Pk.N)
	d := new(big.Int).ModInverse(signature.E, i.Sk.Order)
	if d == nil {
		return nil, common.ErrNoModInverse
	}

	eCommit, err := randomElementMultiplicativeGroup(i.Sk.Order)
	if err != nil {
		return nil, err
	}
	ACommit := new(big.Int).Exp(Q, eCommit, i.Pk.N)

	c := common.HashCommit([]*big.Int{i.Context, Q, signature.A, nonce2, ACommit}, false)
	eResponse := new(big.Int).Mul(c, d)
	eResponse.Sub(eCommit, eResponse).Mod(eResponse, i.Sk.Order)

	return &ProofS{c, eResponse}, nil
}
