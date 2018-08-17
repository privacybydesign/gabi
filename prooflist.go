// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"errors"
	"math/big"
)

// ProofBuilder is an interface for a proof builder. That is, an object to hold
// the state to build a list of bounded proofs (see ProofList).
type ProofBuilder interface {
	Commit(skRandomizer *big.Int) []*big.Int
	CreateProof(challenge *big.Int) Proof
	PublicKey() *PublicKey
	MergeProofPCommitment(commitment *ProofPCommitment)
}

// ProofList represents a list of (typically bound) proofs.
type ProofList []Proof

// ProofBuilderList is a list of proof builders, for calculating a list of bound proofs.
type ProofBuilderList []ProofBuilder

var (
	// ErrMissingProofU is returned when a ProofU proof is missing in a prooflist
	// when this is expected.
	ErrMissingProofU = errors.New("Missing ProofU in ProofList, has a CredentialBuilder been added?")
)

// GetProofU returns the n'th ProofU in this proof list.
func (pl ProofList) GetProofU(n int) (*ProofU, error) {
	count := 0
	for _, proof := range pl {
		switch proof.(type) {
		case *ProofU:
			if count == n {
				return proof.(*ProofU), nil
			}
			count++
		}
	}
	return nil, ErrMissingProofU
}

// GetFirstProofU returns the first ProofU in this proof list
func (pl ProofList) GetFirstProofU() (*ProofU, error) {
	return pl.GetProofU(0)
}

// challengeContributions collects and returns all the challenge contributions
// of the proofs contained in the proof list.
func (pl ProofList) challengeContributions(publicKeys []*PublicKey, context, nonce *big.Int) []*big.Int {
	contributions := make([]*big.Int, 0, len(pl)*2)
	for i, proof := range pl {
		contributions = append(contributions, proof.ChallengeContribution(publicKeys[i])...)
	}
	return contributions
}

// Verify returns true when all the proofs inside verify and if shouldBeBound is
// set to true whether all proofs are properly bound.
func (pl ProofList) Verify(publicKeys []*PublicKey, context, nonce *big.Int, issig bool) bool {
	if len(pl) == 0 {
		return true
	}
	if len(pl) != len(publicKeys) {
		return false
	}

	contributions := pl.challengeContributions(publicKeys, context, nonce)
	expectedChallenge := createChallenge(context, nonce, contributions, issig)
	for i, proof := range pl {
		if !proof.VerifyWithChallenge(publicKeys[i], expectedChallenge) {
			return false
		}
	}

	return true
}

func (builders ProofBuilderList) Challenge(context, nonce *big.Int, issig bool) *big.Int {
	// The secret key may be used across credentials supporting different attribute sizes.
	// So we should take it, and hence also its commitment, to fit within the smallest size -
	// otherwise it will be too big so that we cannot perform the range proof showing
	// that it is not too big.
	skCommitment, _ := RandomBigInt(DefaultSystemParameters[1024].LmCommit)

	commitmentValues := make([]*big.Int, 0, len(builders)*2)
	for _, pb := range builders {
		commitmentValues = append(commitmentValues, pb.Commit(skCommitment)...)
	}

	// Create a shared challenge
	return createChallenge(context, nonce, commitmentValues, issig)
}

func (builders ProofBuilderList) BuildDistributedProofList(
	challenge *big.Int, proofPs []*ProofP,
) (ProofList, error) {
	if proofPs != nil && len(builders) != len(proofPs) {
		return nil, errors.New("Not enough ProofP's given")
	}

	proofs := make([]Proof, len(builders))
	// Now create proofs using this challenge
	for i, v := range builders {
		proofs[i] = v.CreateProof(challenge)
		if proofPs != nil && proofPs[i] != nil {
			proofs[i].MergeProofP(proofPs[i], v.PublicKey())
		}
	}
	return proofs, nil
}

// BuildProofList builds a list of bounded proofs. For this it is given a list
// of ProofBuilders. Examples of proof builders are CredentialBuilder and
// DisclosureProofBuilder.
func (builders ProofBuilderList) BuildProofList(context, nonce *big.Int, issig bool) ProofList {
	challenge := builders.Challenge(context, nonce, issig)
	list, _ := builders.BuildDistributedProofList(challenge, nil)
	return list
}
