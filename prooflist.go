// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"errors"
	"math/big"
)

// ProofBuilder is an interface for a prof builder. That is, an object to hold
// the state to build a list of bounded proofs (see ProofList).
type ProofBuilder interface {
	Commit(skRandomizer *big.Int) []*big.Int
	CreateProof(challenge *big.Int) Proof
}

// ProofList represents a list of (typically bounded) proofs.
type ProofList []Proof

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
func (pl ProofList) Verify(publicKeys []*PublicKey, context, nonce *big.Int, shouldBeBound bool) bool {
	if len(pl) == 0 {
		return true
	}

	if len(pl) != len(publicKeys) {
		return false
	}

	if shouldBeBound {
		contributions := pl.challengeContributions(publicKeys, context, nonce)
		expectedChallenge := createChallenge(context, nonce, contributions)
		expectedSecretKeyResponse := pl[0].SecretKeyResponse()
		for i, proof := range pl {
			if expectedSecretKeyResponse.Cmp(proof.SecretKeyResponse()) != 0 ||
				!proof.VerifyWithChallenge(publicKeys[i], expectedChallenge) {
				return false
			}
		}
	} else {
		for i, proof := range pl {
			// if !proof.Verify(publicKeys[i], context, nonce) {
			if !proof.VerifyWithChallenge(publicKeys[i], createChallenge(context, nonce, proof.ChallengeContribution(publicKeys[i]))) {
				return false
			}
		}
	}

	return true
}

// BuildProofList builds a list of bounded proofs. For this it is given a list
// of ProofBuilders. Examples of proof builders are Builder and
// DisclosureProofBuilder.
func BuildProofList(params *SystemParameters, context, nonce *big.Int, proofBuilders []ProofBuilder) ProofList {
	skCommitment, _ := randomBigInt(params.LmCommit)

	commitmentValues := make([]*big.Int, 0, len(proofBuilders)*2)
	for _, pb := range proofBuilders {
		commitmentValues = append(commitmentValues, pb.Commit(skCommitment)...)
	}

	// Create a shared challenge
	challenge := createChallenge(context, nonce, commitmentValues)

	proofs := make([]Proof, len(proofBuilders))
	// Now create proofs using this challenge
	for i, v := range proofBuilders {
		proofs[i] = v.CreateProof(challenge)
	}
	return proofs
}
