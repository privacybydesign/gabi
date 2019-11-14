// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/revocation"
)

// Proof represents a non-interactive zero-knowledge proof
type Proof interface {
	VerifyWithChallenge(pk *PublicKey, reconstructedChallenge *big.Int) bool
	SecretKeyResponse() *big.Int
	ChallengeContribution(pk *PublicKey) []*big.Int
	MergeProofP(proofP *ProofP, pk *PublicKey)
}

// createChallenge creates a challenge based on context, nonce and the
// contributions.
func createChallenge(context, nonce *big.Int, contributions []*big.Int, issig bool) *big.Int {
	// Basically, sandwich the contributions between context and nonce
	input := make([]*big.Int, 2+len(contributions))
	input[0] = context
	copy(input[1:1+len(contributions)], contributions)
	input[len(input)-1] = nonce
	return common.HashCommit(input, issig)
}

// ProofU represents a proof of correctness of the commitment in the first phase
// of the issuance protocol.
type ProofU struct {
	U              *big.Int `json:"U"`
	C              *big.Int `json:"c"`
	VPrimeResponse *big.Int `json:"v_prime_response"`
	SResponse      *big.Int `json:"s_response"`
}

func (p *ProofU) MergeProofP(proofP *ProofP, pk *PublicKey) {
	p.U.Mod(
		p.U.Mul(p.U, proofP.P),
		pk.N,
	)
	p.SResponse.Add(p.SResponse, proofP.SResponse)
}

// Verify verifies whether the proof is correct.
func (p *ProofU) Verify(pk *PublicKey, context, nonce *big.Int) bool {
	return p.VerifyWithChallenge(pk, createChallenge(context, nonce, p.ChallengeContribution(pk), false))
}

// correctResponseSizes checks the sizes of the elements in the ProofU proof.
func (p *ProofU) correctResponseSizes(pk *PublicKey) bool {
	maximum := new(big.Int).Lsh(big.NewInt(1), pk.Params.LvPrimeCommit+1)
	maximum.Sub(maximum, big.NewInt(1))
	minimum := new(big.Int).Neg(maximum)

	return p.VPrimeResponse.Cmp(minimum) >= 0 && p.VPrimeResponse.Cmp(maximum) <= 0
}

// VerifyWithChallenge verifies whether the proof is correct.
func (p *ProofU) VerifyWithChallenge(pk *PublicKey, reconstructedChallenge *big.Int) bool {
	return p.correctResponseSizes(pk) && p.C.Cmp(reconstructedChallenge) == 0
}

// reconstructUcommit reconstructs U from the information in the proof and the
// provided public key.
func (p *ProofU) reconstructUcommit(pk *PublicKey) *big.Int {
	// Reconstruct Ucommit
	// U_commit = U^{-C} * S^{VPrimeResponse} * R_0^{SResponse}
	Uc := common.ModPow(p.U, new(big.Int).Neg(p.C), pk.N)
	Sv := common.ModPow(pk.S, p.VPrimeResponse, pk.N)
	R0s := common.ModPow(pk.R[0], p.SResponse, pk.N)
	Ucommit := new(big.Int).Mul(Uc, Sv)
	Ucommit.Mul(Ucommit, R0s).Mod(Ucommit, pk.N)

	return Ucommit
}

// SecretKeyResponse returns the secret key response (as part of Proof
// interface).
func (p *ProofU) SecretKeyResponse() *big.Int {
	return p.SResponse
}

// Challenge returns the challenge in the proof (part of the Proof interface).
func (p *ProofU) Challenge() *big.Int {
	return p.C
}

// ChallengeContribution returns the contribution of this proof to the
// challenge.
func (p *ProofU) ChallengeContribution(pk *PublicKey) []*big.Int {
	return []*big.Int{p.U, p.reconstructUcommit(pk)}
}

// ProofS represents a proof.
type ProofS struct {
	C         *big.Int `json:"c"`
	EResponse *big.Int `json:"e_response"`
}

// Verify verifies the proof agains the given public key, signature, context,
// and nonce.
func (p *ProofS) Verify(pk *PublicKey, signature *CLSignature, context, nonce *big.Int) bool {
	// Reconstruct A_commit
	// ACommit = A^{C + EResponse * e}
	exponent := new(big.Int).Mul(p.EResponse, signature.E)
	exponent.Add(p.C, exponent)
	ACommit := new(big.Int).Exp(signature.A, exponent, pk.N)

	// Reconstruct Q
	Q := new(big.Int).Exp(signature.A, signature.E, pk.N)

	// Recalculate hash
	cPrime := common.HashCommit([]*big.Int{context, Q, signature.A, nonce, ACommit}, false)

	return p.C.Cmp(cPrime) == 0
}

// ProofD represents a proof in the showing protocol.
type ProofD struct {
	C                     *big.Int          `json:"c"`
	A                     *big.Int          `json:"A"`
	EResponse             *big.Int          `json:"e_response"`
	VResponse             *big.Int          `json:"v_response"`
	AResponses            map[int]*big.Int  `json:"a_responses"`
	NonRevocationResponse *big.Int          `json:"nonrev_response,omitempty"`
	NonRevocationProof    *revocation.Proof `json:"nonrev_proof,omitempty"`
	ADisclosed            map[int]*big.Int  `json:"a_disclosed"`
}

func (p *ProofD) MergeProofP(proofP *ProofP, pk *PublicKey) {
	p.SecretKeyResponse().Add(p.SecretKeyResponse(), proofP.SResponse)
}

// correctResponseSizes checks the sizes of the elements in the ProofD proof.
func (p *ProofD) correctResponseSizes(pk *PublicKey) bool {
	// Check range on the AResponses
	maximum := new(big.Int).Lsh(big.NewInt(1), pk.Params.LmCommit+1)
	maximum.Sub(maximum, big.NewInt(1))
	minimum := new(big.Int).Neg(maximum)
	for _, aResponse := range p.AResponses {
		if aResponse.Cmp(minimum) < 0 || aResponse.Cmp(maximum) > 0 {
			return false
		}
	}

	// Check range EResponse
	maximum.Lsh(big.NewInt(1), pk.Params.LeCommit+1)
	maximum.Sub(maximum, big.NewInt(1))
	minimum.Neg(maximum)

	if p.EResponse.Cmp(minimum) < 0 || p.EResponse.Cmp(maximum) > 0 {
		return false
	}

	return true
}

// reconstructZ reconstructs Z from the information in the proof and the
// provided public key.
func (p *ProofD) reconstructZ(pk *PublicKey) *big.Int {
	// known = Z / ( prod_{disclosed} R_i^{a_i} * A^{2^{l_e - 1}} )
	numerator := new(big.Int).Lsh(big.NewInt(1), pk.Params.Le-1)
	numerator.Exp(p.A, numerator, pk.N)
	for i, attribute := range p.ADisclosed {
		exp := attribute
		if exp.BitLen() > int(pk.Params.Lm) {
			exp = common.IntHashSha256(exp.Bytes())
		}
		numerator.Mul(numerator, new(big.Int).Exp(pk.R[i], exp, pk.N))
	}

	known := new(big.Int).ModInverse(numerator, pk.N)
	known.Mul(pk.Z, known)

	knownC := common.ModPow(known, new(big.Int).Neg(p.C), pk.N)
	Ae := common.ModPow(p.A, p.EResponse, pk.N)
	Sv := common.ModPow(pk.S, p.VResponse, pk.N)
	Rs := big.NewInt(1)
	for i, response := range p.AResponses {
		Rs.Mul(Rs, common.ModPow(pk.R[i], response, pk.N))
	}
	Z := new(big.Int).Mul(knownC, Ae)
	Z.Mul(Z, Rs).Mul(Z, Sv).Mod(Z, pk.N)

	if p.NonRevocationResponse != nil {
		Z.Mul(Z, common.ModPow(pk.T, p.NonRevocationResponse, pk.N)).Mod(Z, pk.N)
	}

	return Z
}

// Verify verifies the proof against the given public key, context, and nonce.
func (p *ProofD) Verify(pk *PublicKey, context, nonce1 *big.Int, issig bool) bool {
	return p.VerifyWithChallenge(pk, createChallenge(context, nonce1, p.ChallengeContribution(pk), issig))
}

func (p *ProofD) HasNonRevocationProof() bool {
	return p.NonRevocationProof != nil
}

// Verify verifies the proof against the given public key and the provided
// reconstruted challenge.
func (p *ProofD) VerifyWithChallenge(pk *PublicKey, reconstructedChallenge *big.Int) bool {
	var notrevoked bool
	if p.HasNonRevocationProof() {
		rpk, err := pk.RevocationKey()
		if err != nil {
			return false
		}
		notrevoked = p.NonRevocationProof.VerifyWithChallenge(rpk, reconstructedChallenge) &&
			p.NonRevocationProof.Results["alpha"].Cmp(p.NonRevocationResponse) == 0
	} else {
		notrevoked = true
	}
	return notrevoked &&
		p.correctResponseSizes(pk) &&
		p.C.Cmp(reconstructedChallenge) == 0
}

// ChallengeContribution returns the contribution of this proof to the
// challenge.
func (p *ProofD) ChallengeContribution(pk *PublicKey) []*big.Int {
	l := []*big.Int{p.A, p.reconstructZ(pk)}
	if p.NonRevocationProof != nil {
		revPk, _ := pk.RevocationKey()
		l = append(l, p.NonRevocationProof.ChallengeContributions(revPk.Group)...)
	}
	return l
}

// SecretKeyResponse returns the secret key response (as part of Proof
// interface).
func (p *ProofD) SecretKeyResponse() *big.Int {
	return p.AResponses[0]
}

// Challenge returns the challenge in the proof (part of the Proof interface).
func (p *ProofD) Challenge() *big.Int {
	return p.C
}

// ProofP is a keyshare server's knowledge of its part of the secret key.
type ProofP struct {
	P         *big.Int `json:"P"`
	C         *big.Int `json:"c"`
	SResponse *big.Int `json:"s_response"`
}

// ProofPCommitment is a keyshare server's first message in its proof of knowledge
// of its part of the secret key.
type ProofPCommitment struct {
	P       *big.Int
	Pcommit *big.Int
}

// Generate nonce for use in proofs
func GenerateNonce() (*big.Int, error) {
	return common.RandomBigInt(DefaultSystemParameters[2048].Lstatzk)
}
