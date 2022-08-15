// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/rangeproof"
	"github.com/privacybydesign/gabi/revocation"

	"github.com/go-errors/errors"
)

// Proof represents a non-interactive zero-knowledge proof
type Proof interface {
	VerifyWithChallenge(pk *gabikeys.PublicKey, reconstructedChallenge *big.Int) bool
	SecretKeyResponse() *big.Int
	ChallengeContribution(pk *gabikeys.PublicKey) ([]*big.Int, error)
	MergeProofP(proofP *ProofP, pk *gabikeys.PublicKey)
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
	U              *big.Int         `json:"U"`
	C              *big.Int         `json:"c"`
	VPrimeResponse *big.Int         `json:"v_prime_response"`
	SResponse      *big.Int         `json:"s_response"`
	MUserResponses map[int]*big.Int `json:"m_user_responses,omitempty"`
}

func (p *ProofU) MergeProofP(proofP *ProofP, pk *gabikeys.PublicKey) {
	if proofP.P == nil { // new keyshare protocol version
		p.SResponse.Set(proofP.SResponse)
	} else {
		p.U.Mod(
			p.U.Mul(p.U, proofP.P),
			pk.N,
		)
		p.SResponse.Add(p.SResponse, proofP.SResponse)
	}
}

// Verify verifies whether the proof is correct.
func (p *ProofU) Verify(pk *gabikeys.PublicKey, context, nonce *big.Int) bool {
	contrib, err := p.ChallengeContribution(pk)
	if err != nil {
		return false
	}
	return p.VerifyWithChallenge(pk, createChallenge(context, nonce, contrib, false))
}

// correctResponseSizes checks the sizes of the elements in the ProofU proof.
func (p *ProofU) correctResponseSizes(pk *gabikeys.PublicKey) bool {
	minimum := big.NewInt(0)
	maximum := new(big.Int).Lsh(big.NewInt(1), pk.Params.LvPrimeCommit+1)
	maximum.Sub(maximum, big.NewInt(1))

	return p.VPrimeResponse.Cmp(minimum) >= 0 && p.VPrimeResponse.Cmp(maximum) <= 0
}

// VerifyWithChallenge verifies whether the proof is correct.
func (p *ProofU) VerifyWithChallenge(pk *gabikeys.PublicKey, reconstructedChallenge *big.Int) bool {
	return p.correctResponseSizes(pk) && p.C.Cmp(reconstructedChallenge) == 0
}

// reconstructUcommit reconstructs U from the information in the proof and the
// provided public key.
func (p *ProofU) reconstructUcommit(pk *gabikeys.PublicKey) (*big.Int, error) {
	// Reconstruct Ucommit
	// U_commit = U^{-C} * S^{VPrimeResponse} * R_0^{SResponse}
	Uc, err := common.ModPow(p.U, new(big.Int).Neg(p.C), pk.N)
	if err != nil {
		return nil, err
	}
	Sv, err := common.ModPow(pk.S, p.VPrimeResponse, pk.N)
	if err != nil {
		return nil, err
	}
	R0s, err := common.ModPow(pk.R[0], p.SResponse, pk.N)
	if err != nil {
		return nil, err
	}
	Ucommit := new(big.Int).Mul(Uc, Sv)
	Ucommit.Mul(Ucommit, R0s).Mod(Ucommit, pk.N)

	for i, miUserResponse := range p.MUserResponses {
		Rimi, err := common.ModPow(pk.R[i], miUserResponse, pk.N)
		if err != nil {
			return nil, err
		}
		Ucommit.Mul(Ucommit, Rimi).Mod(Ucommit, pk.N)
	}

	return Ucommit, nil
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
func (p *ProofU) ChallengeContribution(pk *gabikeys.PublicKey) ([]*big.Int, error) {
	Ucommit, err := p.reconstructUcommit(pk)
	if err != nil {
		return nil, err
	}
	return []*big.Int{p.U, Ucommit}, nil
}

// ProofS represents a proof.
type ProofS struct {
	C         *big.Int `json:"c"`
	EResponse *big.Int `json:"e_response"`
}

// Verify verifies the proof against the given public key, signature, context,
// and nonce.
func (p *ProofS) Verify(pk *gabikeys.PublicKey, signature *CLSignature, context, nonce *big.Int) bool {
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
	C                  *big.Int                    `json:"c"`
	A                  *big.Int                    `json:"A"`
	EResponse          *big.Int                    `json:"e_response"`
	VResponse          *big.Int                    `json:"v_response"`
	AResponses         map[int]*big.Int            `json:"a_responses"`
	ADisclosed         map[int]*big.Int            `json:"a_disclosed"`
	NonRevocationProof *revocation.Proof           `json:"nonrev_proof,omitempty"`
	RangeProofs        map[int][]*rangeproof.Proof `json:"rangeproofs,omitempty"`

	cachedRangeStructures map[int][]*rangeproof.ProofStructure
}

// MergeProofP merges a ProofP into the ProofD.
func (p *ProofD) MergeProofP(proofP *ProofP, _ *gabikeys.PublicKey) {
	if proofP.P == nil { // new protocol version
		p.SecretKeyResponse().Set(proofP.SResponse)
	} else {
		p.SecretKeyResponse().Add(p.SecretKeyResponse(), proofP.SResponse)
	}
}

func (p *ProofD) reconstructRangeProofStructures(pk *gabikeys.PublicKey) error {
	p.cachedRangeStructures = make(map[int][]*rangeproof.ProofStructure)
	for index, proofs := range p.RangeProofs {
		p.cachedRangeStructures[index] = []*rangeproof.ProofStructure{}
		for _, proof := range proofs {
			s, err := proof.ExtractStructure(index, pk)
			if err != nil {
				return err
			}
			p.cachedRangeStructures[index] = append(p.cachedRangeStructures[index], s)
		}
	}
	return nil
}

// correctResponseSizes checks the sizes of the elements in the ProofD proof.
func (p *ProofD) correctResponseSizes(pk *gabikeys.PublicKey) bool {
	minimum := big.NewInt(0)
	// Check range on the AResponses
	maximum := new(big.Int).Lsh(big.NewInt(1), pk.Params.LmCommit+1)
	maximum.Sub(maximum, big.NewInt(1))
	for _, aResponse := range p.AResponses {
		if aResponse.Cmp(minimum) < 0 || aResponse.Cmp(maximum) > 0 {
			return false
		}
	}

	// Check range EResponse
	maximum.Lsh(big.NewInt(1), pk.Params.LeCommit+1)
	maximum.Sub(maximum, big.NewInt(1))

	return p.EResponse.Cmp(minimum) >= 0 && p.EResponse.Cmp(maximum) <= 0
}

// reconstructZ reconstructs Z from the information in the proof and the
// provided public key.
func (p *ProofD) reconstructZ(pk *gabikeys.PublicKey) (*big.Int, error) {
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
	if known == nil {
		return nil, common.ErrNoModInverse
	}

	known.Mul(pk.Z, known)

	knownC, err := common.ModPow(known, new(big.Int).Neg(p.C), pk.N)
	if err != nil {
		return nil, err
	}
	Ae, err := common.ModPow(p.A, p.EResponse, pk.N)
	if err != nil {
		return nil, err
	}
	Sv, err := common.ModPow(pk.S, p.VResponse, pk.N)
	if err != nil {
		return nil, err
	}
	Rs := big.NewInt(1)
	for i, response := range p.AResponses {
		t, err := common.ModPow(pk.R[i], response, pk.N)
		if err != nil {
			return nil, err
		}
		Rs.Mul(Rs, t)
	}
	Z := new(big.Int).Mul(knownC, Ae)
	Z.Mul(Z, Rs).Mul(Z, Sv).Mod(Z, pk.N)

	return Z, nil
}

// Verify verifies the proof against the given public key, context, and nonce.
func (p *ProofD) Verify(pk *gabikeys.PublicKey, context, nonce1 *big.Int, issig bool) bool {
	contrib, err := p.ChallengeContribution(pk)
	if err != nil {
		return false
	}
	return p.VerifyWithChallenge(pk, createChallenge(context, nonce1, contrib, issig))
}

func (p *ProofD) HasNonRevocationProof() bool {
	return p.NonRevocationProof != nil
}

// VerifyWithChallenge verifies the proof against the given public key and the provided
// reconstructed challenge.
func (p *ProofD) VerifyWithChallenge(pk *gabikeys.PublicKey, reconstructedChallenge *big.Int) bool {
	var notrevoked bool
	// Validate non-revocation
	if p.HasNonRevocationProof() {
		revIdx := p.revocationAttrIndex()
		if revIdx < 0 || p.AResponses[revIdx] == nil {
			return false
		}
		notrevoked = p.NonRevocationProof.VerifyWithChallenge(pk, reconstructedChallenge) &&
			p.NonRevocationProof.Responses["alpha"].Cmp(p.AResponses[revIdx]) == 0
	} else {
		notrevoked = true
	}
	// Range proofs were already validated during challenge reconstruction
	return notrevoked &&
		p.correctResponseSizes(pk) &&
		p.C.Cmp(reconstructedChallenge) == 0
}

// ChallengeContribution returns the contribution of this proof to the
// challenge.
func (p *ProofD) ChallengeContribution(pk *gabikeys.PublicKey) ([]*big.Int, error) {
	z, err := p.reconstructZ(pk)
	if err != nil {
		return nil, errors.WrapPrefix(err, "Could not reconstruct Z", 0)
	}

	l := []*big.Int{p.A, z}
	if p.NonRevocationProof != nil {
		revIdx := p.revocationAttrIndex()
		if revIdx < 0 || p.AResponses[revIdx] == nil {
			return nil, errors.New("no revocation response found")
		}
		if err := p.NonRevocationProof.SetExpected(pk, p.C, p.AResponses[revIdx]); err != nil {
			return nil, err
		}
		contrib := p.NonRevocationProof.ChallengeContributions(pk)
		l = append(l, contrib...)
	}

	if p.RangeProofs != nil {
		if p.cachedRangeStructures == nil {
			if err := p.reconstructRangeProofStructures(pk); err != nil {
				return nil, err
			}
		}
		// need stable attribute order for rangeproof contributions, so determine max undisclosed attribute
		maxAttribute := 0
		for k := range p.AResponses {
			if k > maxAttribute {
				maxAttribute = k
			}
		}
		for index := 0; index <= maxAttribute; index++ {
			structures, ok := p.cachedRangeStructures[index]
			if !ok {
				continue
			}
			for i, s := range structures {
				p.RangeProofs[index][i].MResponse = new(big.Int).Set(p.AResponses[index])
				if !s.VerifyProofStructure(pk, p.RangeProofs[index][i]) {
					return nil, errors.New("Invalid range proof")
				}
				l = append(l, s.CommitmentsFromProof(pk, p.RangeProofs[index][i], p.C)...)
			}
		}
	}

	return l, nil
}

// SecretKeyResponse returns the secret key response (as part of Proof
// interface).
func (p *ProofD) SecretKeyResponse() *big.Int {
	return p.AResponses[0]
}

func (p *ProofD) revocationAttrIndex() int {
	params := revocation.Parameters
	max := new(big.Int).Lsh(big.NewInt(1), params.AttributeSize+params.ChallengeLength+params.ZkStat+1)
	for idx, i := range p.AResponses {
		if i.Cmp(max) < 0 {
			return idx
		}
	}
	return -1
}

// Challenge returns the challenge in the proof (part of the Proof interface).
func (p *ProofD) Challenge() *big.Int {
	return p.C
}

// ProofP is a keyshare server's knowledge of its part of the secret key.
type ProofP struct {
	P         *big.Int `json:"P,omitempty"`
	C         *big.Int `json:"c"`
	SResponse *big.Int `json:"s_response"`
}

// ProofPCommitment is a keyshare server's first message in its proof of knowledge
// of its part of the secret key.
type ProofPCommitment struct {
	P       *big.Int
	Pcommit *big.Int
}

// GenerateNonce generates a nonce for use in proofs
func GenerateNonce() (*big.Int, error) {
	return common.RandomBigInt(gabikeys.DefaultSystemParameters[2048].Lstatzk)
}
