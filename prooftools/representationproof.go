package prooftools

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/keyproof"
)

type QrRepresentationProofStructure keyproof.RepresentationProofStructure

func (s *QrRepresentationProofStructure) CommitmentsFromSecrets(g *PublicKeyGroup, list []*big.Int, bases keyproof.BaseLookup, secretdata keyproof.SecretLookup) []*big.Int {
	commitment := big.NewInt(1)
	var exp, contribution big.Int

	for _, curRhs := range s.Rhs {
		exp.Mul(big.NewInt(curRhs.Power), secretdata.Randomizer(curRhs.Secret))
		bases.Exp(&contribution, curRhs.Base, &exp, g.N)
		commitment.Mul(commitment, &contribution).Mod(commitment, g.N)
	}

	return append(list, commitment)
}

func (s *QrRepresentationProofStructure) CommitmentsFromProof(g *PublicKeyGroup, list []*big.Int, challenge *big.Int, bases keyproof.BaseLookup, proofdata keyproof.ProofLookup) []*big.Int {
	var tmp, lhs big.Int
	lhs.SetUint64(1)
	for _, curLhs := range s.Lhs {
		bases.Exp(&tmp, curLhs.Base, curLhs.Power, g.N)
		lhs.Mul(&lhs, &tmp).Mod(&lhs, g.N)
	}
	lhs.ModInverse(&lhs, g.N)

	commitment := new(big.Int).Exp(&lhs, challenge, g.N)
	var exp, contribution big.Int
	for _, curRhs := range s.Rhs {
		exp.Mul(big.NewInt(curRhs.Power), proofdata.ProofResult(curRhs.Secret))
		bases.Exp(&contribution, curRhs.Base, &exp, g.N)
		commitment.Mul(commitment, &contribution).Mod(commitment, g.N)
	}

	return append(list, commitment)
}
