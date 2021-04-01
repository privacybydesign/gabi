package prooftools

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/keyproof"
	"github.com/privacybydesign/gabi/keys"
)

type QrRepresentationProofStructure keyproof.RepresentationProofStructure

func (s *QrRepresentationProofStructure) CommitmentsFromSecrets(pk *keys.PublicKey, list []*big.Int, bases keyproof.BaseLookup, secretdata keyproof.SecretLookup) []*big.Int {
	g := (*PublicKeyGroup)(pk)
	commitment := big.NewInt(1)
	var exp, contribution big.Int

	for _, curRhs := range s.Rhs {
		exp.Mul(big.NewInt(curRhs.Power), secretdata.Randomizer(curRhs.Secret))
		bases.Exp(&contribution, curRhs.Base, &exp, g.N)
		commitment.Mul(commitment, &contribution).Mod(commitment, g.N)
	}

	return append(list, commitment)
}

func (s *QrRepresentationProofStructure) CommitmentsFromProof(pk *keys.PublicKey, list []*big.Int, challenge *big.Int, bases keyproof.BaseLookup, proofdata keyproof.ProofLookup) []*big.Int {
	g := (*PublicKeyGroup)(pk)
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
