package prooftools

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/keyproof"
)

type QrRepresentationProofStructure keyproof.RepresentationProofStructure

func (s *QrRepresentationProofStructure) CommitmentsFromSecrets(pk *gabikeys.PublicKey, list []*big.Int, bases keyproof.BaseLookup, secretdata keyproof.SecretLookup) []*big.Int {
	commitment := big.NewInt(1)
	var exp, contribution big.Int

	for _, curRhs := range s.Rhs {
		exp.Mul(big.NewInt(curRhs.Power), secretdata.Randomizer(curRhs.Secret))
		bases.Exp(&contribution, curRhs.Base, &exp, pk.N)
		commitment.Mul(commitment, &contribution).Mod(commitment, pk.N)
	}

	return append(list, commitment)
}

func (s *QrRepresentationProofStructure) CommitmentsFromProof(pk *gabikeys.PublicKey, list []*big.Int, challenge *big.Int, bases keyproof.BaseLookup, proofdata keyproof.ProofLookup) []*big.Int {
	var tmp, lhs big.Int
	lhs.SetUint64(1)
	for _, curLhs := range s.Lhs {
		bases.Exp(&tmp, curLhs.Base, curLhs.Power, pk.N)
		lhs.Mul(&lhs, &tmp).Mod(&lhs, pk.N)
	}
	lhs.ModInverse(&lhs, pk.N)

	commitment := new(big.Int).Exp(&lhs, challenge, pk.N)
	var exp, contribution big.Int
	for _, curRhs := range s.Rhs {
		exp.Mul(big.NewInt(curRhs.Power), proofdata.ProofResult(curRhs.Secret))
		bases.Exp(&contribution, curRhs.Base, &exp, pk.N)
		commitment.Mul(commitment, &contribution).Mod(commitment, pk.N)
	}

	return append(list, commitment)
}
