package keyproof

import (
	"github.com/privacybydesign/gabi/big"
)

type lhsContribution struct {
	base  string
	power *big.Int
}

type rhsContribution struct {
	base   string
	secret string
	power  int64
}

type representationProofStructure struct {
	lhs []lhsContribution
	rhs []rhsContribution
}

func (s *representationProofStructure) generateCommitmentsFromSecrets(g group, list []*big.Int, bases baseLookup, secretdata secretLookup) []*big.Int {
	commitment := big.NewInt(1)
	var exp, contribution big.Int

	for _, curRhs := range s.rhs {
		// base := bases.Exp(curRhs.Base, big.NewInt(curRhs.Power), g.P)
		// contribution := new(big.Int).Exp(base, secretdata.GetRandomizer(curRhs.Secret), g.P)
		exp.Set(big.NewInt(curRhs.power))
		exp.Mul(&exp, secretdata.getRandomizer(curRhs.secret))
		g.orderMod.Mod(&exp, &exp)
		bases.exp(&contribution, curRhs.base, &exp, g.p)
		commitment.Mul(commitment, &contribution)
		g.pMod.Mod(commitment, commitment)
	}

	return append(list, commitment)
}

func (s *representationProofStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases baseLookup, proofdata proofLookup) []*big.Int {
	var base, tmp, lhs big.Int
	lhs.SetUint64(1)
	for _, curLhs := range s.lhs {
		bases.exp(&base, curLhs.base, curLhs.power, g.p)
		tmp.Mul(&lhs, &base)
		g.pMod.Mod(&lhs, &tmp)
	}

	commitment := new(big.Int).Exp(&lhs, challenge, g.p)
	var exp, contribution big.Int
	for _, curRhs := range s.rhs {
		// base := bases.Exp(curRhs.Base, big.NewInt(curRhs.Power), g.P)
		// contribution := new(big.Int).Exp(base, proofdata.GetResult(curRhs.Secret), g.P)
		exp.Mul(big.NewInt(curRhs.power), proofdata.getResult(curRhs.secret))
		g.orderMod.Mod(&exp, &exp)
		bases.exp(&contribution, curRhs.base, &exp, g.p)
		commitment.Mul(commitment, &contribution)
		g.pMod.Mod(commitment, commitment)
	}

	return append(list, commitment)
}

func (s *representationProofStructure) isTrue(g group, bases baseLookup, secretdata secretLookup) bool {
	var base, tmp, lhs, rhs big.Int
	lhs.SetUint64(1)
	for _, curLhs := range s.lhs {
		bases.exp(&base, curLhs.base, curLhs.power, g.p)
		tmp.Mul(&lhs, &base)
		g.pMod.Mod(&lhs, &tmp)
	}

	rhs.SetUint64(1)
	var exp, contribution big.Int
	for _, curRhs := range s.rhs {
		exp.SetInt64(curRhs.power)
		tmp.Mul(&exp, secretdata.getSecret(curRhs.secret))
		g.orderMod.Mod(&exp, &tmp)
		bases.exp(&contribution, curRhs.base, &exp, g.p)
		tmp.Mul(&rhs, &contribution)
		g.pMod.Mod(&rhs, &tmp)
	}

	return lhs.Cmp(&rhs) == 0
}

func (s *representationProofStructure) numRangeProofs() int {
	return 0
}

func (s *representationProofStructure) numCommitments() int {
	return 1
}
