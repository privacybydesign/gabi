package keyproof

import "github.com/privacybydesign/gabi/big"

type LhsContribution struct {
	Base  string
	Power *big.Int
}

type RhsContribution struct {
	Base   string
	Secret string
	Power  int64
}

type RepresentationProofStructure struct {
	Lhs []LhsContribution
	Rhs []RhsContribution
}

func (s *RepresentationProofStructure) numRangeProofs() int {
	return 0
}

func (s *RepresentationProofStructure) numCommitments() int {
	return 1
}

func (s *RepresentationProofStructure) generateCommitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) []*big.Int {
	commitment := big.NewInt(1)
	var exp, contribution big.Int

	for _, curRhs := range s.Rhs {
		// Base := bases.Exp(curRhs.Base, big.NewInt(curRhs.Power), g.P)
		// contribution := new(big.Int).Exp(Base, secretdata.GetRandomizer(curRhs.Secret), g.P)
		exp.Set(big.NewInt(curRhs.Power))
		exp.Mul(&exp, secretdata.GetRandomizer(curRhs.Secret))
		g.orderMod.Mod(&exp, &exp)
		bases.Exp(&contribution, curRhs.Base, &exp, g.p)
		commitment.Mul(commitment, &contribution)
		g.pMod.Mod(commitment, commitment)
	}

	return append(list, commitment)
}

func (s *RepresentationProofStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proofdata ProofLookup) []*big.Int {
	var base, tmp, lhs big.Int
	lhs.SetUint64(1)
	for _, curLhs := range s.Lhs {
		bases.Exp(&base, curLhs.Base, curLhs.Power, g.p)
		tmp.Mul(&lhs, &base)
		g.pMod.Mod(&lhs, &tmp)
	}

	commitment := new(big.Int).Exp(&lhs, challenge, g.p)
	var exp, contribution big.Int
	for _, curRhs := range s.Rhs {
		// Base := bases.Exp(curRhs.Base, big.NewInt(curRhs.Power), g.P)
		// contribution := new(big.Int).Exp(Base, proofdata.GetResult(curRhs.Secret), g.P)
		exp.Mul(big.NewInt(curRhs.Power), proofdata.GetResult(curRhs.Secret))
		g.orderMod.Mod(&exp, &exp)
		bases.Exp(&contribution, curRhs.Base, &exp, g.p)
		commitment.Mul(commitment, &contribution)
		g.pMod.Mod(commitment, commitment)
	}

	return append(list, commitment)
}

func (s *RepresentationProofStructure) isTrue(g group, bases BaseLookup, secretdata SecretLookup) bool {
	var base, tmp, lhs, rhs big.Int
	lhs.SetUint64(1)
	for _, curLhs := range s.Lhs {
		bases.Exp(&base, curLhs.Base, curLhs.Power, g.p)
		tmp.Mul(&lhs, &base)
		g.pMod.Mod(&lhs, &tmp)
	}

	rhs.SetUint64(1)
	var exp, contribution big.Int
	for _, curRhs := range s.Rhs {
		exp.SetInt64(curRhs.Power)
		tmp.Mul(&exp, secretdata.GetSecret(curRhs.Secret))
		g.orderMod.Mod(&exp, &tmp)
		bases.Exp(&contribution, curRhs.Base, &exp, g.p)
		tmp.Mul(&rhs, &contribution)
		g.pMod.Mod(&rhs, &tmp)
	}

	return lhs.Cmp(&rhs) == 0
}
