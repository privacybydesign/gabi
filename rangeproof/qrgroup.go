package rangeproof

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/keyproof"
)

// QrGroup represents the group of quadratic residues modulo n = p*q, i.e. ((Z/nZ)*)^2
// where p, q, (p-1)/2 and (q-1)/2 are all prime.
type (
	QrGroup struct {
		N    *big.Int // RSA modulus
		R, S *big.Int // Base points in QR_n
	}

	qrRepresentationProofStructure keyproof.RepresentationProofStructure
)

func NewQrGroup(modulus, R, S *big.Int) QrGroup {
	g := QrGroup{
		N: new(big.Int).Set(modulus),
		R: new(big.Int).Set(R),
		S: new(big.Int).Set(S),
	}
	return g
}

func (g *qrGroup) Base(name string) *big.Int {
	switch name {
	case "R":
		return g.R
	case "S":
		return g.S
	default:
		return nil
	}
}

func (g *qrGroup) Exp(ret *big.Int, name string, exp, n *big.Int) bool {
	switch name {
	case "R", "S":
		ret.Exp(g.Base(name), exp, n)
		return true
	}
	return false
}

func (g *qrGroup) Names() []string {
	return []string{"R", "S"}
}

func (s *qrRepresentationProofStructure) commitmentsFromSecrets(g *qrGroup, list []*big.Int, bases keyproof.BaseLookup, secretdata keyproof.SecretLookup) []*big.Int {
	commitment := big.NewInt(1)
	var exp, contribution big.Int

	for _, curRhs := range s.Rhs {
		exp.Mul(big.NewInt(curRhs.Power), secretdata.Randomizer(curRhs.Secret))
		bases.Exp(&contribution, curRhs.Base, &exp, g.N)
		commitment.Mul(commitment, &contribution).Mod(commitment, g.N)
	}

	return append(list, commitment)
}

func (s *qrRepresentationProofStructure) commitmentsFromProof(g *qrGroup, list []*big.Int, challenge *big.Int, bases keyproof.BaseLookup, proofdata keyproof.ProofLookup) []*big.Int {
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
