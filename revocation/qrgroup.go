package revocation

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/keyproof"
)

// QrGroup represents the group of quadratic residues modulo n = p*q, i.e. ((Z/nZ)*)^2
// where p, q, (p-1)/2 and (q-1)/2 are all prime.
type (
	QrGroup struct {
		N    *big.Int // RSA modulus
		G, H *big.Int // Base points in QR_n

		// derivative bounds
		nDiv4       *big.Int // n/4
		nDiv4twoZk  *big.Int // n/4 * 2^(k'+k'')
		nbDiv4twoZk *big.Int // n/4 * B * 2^(k'+k'')
	}

	qrRepresentationProofStructure keyproof.RepresentationProofStructure
)

func NewQrGroup(modulus *big.Int) QrGroup {
	g := QrGroup{N: modulus}
	g.nDiv4 = new(big.Int).Div(g.N, big.NewInt(4))
	g.nDiv4twoZk = new(big.Int).Mul(g.nDiv4, parameters.twoZk)
	g.nbDiv4twoZk = new(big.Int).Mul(g.nDiv4twoZk, parameters.b)
	return g
}

func (g *qrGroup) GetBase(name string) *big.Int {
	switch name {
	case "g":
		return g.G
	case "h":
		return g.H
	default:
		return nil
	}
}

func (g *qrGroup) Exp(ret *big.Int, name string, exp, n *big.Int) bool {
	switch name {
	case "g", "h":
		ret.Exp(g.GetBase(name), exp, n)
		return true
	}
	return false
}

func (g *qrGroup) GetNames() []string {
	return []string{"g", "h"}
}

func (s *qrRepresentationProofStructure) generateCommitmentsFromSecrets(g *qrGroup, list []*big.Int, bases keyproof.BaseLookup, secretdata keyproof.SecretLookup) []*big.Int {
	commitment := big.NewInt(1)
	var exp, contribution big.Int

	for _, curRhs := range s.Rhs {
		exp.Mul(big.NewInt(curRhs.Power), secretdata.GetRandomizer(curRhs.Secret))
		bases.Exp(&contribution, curRhs.Base, &exp, g.N)
		commitment.Mul(commitment, &contribution).Mod(commitment, g.N)
	}

	return append(list, commitment)
}

func (s *qrRepresentationProofStructure) generateCommitmentsFromProof(g *qrGroup, list []*big.Int, challenge *big.Int, bases keyproof.BaseLookup, proofdata keyproof.ProofLookup) []*big.Int {
	var tmp, lhs big.Int
	lhs.SetUint64(1)
	for _, curLhs := range s.Lhs {
		bases.Exp(&tmp, curLhs.Base, curLhs.Power, g.N)
		lhs.Mul(&lhs, &tmp).Mod(&lhs, g.N).ModInverse(&lhs, g.N)
	}

	commitment := new(big.Int).Exp(&lhs, challenge, g.N)
	var exp, contribution big.Int
	for _, curRhs := range s.Rhs {
		exp.Mul(big.NewInt(curRhs.Power), proofdata.GetResult(curRhs.Secret))
		bases.Exp(&contribution, curRhs.Base, &exp, g.N)
		commitment.Mul(commitment, &contribution).Mod(commitment, g.N)
	}

	return append(list, commitment)
}
