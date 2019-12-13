package keyproof

import (
	"strings"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
)

type (
	pedersenStructure struct {
		name           string
		representation representationProofStructure
	}

	pedersenCommit struct {
		name    string
		secretv secret
		hider   secret
		commit  *big.Int

		g *group
	}

	PedersenProof struct {
		name    string
		Commit  *big.Int
		Sresult Proof
		Hresult Proof
	}
)

func newPedersenStructure(name string) pedersenStructure {
	return pedersenStructure{
		name,
		representationProofStructure{
			[]lhsContribution{
				{name, big.NewInt(1)},
			},
			[]rhsContribution{
				{"g", name, 1},
				{"h", strings.Join([]string{name, "hider"}, "_"), 1},
			},
		},
	}
}

func newPedersenRangeProofStructure(name string, l1 uint, l2 uint) rangeProofStructure {
	var structure rangeProofStructure
	structure.lhs = []lhsContribution{
		{name, big.NewInt(1)},
	}
	structure.rhs = []rhsContribution{
		{"g", name, 1},
		{"h", strings.Join([]string{name, "hider"}, "_"), 1},
	}
	structure.rangeSecret = name
	structure.l1 = l1
	structure.l2 = l2
	return structure
}

func (s *pedersenStructure) numRangeProofs() int {
	return s.representation.numRangeProofs()
}

func (s *pedersenStructure) numCommitments() int {
	return s.representation.numCommitments() + 1
}

func (s *pedersenStructure) generateCommitmentsFromSecrets(g group, list []*big.Int, value *big.Int) ([]*big.Int, pedersenCommit) {
	var result pedersenCommit
	result.name = s.name
	result.secretv = newSecret(g, s.name, value)
	result.hider = newSecret(g, strings.Join([]string{s.name, "hider"}, "_"), common.FastRandomBigInt(g.order))
	result.g = &g
	result.commit = new(big.Int)
	result.exp(result.commit, s.name, big.NewInt(1), g.p)

	bases := newBaseMerge(&result, &g)
	list = append(list, result.commit)
	return s.representation.generateCommitmentsFromSecrets(g, list, &bases, &result), result
}

func (s *pedersenStructure) generateCommitmentsDuplicate(g group, list []*big.Int, value *big.Int, hider *big.Int) ([]*big.Int, pedersenCommit) {
	var result = pedersenCommit{
		name:    s.name,
		secretv: newSecret(g, s.name, value),
		hider:   newSecret(g, strings.Join([]string{s.name, "hider"}, "_"), hider),
		g:       &g,
		commit:  new(big.Int),
	}
	result.exp(result.commit, s.name, big.NewInt(1), g.p)

	bases := newBaseMerge(&result, &g)
	list = append(list, result.commit)
	return s.representation.generateCommitmentsFromSecrets(g, list, &bases, &result), result
}

func (s *pedersenStructure) buildProof(g group, challenge *big.Int, commit pedersenCommit) PedersenProof {
	var proof PedersenProof
	proof.Commit = commit.commit
	proof.Sresult = commit.secretv.buildProof(g, challenge)
	proof.Hresult = commit.hider.buildProof(g, challenge)
	return proof
}

func (s *pedersenStructure) fakeProof(g group) PedersenProof {
	var proof PedersenProof
	var gCommit, hCommit big.Int
	g.exp(&gCommit, "g", common.FastRandomBigInt(g.order), g.p)
	g.exp(&hCommit, "h", common.FastRandomBigInt(g.order), g.p)
	proof.Commit = new(big.Int)
	proof.Commit.Mul(&gCommit, &hCommit)
	proof.Commit.Mod(proof.Commit, g.p)
	proof.Sresult = fakeProof(g)
	proof.Hresult = fakeProof(g)
	return proof
}

func (s *pedersenStructure) verifyProofStructure(proof PedersenProof) bool {
	return proof.Commit != nil && proof.Hresult.verifyStructure() && proof.Sresult.verifyStructure()
}

func (s *pedersenStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, proof PedersenProof) []*big.Int {
	proof.setName(s.name)
	bases := newBaseMerge(&proof, &g)
	list = append(list, proof.Commit)
	return s.representation.generateCommitmentsFromProof(g, list, challenge, &bases, &proof)
}

func (c *pedersenCommit) base(name string) *big.Int {
	if name == c.name {
		return c.commit
	} else {
		return nil
	}
}

func (c *pedersenCommit) exp(ret *big.Int, name string, exp, P *big.Int) bool {
	if name != c.name {
		return false
	}
	// We effectively compute c.commit^exp, which is more expensive to do
	// directly, than with two table-backed exponentiations.
	var exp1, exp2, ret1, ret2, tmp big.Int
	tmp.Mul(c.secretv.secretv, exp)
	c.g.orderMod.Mod(&exp1, &tmp)
	tmp.Mul(c.hider.secretv, exp)
	c.g.orderMod.Mod(&exp2, &tmp)
	c.g.exp(&ret1, "g", &exp1, c.g.p)
	c.g.exp(&ret2, "h", &exp2, c.g.p)
	tmp.Mul(&ret1, &ret2)
	c.g.pMod.Mod(ret, &tmp)
	return true
}

func (c *pedersenCommit) names() []string {
	return []string{c.name}
}

func (c *pedersenCommit) secret(name string) *big.Int {
	result := c.secretv.secret(name)
	if result == nil {
		result = c.hider.secret(name)
	}
	return result
}

func (c *pedersenCommit) randomizer(name string) *big.Int {
	result := c.secretv.randomizer(name)
	if result == nil {
		result = c.hider.randomizer(name)
	}
	return result
}

func (p *PedersenProof) setName(name string) {
	p.name = name
	p.Sresult.setName(name)
	p.Hresult.setName(strings.Join([]string{name, "hider"}, "_"))
}

func (p *PedersenProof) base(name string) *big.Int {
	if p.name == name {
		return p.Commit
	}
	return nil
}

func (p *PedersenProof) exp(ret *big.Int, name string, exp, P *big.Int) bool {
	base := p.base(name)
	if base == nil {
		return false
	}
	ret.Exp(base, exp, P)
	return true
}

func (p *PedersenProof) names() []string {
	return []string{p.name}
}

func (p *PedersenProof) result(name string) *big.Int {
	result := p.Sresult.result(name)
	if result == nil {
		result = p.Hresult.result(name)
	}
	return result
}
