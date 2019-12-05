package keyproof

import (
	"strings"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
)

type pedersonStructure struct {
	name           string
	representation representationProofStructure
}

type pedersonCommit struct {
	name   string
	secret basicSecret
	hider  basicSecret
	commit *big.Int

	g *group
}

type PedersonProof struct {
	name    string
	Commit  *big.Int
	Sresult BasicProof
	Hresult BasicProof
}

func (c *pedersonCommit) getBase(name string) *big.Int {
	if name == c.name {
		return c.commit
	} else {
		return nil
	}
}

func (c *pedersonCommit) exp(ret *big.Int, name string, exp, P *big.Int) bool {
	if name != c.name {
		return false
	}
	// We effectively compute c.commit^exp, which is more expensive to do
	// directly, than with two table-backed exponentiations.
	var exp1, exp2, ret1, ret2, tmp big.Int
	tmp.Mul(c.secret.secret, exp)
	c.g.orderMod.Mod(&exp1, &tmp)
	tmp.Mul(c.hider.secret, exp)
	c.g.orderMod.Mod(&exp2, &tmp)
	c.g.exp(&ret1, "g", &exp1, c.g.p)
	c.g.exp(&ret2, "h", &exp2, c.g.p)
	tmp.Mul(&ret1, &ret2)
	c.g.pMod.Mod(ret, &tmp)
	return true
}

func (c *pedersonCommit) names() []string {
	return []string{c.name}
}

func (c *pedersonCommit) getSecret(name string) *big.Int {
	result := c.secret.getSecret(name)
	if result == nil {
		result = c.hider.getSecret(name)
	}
	return result
}

func (c *pedersonCommit) getRandomizer(name string) *big.Int {
	result := c.secret.getRandomizer(name)
	if result == nil {
		result = c.hider.getRandomizer(name)
	}
	return result
}

func (p *PedersonProof) setName(name string) {
	p.name = name
	p.Sresult.setName(name)
	p.Hresult.setName(strings.Join([]string{name, "hider"}, "_"))
}

func (p *PedersonProof) getBase(name string) *big.Int {
	if p.name == name {
		return p.Commit
	}
	return nil
}

func (p *PedersonProof) exp(ret *big.Int, name string, exp, P *big.Int) bool {
	base := p.getBase(name)
	if base == nil {
		return false
	}
	ret.Exp(base, exp, P)
	return true
}

func (p *PedersonProof) names() []string {
	return []string{p.name}
}

func (p *PedersonProof) getResult(name string) *big.Int {
	result := p.Sresult.getResult(name)
	if result == nil {
		result = p.Hresult.getResult(name)
	}
	return result
}

func newPedersonStructure(name string) pedersonStructure {
	return pedersonStructure{
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

func newPedersonRangeProofStructure(name string, l1 uint, l2 uint) rangeProofStructure {
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

func (s *pedersonStructure) numRangeProofs() int {
	return s.representation.numRangeProofs()
}

func (s *pedersonStructure) numCommitments() int {
	return s.representation.numCommitments() + 1
}

func (s *pedersonStructure) generateCommitmentsFromSecrets(g group, list []*big.Int, value *big.Int) ([]*big.Int, pedersonCommit) {
	var result pedersonCommit
	result.name = s.name
	result.secret = newBasicSecret(g, s.name, value)
	result.hider = newBasicSecret(g, strings.Join([]string{s.name, "hider"}, "_"), common.FastRandomBigInt(g.order))
	result.g = &g
	result.commit = new(big.Int)
	result.exp(result.commit, s.name, big.NewInt(1), g.p)

	bases := newBaseMerge(&result, &g)
	list = append(list, result.commit)
	return s.representation.generateCommitmentsFromSecrets(g, list, &bases, &result), result
}

func (s *pedersonStructure) generateCommitmentsDuplicate(g group, list []*big.Int, value *big.Int, hider *big.Int) ([]*big.Int, pedersonCommit) {
	var result = pedersonCommit{
		name:   s.name,
		secret: newBasicSecret(g, s.name, value),
		hider:  newBasicSecret(g, strings.Join([]string{s.name, "hider"}, "_"), hider),
		g:      &g,
		commit: new(big.Int),
	}
	result.exp(result.commit, s.name, big.NewInt(1), g.p)

	bases := newBaseMerge(&result, &g)
	list = append(list, result.commit)
	return s.representation.generateCommitmentsFromSecrets(g, list, &bases, &result), result
}

func (s *pedersonStructure) buildProof(g group, challenge *big.Int, commit pedersonCommit) PedersonProof {
	var proof PedersonProof
	proof.Commit = commit.commit
	proof.Sresult = commit.secret.buildProof(g, challenge)
	proof.Hresult = commit.hider.buildProof(g, challenge)
	return proof
}

func (s *pedersonStructure) fakeProof(g group) PedersonProof {
	var proof PedersonProof
	var gCommit, hCommit big.Int
	g.exp(&gCommit, "g", common.FastRandomBigInt(g.order), g.p)
	g.exp(&hCommit, "h", common.FastRandomBigInt(g.order), g.p)
	proof.Commit = new(big.Int)
	proof.Commit.Mul(&gCommit, &hCommit)
	proof.Commit.Mod(proof.Commit, g.p)
	proof.Sresult = fakeBasicProof(g)
	proof.Hresult = fakeBasicProof(g)
	return proof
}

func (s *pedersonStructure) verifyProofStructure(proof PedersonProof) bool {
	return proof.Commit != nil && proof.Hresult.verifyStructure() && proof.Sresult.verifyStructure()
}

func (s *pedersonStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, proof PedersonProof) []*big.Int {
	proof.setName(s.name)
	bases := newBaseMerge(&proof, &g)
	list = append(list, proof.Commit)
	return s.representation.generateCommitmentsFromProof(g, list, challenge, &bases, &proof)
}
