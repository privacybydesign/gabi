package keyproof

import (
	"strings"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
)

type (
	pedersenStructure struct {
		name           string
		representation RepresentationProofStructure
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
		RepresentationProofStructure{
			[]LhsContribution{
				{name, big.NewInt(1)},
			},
			[]RhsContribution{
				{"g", name, 1},
				{"h", strings.Join([]string{name, "hider"}, "_"), 1},
			},
		},
	}
}

func newPedersenRangeProofStructure(name string, l1 uint, l2 uint) rangeProofStructure {
	structure := rangeProofStructure{
		RepresentationProofStructure: RepresentationProofStructure{
			Lhs: []LhsContribution{
				{name, big.NewInt(1)},
			},
			Rhs: []RhsContribution{
				{"g", name, 1},
				{"h", strings.Join([]string{name, "hider"}, "_"), 1},
			},
		},
		rangeSecret: name,
		l1:          l1,
		l2:          l2,
	}
	return structure
}

func (s *pedersenStructure) numRangeProofs() int {
	return s.representation.numRangeProofs()
}

func (s *pedersenStructure) numCommitments() int {
	return s.representation.numCommitments() + 1
}

func (s *pedersenStructure) commitmentsFromSecrets(g group, list []*big.Int, value *big.Int) ([]*big.Int, pedersenCommit) {
	result := pedersenCommit{
		name:    s.name,
		secretv: newSecret(g, s.name, value),
		hider:   newSecret(g, strings.Join([]string{s.name, "hider"}, "_"), common.FastRandomBigInt(g.order)),
		g:       &g,
		commit:  new(big.Int),
	}
	result.Exp(result.commit, s.name, big.NewInt(1), g.p)

	bases := NewBaseMerge(&result, &g)
	list = append(list, result.commit)
	return s.representation.commitmentsFromSecrets(g, list, &bases, &result), result
}

func (s *pedersenStructure) commitmentsDuplicate(g group, list []*big.Int, value *big.Int, hider *big.Int) ([]*big.Int, pedersenCommit) {
	var result = pedersenCommit{
		name:    s.name,
		secretv: newSecret(g, s.name, value),
		hider:   newSecret(g, strings.Join([]string{s.name, "hider"}, "_"), hider),
		g:       &g,
		commit:  new(big.Int),
	}
	result.Exp(result.commit, s.name, big.NewInt(1), g.p)

	bases := NewBaseMerge(&result, &g)
	list = append(list, result.commit)
	return s.representation.commitmentsFromSecrets(g, list, &bases, &result), result
}

func (s *pedersenStructure) buildProof(g group, challenge *big.Int, commit pedersenCommit) PedersenProof {
	return PedersenProof{
		Commit:  commit.commit,
		Sresult: commit.secretv.buildProof(g, challenge),
		Hresult: commit.hider.buildProof(g, challenge),
	}
}

func (s *pedersenStructure) fakeProof(g group) PedersenProof {
	var gCommit, hCommit big.Int
	g.Exp(&gCommit, "g", common.FastRandomBigInt(g.order), g.p)
	g.Exp(&hCommit, "h", common.FastRandomBigInt(g.order), g.p)
	var Commit big.Int
	Commit.Mul(&gCommit, &hCommit)
	Commit.Mod(&Commit, g.p)
	return PedersenProof{
		Commit:  &Commit,
		Sresult: fakeProof(g),
		Hresult: fakeProof(g),
	}
}

func (s *pedersenStructure) verifyProofStructure(proof PedersenProof) bool {
	return proof.Commit != nil && proof.Hresult.verifyStructure() && proof.Sresult.verifyStructure()
}

func (s *pedersenStructure) commitmentsFromProof(g group, list []*big.Int, challenge *big.Int, proof PedersenProof) []*big.Int {
	proof.setName(s.name)
	bases := NewBaseMerge(&proof, &g)
	list = append(list, proof.Commit)
	return s.representation.commitmentsFromProof(g, list, challenge, &bases, &proof)
}

func (c *pedersenCommit) Base(name string) *big.Int {
	if name == c.name {
		return c.commit
	} else {
		return nil
	}
}

func (c *pedersenCommit) Exp(ret *big.Int, name string, exp, P *big.Int) bool {
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
	c.g.Exp(&ret1, "g", &exp1, c.g.p)
	c.g.Exp(&ret2, "h", &exp2, c.g.p)
	tmp.Mul(&ret1, &ret2)
	c.g.pMod.Mod(ret, &tmp)
	return true
}

func (c *pedersenCommit) Names() []string {
	return []string{c.name}
}

func (c *pedersenCommit) Secret(name string) *big.Int {
	result := c.secretv.Secret(name)
	if result == nil {
		result = c.hider.Secret(name)
	}
	return result
}

func (c *pedersenCommit) Randomizer(name string) *big.Int {
	result := c.secretv.Randomizer(name)
	if result == nil {
		result = c.hider.Randomizer(name)
	}
	return result
}

func (p *PedersenProof) setName(name string) {
	p.name = name
	p.Sresult.setName(name)
	p.Hresult.setName(strings.Join([]string{name, "hider"}, "_"))
}

func (p *PedersenProof) Base(name string) *big.Int {
	if p.name == name {
		return p.Commit
	}
	return nil
}

func (p *PedersenProof) Exp(ret *big.Int, name string, exp, P *big.Int) bool {
	base := p.Base(name)
	if base == nil {
		return false
	}
	ret.Exp(base, exp, P)
	return true
}

func (p *PedersenProof) Names() []string {
	return []string{p.name}
}

func (p *PedersenProof) ProofResult(name string) *big.Int {
	result := p.Sresult.ProofResult(name)
	if result == nil {
		result = p.Hresult.ProofResult(name)
	}
	return result
}
