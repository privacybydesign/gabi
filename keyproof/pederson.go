package keyproof

import "github.com/privacybydesign/gabi/internal/common"
import "github.com/privacybydesign/gabi/big"
import "strings"

type pedersonSecret struct {
	name             string
	hname            string
	secret           *big.Int
	secretRandomizer *big.Int
	hider            *big.Int
	hiderRandomizer  *big.Int
	commit           *big.Int

	g *group
}

type PedersonProof struct {
	name    string
	hname   string
	Commit  *big.Int
	Sresult *big.Int
	Hresult *big.Int
}

func newPedersonRepresentationProofStructure(name string) representationProofStructure {
	var structure representationProofStructure
	structure.lhs = []lhsContribution{
		{name, big.NewInt(1)},
	}
	structure.rhs = []rhsContribution{
		{"g", name, 1},
		{"h", strings.Join([]string{name, "hider"}, "_"), 1},
	}
	return structure
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

func newPedersonSecret(g group, name string, value *big.Int) pedersonSecret {
	var result pedersonSecret
	result.name = name
	result.hname = strings.Join([]string{name, "hider"}, "_")
	result.secret = new(big.Int).Set(value)
	result.secretRandomizer = common.FastRandomBigInt(g.order)
	result.hider = common.FastRandomBigInt(g.order)
	result.hiderRandomizer = common.FastRandomBigInt(g.order)
	var gCommit, hCommit big.Int
	g.exp(&gCommit, "g", result.secret, g.p)
	g.exp(&hCommit, "h", result.hider, g.p)
	result.commit = new(big.Int)
	result.commit.Mul(&gCommit, &hCommit)
	result.commit.Mod(result.commit, g.p)
	result.g = &g
	return result
}

func newPedersonFakeProof(g group) PedersonProof {
	var result PedersonProof
	var gCommit, hCommit big.Int
	g.exp(&gCommit, "g", common.FastRandomBigInt(g.order), g.p)
	g.exp(&hCommit, "h", common.FastRandomBigInt(g.order), g.p)
	result.Commit = new(big.Int)
	result.Commit.Mul(&gCommit, &hCommit)
	result.Commit.Mod(result.Commit, g.p)
	result.Sresult = common.FastRandomBigInt(g.order)
	result.Hresult = common.FastRandomBigInt(g.order)
	return result
}

func (s *pedersonSecret) buildProof(g group, challenge *big.Int) PedersonProof {
	var result PedersonProof
	result.Commit = s.commit
	result.Sresult = new(big.Int).Mod(new(big.Int).Sub(s.secretRandomizer, new(big.Int).Mul(challenge, s.secret)), g.order)
	result.Hresult = new(big.Int).Mod(new(big.Int).Sub(s.hiderRandomizer, new(big.Int).Mul(challenge, s.hider)), g.order)
	return result
}

func (s *pedersonSecret) generateCommitments(list []*big.Int) []*big.Int {
	return append(list, s.commit)
}

func (s *pedersonSecret) getSecret(name string) *big.Int {
	if name == s.name {
		return s.secret
	}
	if name == s.hname {
		return s.hider
	}
	return nil
}

func (s *pedersonSecret) getRandomizer(name string) *big.Int {
	if name == s.name {
		return s.secretRandomizer
	}
	if name == s.hname {
		return s.hiderRandomizer
	}
	return nil
}
func (s *pedersonSecret) exp(ret *big.Int, name string, exp, P *big.Int) bool {
	if name != s.name {
		return false
	}
	// We effectively compute c.commit^exp, which is more expensive to do
	// directly, than with two table-backed exponentiations.
	var exp1, exp2, ret1, ret2, tmp big.Int
	tmp.Mul(s.secret, exp)
	s.g.orderMod.Mod(&exp1, &tmp)
	tmp.Mul(s.hider, exp)
	s.g.orderMod.Mod(&exp2, &tmp)
	s.g.exp(&ret1, "g", &exp1, s.g.p)
	s.g.exp(&ret2, "h", &exp2, s.g.p)
	tmp.Mul(&ret1, &ret2)
	s.g.pMod.Mod(ret, &tmp)
	return true
}
func (s *pedersonSecret) getBase(name string) *big.Int {
	if name == s.name {
		return s.commit
	}
	return nil
}
func (s *pedersonSecret) names() []string {
	return []string{s.name}
}

func (p *PedersonProof) setName(name string) {
	p.name = name
	p.hname = strings.Join([]string{name, "hider"}, "_")
}

func (p *PedersonProof) generateCommitments(list []*big.Int) []*big.Int {
	return append(list, p.Commit)
}

func (p *PedersonProof) verifyStructure() bool {
	return p.Commit != nil && p.Sresult != nil && p.Hresult != nil
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

func (p *PedersonProof) getBase(name string) *big.Int {
	if name == p.name {
		return p.Commit
	}
	return nil
}

func (p *PedersonProof) getResult(name string) *big.Int {
	if name == p.name {
		return p.Sresult
	}
	if name == p.hname {
		return p.Hresult
	}
	return nil
}
