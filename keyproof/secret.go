package keyproof

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/zkproof"
)

type (
	secret struct {
		name        string
		secretv     *big.Int
		randomizerv *big.Int
	}

	Proof struct {
		name   string
		Result *big.Int
	}
)

func newSecret(g zkproof.Group, name string, value *big.Int) secret {
	return secret{
		name,
		new(big.Int).Set(value),
		common.FastRandomBigInt(g.Order),
	}
}

func (s *secret) buildProof(g zkproof.Group, challenge *big.Int) Proof {
	return Proof{
		s.name,
		new(big.Int).Mod(new(big.Int).Sub(s.randomizerv, new(big.Int).Mul(s.secretv, challenge)), g.Order),
	}
}

func (p *Proof) verifyStructure() bool {
	return p.Result != nil
}

func fakeProof(g zkproof.Group) Proof {
	return Proof{
		"",
		common.FastRandomBigInt(g.Order),
	}
}

func (s *secret) Secret(name string) *big.Int {
	if name == s.name {
		return s.secretv
	} else {
		return nil
	}
}

func (s *secret) Randomizer(name string) *big.Int {
	if name == s.name {
		return s.randomizerv
	} else {
		return nil
	}
}

func (p *Proof) ProofResult(name string) *big.Int {
	if name == p.name {
		return p.Result
	} else {
		return nil
	}
}

func (p *Proof) setName(name string) {
	p.name = name
}
