package keyproof

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
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

func newSecret(g group, name string, value *big.Int) secret {
	return secret{
		name,
		new(big.Int).Set(value),
		common.FastRandomBigInt(g.order),
	}
}

func (s *secret) buildProof(g group, challenge *big.Int) Proof {
	return Proof{
		s.name,
		new(big.Int).Mod(new(big.Int).Sub(s.randomizerv, new(big.Int).Mul(s.secretv, challenge)), g.order),
	}
}

func (p *Proof) verifyStructure() bool {
	return p.Result != nil
}

func fakeProof(g group) Proof {
	return Proof{
		"",
		common.FastRandomBigInt(g.order),
	}
}

func (s *secret) secret(name string) *big.Int {
	if name == s.name {
		return s.secretv
	} else {
		return nil
	}
}

func (s *secret) randomizer(name string) *big.Int {
	if name == s.name {
		return s.randomizerv
	} else {
		return nil
	}
}

func (p *Proof) result(name string) *big.Int {
	if name == p.name {
		return p.Result
	} else {
		return nil
	}
}

func (p *Proof) setName(name string) {
	p.name = name
}
