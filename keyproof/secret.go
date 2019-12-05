package keyproof

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
)

type basicSecret struct {
	name       string
	secret     *big.Int
	randomizer *big.Int
}

type BasicProof struct {
	name   string
	Result *big.Int
}

func (s *basicSecret) getSecret(name string) *big.Int {
	if name == s.name {
		return s.secret
	} else {
		return nil
	}
}

func (s *basicSecret) getRandomizer(name string) *big.Int {
	if name == s.name {
		return s.randomizer
	} else {
		return nil
	}
}

func (p *BasicProof) getResult(name string) *big.Int {
	if name == p.name {
		return p.Result
	} else {
		return nil
	}
}

func (p *BasicProof) setName(name string) {
	p.name = name
}

func newBasicSecret(g group, name string, value *big.Int) basicSecret {
	return basicSecret{
		name,
		new(big.Int).Set(value),
		common.FastRandomBigInt(g.order),
	}
}

func (s *basicSecret) buildProof(g group, challenge *big.Int) BasicProof {
	return BasicProof{
		s.name,
		new(big.Int).Mod(new(big.Int).Sub(s.randomizer, new(big.Int).Mul(s.secret, challenge)), g.order),
	}
}

func (p *BasicProof) verifyStructure() bool {
	return p.Result != nil
}

func fakeBasicProof(g group) BasicProof {
	return BasicProof{
		"",
		common.FastRandomBigInt(g.order),
	}
}
