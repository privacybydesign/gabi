package keyproof

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
)

type (
	secret struct {
		name       string
		secret     *big.Int
		randomizer *big.Int
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
		new(big.Int).Mod(new(big.Int).Sub(s.randomizer, new(big.Int).Mul(s.secret, challenge)), g.order),
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

func (s *secret) getSecret(name string) *big.Int {
	if name == s.name {
		return s.secret
	} else {
		return nil
	}
}

func (s *secret) getRandomizer(name string) *big.Int {
	if name == s.name {
		return s.randomizer
	} else {
		return nil
	}
}

func (p *Proof) getResult(name string) *big.Int {
	if name == p.name {
		return p.Result
	} else {
		return nil
	}
}

func (p *Proof) setName(name string) {
	p.name = name
}
