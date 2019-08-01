package keyproof

import (
	"github.com/privacybydesign/gabi/big"
)

type BaseLookup interface {
	GetBase(name string) *big.Int
	GetNames() []string
	Exp(ret *big.Int, name string, exp, P *big.Int) bool
}

type SecretLookup interface {
	GetSecret(name string) *big.Int
	GetRandomizer(name string) *big.Int
}

type ProofLookup interface {
	GetResult(name string) *big.Int
}

type BaseMerge struct {
	parts  []BaseLookup
	inames []string
	lut    map[string]BaseLookup
}

func NewBaseMerge(parts ...BaseLookup) BaseMerge {
	var result BaseMerge
	result.parts = parts
	if len(parts) > 16 {
		result.lut = make(map[string]BaseLookup)

	}
	for _, part := range parts {
		partNames := part.GetNames()
		if result.lut != nil {
			for _, name := range partNames {
				result.lut[name] = part
			}
		}
		result.inames = append(result.inames, partNames...)
	}
	return result
}

func (b *BaseMerge) GetNames() []string {
	return b.inames
}
func (b *BaseMerge) GetBase(name string) *big.Int {
	if b.lut != nil {
		part, ok := b.lut[name]
		if !ok {
			return nil
		}
		return part.GetBase(name)
	}
	for _, part := range b.parts {
		res := part.GetBase(name)
		if res != nil {
			return res
		}
	}
	return nil
}

func (b *BaseMerge) Exp(ret *big.Int, name string, exp, P *big.Int) bool {
	if b.lut != nil {
		part, ok := b.lut[name]
		if !ok {
			return false
		}
		return part.Exp(ret, name, exp, P)
	}
	for _, part := range b.parts {
		ok := part.Exp(ret, name, exp, P)
		if ok {
			return true
		}
	}
	return false
}

type SecretMerge struct {
	parts []SecretLookup
}

func NewSecretMerge(parts ...SecretLookup) SecretMerge {
	var result SecretMerge
	result.parts = parts
	return result
}

func (s *SecretMerge) GetSecret(name string) *big.Int {
	for _, part := range s.parts {
		res := part.GetSecret(name)
		if res != nil {
			return res
		}
	}
	return nil
}

func (s *SecretMerge) GetRandomizer(name string) *big.Int {
	for _, part := range s.parts {
		res := part.GetRandomizer(name)
		if res != nil {
			return res
		}
	}
	return nil
}

type ProofMerge struct {
	parts []ProofLookup
}

func NewProofMerge(parts ...ProofLookup) ProofMerge {
	var result ProofMerge
	result.parts = parts
	return result
}

func (p *ProofMerge) GetResult(name string) *big.Int {
	for _, part := range p.parts {
		res := part.GetResult(name)
		if res != nil {
			return res
		}
	}
	return nil
}
