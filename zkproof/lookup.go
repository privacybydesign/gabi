package zkproof

import "github.com/privacybydesign/gabi/big"

type (
	BaseLookup interface {
		Base(name string) *big.Int
		Exp(ret *big.Int, name string, exp, P *big.Int) bool
		Names() []string
	}

	SecretLookup interface {
		Secret(name string) *big.Int
		Randomizer(name string) *big.Int
	}

	ProofLookup interface {
		ProofResult(name string) *big.Int
	}

	BaseMerge struct {
		parts  []BaseLookup
		inames []string
		lut    map[string]BaseLookup
	}

	SecretMerge struct {
		parts []SecretLookup
	}

	ProofMerge struct {
		parts []ProofLookup
	}
)

func NewBaseMerge(parts ...BaseLookup) BaseMerge {
	var result BaseMerge
	result.parts = parts
	if len(parts) > 16 {
		result.lut = make(map[string]BaseLookup)
	}
	for _, part := range parts {
		partNames := part.Names()
		if result.lut != nil {
			for _, name := range partNames {
				result.lut[name] = part
			}
		}
		result.inames = append(result.inames, partNames...)
	}
	return result
}

func (b *BaseMerge) Names() []string {
	return b.inames
}
func (b *BaseMerge) Base(name string) *big.Int {
	if b.lut != nil {
		part, ok := b.lut[name]
		if !ok {
			return nil
		}
		return part.Base(name)
	}
	for _, part := range b.parts {
		res := part.Base(name)
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

func NewSecretMerge(parts ...SecretLookup) SecretMerge {
	var result SecretMerge
	result.parts = parts
	return result
}

func (s *SecretMerge) Secret(name string) *big.Int {
	for _, part := range s.parts {
		res := part.Secret(name)
		if res != nil {
			return res
		}
	}
	return nil
}

func (s *SecretMerge) Randomizer(name string) *big.Int {
	for _, part := range s.parts {
		res := part.Randomizer(name)
		if res != nil {
			return res
		}
	}
	return nil
}

func NewProofMerge(parts ...ProofLookup) ProofMerge {
	var result ProofMerge
	result.parts = parts
	return result
}

func (p *ProofMerge) ProofResult(name string) *big.Int {
	for _, part := range p.parts {
		res := part.ProofResult(name)
		if res != nil {
			return res
		}
	}
	return nil
}
