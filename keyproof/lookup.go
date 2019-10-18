package keyproof

import (
	"github.com/bwesterb/go-exptable"
	"github.com/privacybydesign/gabi/big"

	"fmt"
)

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

func (g *group) Exp(ret *big.Int, name string, exp, P *big.Int) bool {
	var table *exptable.Table
	if name == "g" {
		table = &g.gTable
	} else if name == "h" {
		table = &g.hTable
	} else {
		return false
	}
	var exp2 big.Int
	if exp.Sign() == -1 {
		exp2.Add(exp, g.order)
		exp = &exp2
	}
	if exp.Cmp(g.order) >= 0 {
		panic(fmt.Sprintf("scalar out of bounds: %v %v", exp, g.order))
	}
	// exp2.Mod(exp, g.order)
	table.Exp(ret.Go(), exp.Go())
	return true
}

func (g *group) Names() []string {
	return []string{"g", "h"}
}

func (g *group) Base(name string) *big.Int {
	if name == "g" {
		return g.g
	}
	if name == "h" {
		return g.h
	}
	return nil
}

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
