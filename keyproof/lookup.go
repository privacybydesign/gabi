package keyproof

import (
	"github.com/bwesterb/go-exptable"
	"github.com/privacybydesign/gabi/big"

	"fmt"
)

type (
	baseLookup interface {
		base(name string) *big.Int
		exp(ret *big.Int, name string, exp, P *big.Int) bool
		names() []string
	}

	secretLookup interface {
		secret(name string) *big.Int
		randomizer(name string) *big.Int
	}

	proofLookup interface {
		result(name string) *big.Int
	}

	baseMerge struct {
		parts  []baseLookup
		inames []string
		lut    map[string]baseLookup
	}

	secretMerge struct {
		parts []secretLookup
	}

	proofMerge struct {
		parts []proofLookup
	}
)

func (g *group) exp(ret *big.Int, name string, exp, P *big.Int) bool {
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
	table.Exp(ret.Value(), exp.Value())
	return true
}

func (g *group) names() []string {
	return []string{"g", "h"}
}

func (g *group) base(name string) *big.Int {
	if name == "g" {
		return g.g
	}
	if name == "h" {
		return g.h
	}
	return nil
}

func newBaseMerge(parts ...baseLookup) baseMerge {
	var result baseMerge
	result.parts = parts
	if len(parts) > 16 {
		result.lut = make(map[string]baseLookup)
	}
	for _, part := range parts {
		partNames := part.names()
		if result.lut != nil {
			for _, name := range partNames {
				result.lut[name] = part
			}
		}
		result.inames = append(result.inames, partNames...)
	}
	return result
}

func (b *baseMerge) names() []string {
	return b.inames
}
func (b *baseMerge) base(name string) *big.Int {
	if b.lut != nil {
		part, ok := b.lut[name]
		if !ok {
			return nil
		}
		return part.base(name)
	}
	for _, part := range b.parts {
		res := part.base(name)
		if res != nil {
			return res
		}
	}
	return nil
}

func (b *baseMerge) exp(ret *big.Int, name string, exp, P *big.Int) bool {
	if b.lut != nil {
		part, ok := b.lut[name]
		if !ok {
			return false
		}
		return part.exp(ret, name, exp, P)
	}
	for _, part := range b.parts {
		ok := part.exp(ret, name, exp, P)
		if ok {
			return true
		}
	}
	return false
}

func newSecretMerge(parts ...secretLookup) secretMerge {
	var result secretMerge
	result.parts = parts
	return result
}

func (s *secretMerge) secret(name string) *big.Int {
	for _, part := range s.parts {
		res := part.secret(name)
		if res != nil {
			return res
		}
	}
	return nil
}

func (s *secretMerge) randomizer(name string) *big.Int {
	for _, part := range s.parts {
		res := part.randomizer(name)
		if res != nil {
			return res
		}
	}
	return nil
}

func newProofMerge(parts ...proofLookup) proofMerge {
	var result proofMerge
	result.parts = parts
	return result
}

func (p *proofMerge) result(name string) *big.Int {
	for _, part := range p.parts {
		res := part.result(name)
		if res != nil {
			return res
		}
	}
	return nil
}
