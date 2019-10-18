package keyproof

import (
	"fmt"

	"github.com/privacybydesign/gabi/big"

	"github.com/privacybydesign/gabi/internal/common"

	"github.com/bwesterb/go-exptable"
)

type group struct {
	p     *big.Int
	order *big.Int
	g     *big.Int
	h     *big.Int

	gTable exptable.Table
	hTable exptable.Table

	pMod     common.FastMod
	orderMod common.FastMod
}

func buildGroup(prime *big.Int) (group, bool) {
	var result group

	if !prime.ProbablyPrime(80) {
		return result, false
	}

	result.p = new(big.Int).Set(prime)
	result.order = new(big.Int).Rsh(prime, 1)

	if !result.order.ProbablyPrime(80) {
		return result, false
	}

	result.g = new(big.Int).Exp(big.NewInt(0x41424344), big.NewInt(0x45464748), result.p)
	result.h = new(big.Int).Exp(big.NewInt(0x494A4B4C), big.NewInt(0x4D4E4F50), result.p)

	result.gTable.Compute(result.g.Go(), result.p.Go(), 7)
	result.hTable.Compute(result.h.Go(), result.p.Go(), 7)

	result.pMod.Set(result.p)
	result.orderMod.Set(result.order)

	return result, true
}

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

func (g *group) GetNames() []string {
	return []string{"g", "h"}
}

func (g *group) GetBase(name string) *big.Int {
	if name == "g" {
		return g.g
	}
	if name == "h" {
		return g.h
	}
	return nil
}
