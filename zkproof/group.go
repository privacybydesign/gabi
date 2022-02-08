package zkproof

import (
	"fmt"

	"github.com/bwesterb/go-exptable"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
)

type Group struct {
	P     *big.Int
	Order *big.Int
	G     *big.Int
	H     *big.Int

	GTable exptable.Table
	HTable exptable.Table

	PMod     common.FastMod
	OrderMod common.FastMod
}

func BuildGroup(prime *big.Int) (Group, bool) {
	var result Group

	if !prime.ProbablyPrime(80) {
		return result, false
	}

	result.P = new(big.Int).Set(prime)
	result.Order = new(big.Int).Rsh(prime, 1)

	if !result.Order.ProbablyPrime(80) {
		return result, false
	}

	result.G = new(big.Int).Exp(big.NewInt(0x41424344), big.NewInt(0x45464748), result.P)
	result.H = new(big.Int).Exp(big.NewInt(0x494A4B4C), big.NewInt(0x4D4E4F50), result.P)

	result.GTable.Compute(result.G.Go(), result.P.Go(), 7)
	result.HTable.Compute(result.H.Go(), result.P.Go(), 7)

	result.PMod.Set(result.P)
	result.OrderMod.Set(result.Order)

	return result, true
}

func (g *Group) Exp(ret *big.Int, name string, exp, _ *big.Int) bool {
	var table *exptable.Table
	if name == "g" {
		table = &g.GTable
	} else if name == "h" {
		table = &g.HTable
	} else {
		return false
	}
	var exp2 big.Int
	if exp.Sign() == -1 {
		exp2.Add(exp, g.Order)
		exp = &exp2
	}
	if exp.Cmp(g.Order) >= 0 {
		panic(fmt.Sprintf("scalar out of bounds: %v %v", exp, g.Order))
	}
	// exp2.Mod(exp, g.order)
	table.Exp(ret.Go(), exp.Go())
	return true
}

func (g *Group) Names() []string {
	return []string{"g", "h"}
}

func (g *Group) Base(name string) *big.Int {
	if name == "g" {
		return g.G
	}
	if name == "h" {
		return g.H
	}
	return nil
}
