package prooftools

import (
	"fmt"
	"strconv"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/keys"
)

type PublicKeyGroup keys.PublicKey

func (g *PublicKeyGroup) Base(name string) *big.Int {
	if name == "Z" {
		return g.Z
	}
	if name == "S" {
		return g.S
	}
	if name == "G" {
		return g.G
	}
	if name == "H" {
		return g.H
	}
	if name[0] == 'R' {
		i, err := strconv.Atoi(name[1:])
		if err != nil || i < 0 || i >= len(g.R) {
			return nil
		}
		return g.R[i]
	}
	return nil
}

func (g *PublicKeyGroup) Exp(ret *big.Int, name string, exp, n *big.Int) bool {
	base := g.Base(name)
	if base == nil {
		return false
	}
	ret.Exp(base, exp, n)
	return true
}

func (g *PublicKeyGroup) Names() []string {
	names := []string{"Z", "S"}
	if g.G != nil && g.H != nil {
		names = append(names, "G", "H")
	}
	for i := range g.R {
		names = append(names, fmt.Sprintf("R%d", i))
	}
	return names
}
