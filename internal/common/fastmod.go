package common

import (
	"github.com/privacybydesign/gabi/big"
)

// Fast modulo operation for p = 2^b - c for small c.

type FastMod struct {
	enabled bool
	p       big.Int
	c       big.Int
	b       uint
	mask    big.Int // (1 << b) - 1
}

func (m *FastMod) Set(p *big.Int) {
	var tmp, one big.Int
	one.SetUint64(1)
	m.p.Set(p)
	m.b = uint(p.BitLen())
	tmp.SetUint64(1)
	tmp.Lsh(&tmp, m.b)
	m.c.Sub(&tmp, &m.p)
	if m.c.BitLen() < 60 {
		m.enabled = true
		m.mask.Sub(&tmp, &one)
	} else {
		m.enabled = false
	}
}

func (m *FastMod) Mod(ret, x *big.Int) *big.Int {
	if !m.enabled {
		return ret.Mod(x, &m.p)
	}

	if x.Sign() == -1 {
		return ret.Mod(x, &m.p) // TODO
	}

	if x.Cmp(&m.p) < 0 {
		return ret.Set(x)
	}

	cur := x

	var tmp, carry big.Int
	retSet := false
	for {
		carry.Rsh(cur, m.b)
		if carry.Sign() == 0 {
			break
		}
		retSet = true
		ret.And(cur, &m.mask)
		tmp.Mul(&carry, &m.c)
		ret.Add(ret, &tmp)
		cur = ret
	}

	if !retSet {
		if x.Cmp(&m.p) < 0 {
			return ret.Set(x)
		}
		return ret.Sub(x, &m.p)
	}

	if ret.Cmp(&m.p) >= 0 {
		ret.Sub(ret, &m.p)
	}

	return ret
}
