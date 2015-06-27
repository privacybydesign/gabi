package credential

import (
	"math/big"
)

type SecretKey struct {
	P, Q           big.Int
	PPrime, QPrime big.Int
}

func NewSecretKey(p, q *big.Int) *SecretKey {
	sk := SecretKey{P: *p, Q: *q}

	sk.PPrime.Sub(p, bigONE)
	sk.PPrime.Rsh(&sk.PPrime, 1)

	sk.QPrime.Sub(q, bigONE)
	sk.QPrime.Rsh(&sk.QPrime, 1)

	return &sk
}

type PublicKey struct {
	N      big.Int // Modulus n
	Z      big.Int // Generator Z
	S      big.Int // Generator S
	R      []*big.Int
	Params *SystemParameters
}

func NewPublicKey(N, Z, S *big.Int, R []*big.Int) *PublicKey {
	pk := PublicKey{N: *N, Z: *Z, S: *S, R: R, Params: &DefaultSystemParameters}
	return &pk
}

type BaseParameters struct {
	Le      uint
	LePrime uint
	Lh      uint
	Lm      uint
	Ln      uint
	Lstatzk uint
	Lv      uint
}

var defaultBaseParameters = BaseParameters{
	Le:      597,
	LePrime: 120,
	Lh:      256,
	Lm:      256,
	Ln:      1024,
	Lstatzk: 80,
	Lv:      1700,
}

type DerivedParameters struct {
	LeCommit      uint
	LmCommit      uint
	LRA           uint
	LsCommit      uint
	LvCommit      uint
	LvPrime       uint
	LvPrimeCommit uint
}

func makeDerivedParameters(base BaseParameters) DerivedParameters {
	return DerivedParameters{
		LeCommit:      base.LePrime + base.Lstatzk + base.Lh,
		LmCommit:      base.Lm + base.Lstatzk + base.Lh,
		LRA:           base.Ln + base.Lstatzk,
		LsCommit:      base.Lm + base.Lstatzk + base.Lh + 1,
		LvCommit:      base.Lv + base.Lstatzk + base.Lh,
		LvPrime:       base.Ln + base.Lstatzk,
		LvPrimeCommit: base.Ln + 2*base.Lstatzk + base.Lh,
	}
}

type SystemParameters struct {
	BaseParameters
	DerivedParameters
}

var DefaultSystemParameters = SystemParameters{defaultBaseParameters, makeDerivedParameters(defaultBaseParameters)}

func ParamSize(a int) int {
	return (a + 8 - 1) / 8
}
