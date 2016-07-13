package credential

// BaseParameters holds the base system parameters
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

// DerivedParameters holds system parameters that can be drived from base
// systemparameters (BaseParameters)
type DerivedParameters struct {
	LeCommit      uint
	LmCommit      uint
	LRA           uint
	LsCommit      uint
	LvCommit      uint
	LvPrime       uint
	LvPrimeCommit uint
}

// makeDerivedParameters computes the derived system parameters
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

// SystemParameters holds the system parameters of the IRMA system.
type SystemParameters struct {
	BaseParameters
	DerivedParameters
}

// DefaultSystemParameters holds the default parameters as are currently in use
// at the moment. This might (and probably will) change in the future.
var DefaultSystemParameters = SystemParameters{defaultBaseParameters, makeDerivedParameters(defaultBaseParameters)}

// ParamSize computes the size of a parameter in bytes given the size in bits.
func ParamSize(a int) int {
	return (a + 8 - 1) / 8
}
