package safeprime

import "github.com/privacybydesign/gabi/big"

// ProbablySafePrime reports whether x is probably safe prime, by calling big.Int.ProbablyPrime(n)
// on x as well as on (x-1)/2.
//
// If x is safe prime, ProbablySafePrime returns true.
// If x is chosen randomly and not safe prime, ProbablyPrime probably returns false.
func ProbablySafePrime(x *big.Int, n int) bool {
	if x.Cmp(two) <= 0 {
		return false
	}
	if !x.ProbablyPrime(n) {
		return false
	}
	y := new(big.Int).Rsh(x, 1)
	return y.ProbablyPrime(n)
}

var two = big.NewInt(2)
