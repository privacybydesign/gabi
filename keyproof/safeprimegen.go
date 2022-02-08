package keyproof

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/safeprime"
)

// Performance parameter, defines amount of extra bits allowed when using a convenient safe prime
const convenientRange = 100

// A convenient safe prime is a safe prime of the form
// 2^exp - diff for small positive diff.
type convenientSafePrime struct {
	Exp  int
	Diff int
}

var convenientSafePrimes = []convenientSafePrime{
	{787, 7341},
	{836, 12077},
	{912, 7577},
	{933, 6249},
	{985, 3645},
	{1008, 3317},
	{1259, 2505},
	{1307, 4425},
	{1503, 1629},
	{1567, 3309},
	{2043, 11301},
	{2145, 429},
	{2639, 163185},
	{2659, 91209},
	{2661, 71745},
	{2705, 5445},
	{4099, 5025},
	{4682, 190265},
	{4743, 268629},
}

func findConvenientPrime(size int) *big.Int {
	for _, cp := range convenientSafePrimes {
		if cp.Exp > size && cp.Exp-size < convenientRange {
			var ret, diff big.Int
			diff.SetUint64(uint64(cp.Diff))
			ret.SetUint64(1)
			ret.Lsh(&ret, uint(cp.Exp))
			ret.Sub(&ret, &diff)
			return &ret
		}
	}
	return nil
}

func findSafePrime(size int) *big.Int {
	result := findConvenientPrime(size)
	if result == nil {
		var err error
		stop := make(chan struct{})
		resultChan, errChan := safeprime.GenerateConcurrent(size, stop)
		select {
		case result = <-resultChan:
			stop <- struct{}{}
			break
		case err = <-errChan:
			panic(err.Error())
		}
	}
	return result
}
