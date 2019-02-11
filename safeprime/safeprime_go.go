// +build !cgo,!android,!ios

package safeprime

import (
	"crypto/rand"

	"github.com/privacybydesign/gabi/big"
)

// Generate a safe prime of the given size, using the fact that:
//     If q is prime and 2^(2q) = 1 mod (2q+1), then q is a safe prime.
// We take a random bigint q; if the above formula holds and q is prime, then we return 2q+1.
//
// See
// https://www.ijipbangalore.org/abstracts_2(1)/p5.pdf and
// https://groups.google.com/group/sci.crypt/msg/34c4abf63568a8eb
func Generate(bitsize int) (*big.Int, error) {
	var (
		one        = big.NewInt(1)
		two        = big.NewInt(2)
		max        = new(big.Int).Lsh(one, uint(bitsize)) // 2^bitsize, len bitsize+1
		twoq       = new(big.Int)
		twoqone    = new(big.Int)
		twoexptwoq = new(big.Int)
		q          *big.Int
		bitlen     int
		err        error
	)

	for {
		if q, err = big.RandInt(rand.Reader, max); err != nil {
			return nil, err
		}

		bitlen = q.BitLen() // q < max = 2^bitsize, so bitlen <= bitsize

		if q.Bit(0) != uint(1) || // q is not odd
			bitlen < int(bitsize)-1 { // q is too small
			continue
		}

		// bitlen now equals either bitsize or bitsize - 1. We want the latter.
		// If bitlen == bitsize we use (q-1)/2 instead of q in the remainder of the algorithm.
		// This way the acceptable bit length range of big.RandInt's output is 2 bits.
		if bitlen == int(bitsize) {
			q.Sub(q, one).Div(q, two)
			if q.Bit(0) != uint(1) { // ensure again that q is odd
				continue
			}
		}

		twoq.Mul(two, q)
		twoqone.Add(twoq, one)
		twoexptwoq.Exp(two, twoq, twoqone) // 2^(2q) mod (2q+1)

		if twoexptwoq.Cmp(one) == 0 && q.ProbablyPrime(40) {
			break
		}
	}

	return twoqone, nil
}
