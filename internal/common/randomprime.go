// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package common

import (
	"io"

	"github.com/go-errors/errors"

	"github.com/privacybydesign/gabi/big"
)

// smallPrimes is a list of small, prime numbers that allows us to rapidly
// exclude some fraction of composite candidates when searching for a random
// prime. This list is truncated at the point where smallPrimesProduct exceeds
// a uint64. It does not include two because we ensure that the candidates are
// odd by construction.
var smallPrimes = []uint8{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
}

// smallPrimesProduct is the product of the values in smallPrimes and allows us
// to reduce a candidate prime by this number and then determine whether it's
// coprime to all the elements of smallPrimes without further big.Int
// operations.
var smallPrimesProduct = new(big.Int).SetUint64(16294579238595022365)

// RandomPrimeInRange returns a random probable prime in the range [2^start, 2^start + 2^length]
// This code is an adaption of Go's own Prime function in rand/util.go
func RandomPrimeInRange(rand io.Reader, start, length uint) (p *big.Int, err error) {
	if start < 2 {
		err = errors.New("randomPrimeInRange: prime size must be at least 2-bit")
		return
	}

	b := uint(length % 8)
	if b == 0 {
		b = 8
	}

	startVal := new(big.Int).Lsh(big.NewInt(1), start)
	endVal := new(big.Int).Lsh(big.NewInt(1), length)
	endVal.Add(endVal, startVal)

	bytes := make([]byte, (length+7)/8)
	offset := new(big.Int)

	p = new(big.Int)
	bigMod := new(big.Int)

	for {
		_, err = io.ReadFull(rand, bytes)
		if err != nil {
			return nil, err
		}

		// Clear bits in the first byte to make sure the candidate has a size <= length.
		bytes[0] &= uint8(int(1<<b) - 1)

		// Make the value odd since an even number this large certainly isn't prime.
		bytes[len(bytes)-1] |= 1

		offset.SetBytes(bytes)

		p.Add(startVal, offset)

		// Calculate the value mod the product of smallPrimes.  If it's
		// a multiple of any of these primes we add two until it isn't.
		// The probability of overflowing is minimal and can be ignored
		// because we still perform Miller-Rabin tests on the result.
		bigMod.Mod(p, smallPrimesProduct)
		mod := bigMod.Uint64()

	NextDelta:
		for delta := uint64(0); delta < 1<<20; delta += 2 {
			m := mod + delta
			for _, prime := range smallPrimes {
				if m%uint64(prime) == 0 && (start > 6 || m != uint64(prime)) {
					continue NextDelta
				}
			}

			if delta > 0 {
				bigMod.SetUint64(delta)
				p.Add(p, bigMod)
			}
			break
		}

		// There is a tiny possibility that, by adding delta, we caused
		// the number to be one bit too long. Thus we check BitLen
		// here.
		if p.ProbablyPrime(20) && p.Cmp(endVal) < 0 {
			return
		}
	}
}
