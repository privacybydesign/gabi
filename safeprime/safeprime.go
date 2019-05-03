// +build !android,!ios

// Package safeprime computes safe primes, i.e. primes of the form 2p+1 where p is also prime.
package safeprime

import (
	"crypto/rand"
	"runtime"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
)

// GenerateConcurrent concurrently and continuously generates safeprimes on all CPU cores,
// until the stop channel receives a struct or is closed. If an error is encountered, generation is
// stopped in all goroutines, and the error is sent on the second return parameter.
func GenerateConcurrent(bitsize int, stop chan struct{}) (<-chan *big.Int, <-chan error) {
	count := runtime.GOMAXPROCS(0)
	ints := make(chan *big.Int, count)
	errs := make(chan error, count)

	// In order to succesfully close all goroutines below when the caller wants them to, they require
	// a channel that is close()d: just sending a struct{}{} would stop one but not all goroutines.
	// Instead of requiring the caller to close() the stop chan parameter we use our own chan for
	// this, so that we always stop all goroutines independent of whether the caller close()s stop
	// or sends a struct{}{} to it.
	stopped := make(chan struct{})
	go func() {
		select {
		case <-stop:
			close(stopped)
		case <-stopped: // stopped can also be closed by a goroutine that encountered an error
		}
	}()

	// Start safeprime generation goroutines
	for i := 0; i < count; i++ {
		go func() {
			for {
				// Pass stopped chan along; if closed, Generate() returns nil, nil
				x, err := Generate(bitsize, stopped)
				if err != nil {
					errs <- err
					close(stopped)
					return
				}

				// Only send result and continue generating if we have not been told to stop
				select {
				case <-stopped:
					return
				default:
					ints <- x
					continue
				}
			}
		}()
	}

	return ints, errs
}

// Generate a safe prime of the given size, using the fact that:
//     If q is prime and 2^(2q) = 1 mod (2q+1), then 2q+1 is a safe prime.
// We take a random bigint q; if the above formula holds and q is prime, then we return 2q+1.
// (See https://www.ijipbangalore.org/abstracts_2(1)/p5.pdf and
// https://groups.google.com/group/sci.crypt/msg/34c4abf63568a8eb)
//
// In order to cancel the generation algorithm, send a struct{} on the stop parameter or close() it.
// (Passing nil is allowed; then the algorithm cannot be cancelled).
func Generate(bitsize int, stop chan struct{}) (*big.Int, error) {
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
		i          int
	)

	for {
		// Every 1000 iterations, check if we have been asked to stop
		i++
		if stop != nil && i%1000 == 0 {
			select {
			case <-stop:
				return nil, nil
			default: // just continue with the loop
			}
		}

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
			q.Rsh(q, 1)
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

	if !ProbablySafePrime(twoqone, 40) {
		return nil, errors.New("Go safeprime generation returned non-safeprime")
	}
	return twoqone, nil
}

var two = big.NewInt(2)

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
