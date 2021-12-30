// +build !android,!ios

// Package safeprime computes safe primes, i.e. primes of the form 2p+1 where p is also prime.
package safeprime

import (
	"crypto/rand"
	"io"
	"runtime"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
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
//     If (and only if) q is prime and 2^(2q) = 1 mod (2q+1), then 2q+1 is a safe prime.
// The algorithm works as follows:
//   - We take a random bigint q;
//   - We do some bit manipulation to ensure that it has the right size and is not even;
//   - We sieve out a number of small prime factors: we add 2 to it until it is not a multiple of
//     any prime below and including 53;
//   - Then, if the above formula holds and q is prime, we return 2q+1.
// (See https://groups.google.com/group/sci.crypt/msg/34c4abf63568a8eb and below.)
//
// In order to cancel the generation algorithm, send a struct{} on the stop parameter or close() it.
// (Passing nil is allowed; then the algorithm cannot be cancelled).
func Generate(bitsize int, stop chan struct{}) (*big.Int, error) {
	var (
		one        = big.NewInt(1)
		two        = big.NewInt(2)
		twoq       = new(big.Int)
		twoqone    = new(big.Int)
		twoexptwoq = new(big.Int)
		q          = new(big.Int)
		bigMod     = new(big.Int)
		err        error
		i          int
	)

	// The algorithm generates a prime q and then returns 2q+1. The latter must have length bitsize,
	// so the former must be one bit shorter.
	bitsize--

	// b is the number of bits in the most significant byte of the output that will be part of our q
	b := uint(bitsize % 8)
	if b == 0 {
		b = 8
	}

	// We read our random bytes into this. Adding 7 effectively rounds the division up instead of down
	bytes := make([]byte, (bitsize+7)/8)

NextCandidate:
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

		_, err = io.ReadFull(rand.Reader, bytes)
		if err != nil {
			return nil, err
		}

		// Manipulate our bytes so that it results in an odd number of the right size
		prepareBytes(bytes, b)

		q.SetBytes(bytes)

		// Calculate the value mod the product of SmallPrimes. If it's a multiple of any of these
		// primes we discard this candidate. This check is much cheaper than the modular arithmetic
		// and ProbablyPrime() below.
		// Based on rand.Prime() in crypto/rand/util.go from Go 1.16.5.
		bigMod.Mod(q, common.SmallPrimesProduct)
		mod := bigMod.Uint64()
		for _, prime := range common.SmallPrimes {
			if mod%uint64(prime) == 0 && (bitsize > 6 || mod != uint64(prime)) {
				continue NextCandidate
			}
		}

		// Now check the formula 2^(2q) mod (2q+1) == 1
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

// prepareBytes ensures that the specified bytes, when passed to big.Int.SetBytes(), results in a
// bigint that is not too large, not too small, and odd. (This function is inlined by the compiler.)
//
// Copied from rand.Prime() in crypto/rand/util.go from Go 1.16.5.
func prepareBytes(bytes []byte, b uint) {
	// Clear bits in the first byte to make sure the candidate has a size <= bitsize.
	bytes[0] &= uint8(int(1<<b) - 1)
	// Don't let the value be too small, i.e, set the most significant two bits.
	// Setting the top two bits, rather than just the top bit,
	// means that when two of these values are multiplied together,
	// the result isn't ever one bit short.
	if b >= 2 {
		bytes[0] |= 3 << (b - 2)
	} else {
		// Here b==1, because b cannot be zero.
		bytes[0] |= 1
		if len(bytes) > 1 {
			bytes[1] |= 0x80
		}
	}
	// Make the value odd since an even number this large certainly isn't prime.
	bytes[len(bytes)-1] |= 1
}

/*
Here we include a proof of the statement above based on the argument from
https://groups.google.com/group/sci.crypt/msg/34c4abf63568a8eb, and on "Algorithms to Compute a
Generator of the Group (Z_p^*,×_p) and Safe Primes", Pinaki Mitra, M Durgaprasada Rao and M Kranthi
Kumara, International Journal of Information Processing, 2(1), 29 - 35, 2008.

Theorem: If (and only if) q is prime and 2^(2q) = 1 mod (2q+1), then 2q+1 is a safe prime.

Proof: The "only if" direction follows immediately from Fermat's little theorem. Thus, suppose that
q is prime and that the equation holds. Consider the order of 2 within the multiplicative group of
the integers modulo p := 2q + 1. Since 2^(2q) mod (2q+1) = 1, the order must divide 2q. Since q is
prime, the only divisors of 2q are 1, 2, q and 2q, so the order of 2 must equal one of these. It
cannot be 1 or 2, since p must be at least 5, so the order equals either q or 2q. Either way, q
divides the order.

Now the order of any element must divide the order of the group, so q also divides the order of the
multiplicative group mod p. Additionally, 2 divides the order of this group, because as is easily
seen, p-1 has order 2. If q > 2 then since gcd(2, q) = 1 it follows that 2q divides the order of the
group (and even if q=2 this holds since it's true for p=5). The order of the group cannot be larger
than 2q = p - 1, so it must be equal to 2q = p - 1, which only happens if p is prime. QED

Note that because of the "only if" direction of the theorem, sieving safe prime candidates using
this equation does not sieve out any safe primes.
*/
