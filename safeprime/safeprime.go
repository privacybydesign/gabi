// +build !android,!ios,!windows,cgo

// Package safeprime is a small wrapper around openssl's BN_generate_prime_ex for generating safe primes.
package safeprime

import (
	"errors"
	"math/big"

	"github.com/rainycape/dl"
)

var (
	bnNew      func() uintptr
	bnFree     func(uintptr)
	bnGenPrime func(uintptr, int, int, uintptr, uintptr, uintptr) int
	bnToHex    func(uintptr) string
)

// Generate uses openssl's BN_generate_prime_ex to generate a new safe prime of the given size.
func Generate(bitsize int) (*big.Int, error) {
	openssl, err := linkOpenssl()
	if err != nil {
		return nil, err
	}
	defer openssl.Close()

	bignum := bnNew()
	if bignum == 0 {
		return nil, errors.New("BN_new could not allocate new bignum")
	}
	defer bnFree(bignum)

	if r := bnGenPrime(bignum, bitsize, 1, 0, 0, 0); r != 1 {
		return nil, errors.New("BN_generate_prime_ex failed")
	}

	x := new(big.Int)
	x.SetString(bnToHex(bignum), 16)
	return x, nil
}

func linkOpenssl() (*dl.DL, error) {
	openssl, err := dl.Open("libssl", 0)
	if err != nil {
		return nil, err
	}

	if err = openssl.Sym("BN_new", &bnNew); err != nil {
		return nil, err
	}
	if err = openssl.Sym("BN_clear_free", &bnFree); err != nil {
		return nil, err
	}
	if err = openssl.Sym("BN_generate_prime_ex", &bnGenPrime); err != nil {
		return nil, err
	}
	if err = openssl.Sym("BN_bn2hex", &bnToHex); err != nil {
		return nil, err
	}

	return openssl, nil
}
