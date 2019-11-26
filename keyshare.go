package gabi

import (
	"crypto/rand"
	"errors"

	"github.com/privacybydesign/gabi/big"
)

var (
	ErrKeyMismatch = errors.New("key lengths are incompatible")
)

// Generate keyshare secret
func NewKeyshareSecret() (*big.Int, error) {
	// This value should be 1 bit less than indicated by Lm, as it is combined with an equal-length value
	// from the client, resulting in a combined value that should fit in Lm bits.
	return big.RandInt(rand.Reader, new(big.Int).Lsh(big.NewInt(1), DefaultSystemParameters[1024].Lm-1))
}

// Return a hidden copy of the keyshare's part of the 0-attribute
func KeyshareExponentiatedSecret(secret *big.Int, key *PublicKey) *big.Int {
	return new(big.Int).Exp(key.R[0], secret, key.N)
}

// Generate commitments for the keyshare server for given set of keys
func NewKeyshareCommitments(keys []*PublicKey) (*big.Int, []*big.Int, error) {
	// Determine required randomizer length
	var lRand uint = 0
	for _, key := range keys {
		lCur := key.Params.LmCommit
		if lRand != 0 && lCur != lRand {
			return nil, nil, ErrKeyMismatch
		}
		lRand = lCur
	}

	// Generate commitment value
	commit, err := big.RandInt(rand.Reader, new(big.Int).Lsh(big.NewInt(1), lRand))
	if err != nil {
		return nil, nil, err
	}

	// And exponentiate it with all keys
	var exponentiatedCommitments []*big.Int
	for _, key := range keys {
		exponentiatedCommitments = append(exponentiatedCommitments,
			new(big.Int).Exp(key.R[0], commit, key.N))
	}

	return commit, exponentiatedCommitments, nil
}

// Generate keyshare response for a given challenge and commit, given a secret
func KeyshareResponse(secret, commit, challenge *big.Int) *big.Int {
	return new(big.Int).Add(commit, new(big.Int).Mul(challenge, secret))
}
