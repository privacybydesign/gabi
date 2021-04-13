package gabi

import (
	"errors"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/internal/common"
)

var (
	ErrKeyMismatch = errors.New("key lengths are incompatible")
)

// Generate keyshare secret
func NewKeyshareSecret() (*big.Int, error) {
	// This value should be 1 bit less than indicated by Lm, as it is combined with an equal-length value
	// from the client, resulting in a combined value that should fit in Lm bits.
	return common.RandomBigInt(gabikeys.DefaultSystemParameters[1024].Lm - 1)
}

// Generate commitments for the keyshare server for given set of keys
func NewKeyshareCommitments(secret *big.Int, keys []*gabikeys.PublicKey) (*big.Int, []*ProofPCommitment, error) {
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
	commit, err := common.RandomBigInt(lRand)
	if err != nil {
		return nil, nil, err
	}

	// And exponentiate it with all keys
	var exponentiatedCommitments []*ProofPCommitment
	for _, key := range keys {
		exponentiatedCommitments = append(exponentiatedCommitments,
			&ProofPCommitment{
				P:       new(big.Int).Exp(key.R[0], secret, key.N),
				Pcommit: new(big.Int).Exp(key.R[0], commit, key.N),
			})
	}

	return commit, exponentiatedCommitments, nil
}

// Generate keyshare response for a given challenge and commit, given a secret
func KeyshareResponse(secret, commit, challenge *big.Int, key *gabikeys.PublicKey) *ProofP {
	return &ProofP{
		P:         new(big.Int).Exp(key.R[0], secret, key.N),
		C:         new(big.Int).Set(challenge),
		SResponse: new(big.Int).Add(commit, new(big.Int).Mul(challenge, secret)),
	}
}
