package gabi

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/internal/common"
)

// NewKeyshareSecret generates keyshare secret
func NewKeyshareSecret() (*big.Int, error) {
	// This value should be 1 bit less than indicated by Lm, as it is combined with an equal-length value
	// from the client, resulting in a combined value that should fit in Lm bits.
	return common.RandomBigInt(gabikeys.DefaultSystemParameters[1024].Lm - 1)
}

// NewKeyshareCommitments generates commitments for the keyshare server for given set of keys
func NewKeyshareCommitments(secret *big.Int, keys []*gabikeys.PublicKey) (*big.Int, []*ProofPCommitment, error) {
	// Generate randomizer value.
	// Given that with this zero knowledge proof we are hiding a secret of length params[1024].Lm,
	// normally we would use params[1024].LmCommit here. Generally LmCommit = Lm + Lh + Lstatzk,
	// where Lstatzk is the level of security with which the proof hides the secret.
	// However, params[1024].Lstatzk = 80 while everywhere else we use Lstatzk = 128.
	// So instead of using params[1024].LmCommit we recompute it with the Lstatzk of key length 2048.
	randLength := gabikeys.DefaultSystemParameters[1024].Lm +
		gabikeys.DefaultSystemParameters[1024].Lh +
		gabikeys.DefaultSystemParameters[2048].Lstatzk

	randomizer, err := common.RandomBigInt(randLength)
	if err != nil {
		return nil, nil, err
	}

	// And exponentiate it with all keys
	var exponentiatedCommitments []*ProofPCommitment
	for _, key := range keys {
		exponentiatedCommitments = append(exponentiatedCommitments,
			&ProofPCommitment{
				P:       new(big.Int).Exp(key.R[0], secret, key.N),
				Pcommit: new(big.Int).Exp(key.R[0], randomizer, key.N),
			})
	}

	return randomizer, exponentiatedCommitments, nil
}

// KeyshareResponse generates the keyshare response for a given challenge and commit, given a secret
func KeyshareResponse(secret, commit, challenge *big.Int, key *gabikeys.PublicKey) *ProofP {
	return &ProofP{
		P:         new(big.Int).Exp(key.R[0], secret, key.N),
		C:         new(big.Int).Set(challenge),
		SResponse: new(big.Int).Add(commit, new(big.Int).Mul(challenge, secret)),
	}
}
