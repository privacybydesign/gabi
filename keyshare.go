package gabi

import (
	"github.com/go-errors/errors"
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
	// Generate randomizer value, whose length is specified by the LmCommit parameter.
	// Generally LmCommit = Lm + Lh + Lstatzk, where Lstatzk is the level of security with which the
	// proof hides the secret. Generally Lstatzk = 128, but for 1024 bit keys, Lstatzk = 80.
	// So we prefer params[2048].LmCommit here, but if one of the keys is 1024 bits, then we have
	// to fall back to params[1024].LmCommit, because otherwise the larger Lstatzk will cause
	// the zero-knowledge proof response of the secret key to be too large, so that verification
	// will fail (in ProofD.correctResponseSizes()).
	randLength := gabikeys.DefaultSystemParameters[2048].LmCommit
	for _, key := range keys {
		if key.N.BitLen() == 1024 {
			randLength = gabikeys.DefaultSystemParameters[1024].LmCommit
			if secret.BitLen() > int(gabikeys.DefaultSystemParameters[1024].Lm-1) {
				// minus one to allow for the client's contribution
				return nil, nil, errors.New("cannot commit: secret too big for 1024 bit keys")
			}
			break
		}
	}

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
