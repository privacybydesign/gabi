package gabi

import (
	"crypto/rand"
	"errors"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
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

// Generate keyshare parts of P for given set of keys
func KeysharePs(secret *big.Int, keys []*PublicKey) map[string]*big.Int {
	Ps := make(map[string]*big.Int)
	for _, key := range keys {
		Ps[key.KeyID] = new(big.Int).Exp(key.R[0], secret, key.N)
	}
	return Ps
}

func NewKeyshareCommitments(keys []*PublicKey) (*big.Int, map[string]*big.Int, error) {
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
	Ws := make(map[string]*big.Int)
	for _, key := range keys {
		Ws[key.KeyID] = new(big.Int).Exp(key.R[0], commit, key.N)
	}

	return commit, Ws, nil
}

// Generate commitments for the keyshare server for given set of keys
func NewProofPCommitments(secret *big.Int, keys []*PublicKey) (*big.Int, []*ProofPCommitment, error) {
	Ps := KeysharePs(secret, keys)
	commit, Ws, err := NewKeyshareCommitments(keys)

	if err != nil {
		return nil, nil, err
	}

	// Merge Ps and Ws
	ppCommitments := make([]*ProofPCommitment, len(keys))
	for i, key := range keys {
		ppCommitments[i] = &ProofPCommitment{
			P:       Ps[key.KeyID],
			Pcommit: Ws[key.KeyID],
		}
	}

	return commit, ppCommitments, nil
}

// Generate keyshare response for a givven challenge and commit, given a secret
func KeyshareResponse(userS, secret, commit, challenge *big.Int) *KeyshareContribution {
	return &KeyshareContribution{
		S: new(big.Int).Add(userS, new(big.Int).Add(commit, new(big.Int).Mul(challenge, secret))),
		C: new(big.Int).Set(challenge),
	}
}

// Generate keyshare ProofP for a given challenge and commit, given a secret
func KeyshareProofP(secret, commit, challenge *big.Int, key *PublicKey) *ProofP {
	P := KeysharePs(secret, []*PublicKey{key})
	response := KeyshareResponse(big.NewInt(0), secret, commit, challenge)
	return &ProofP{
		P:         P[key.KeyID],
		C:         response.C,
		SResponse: response.S,
	}
}

func KeyshareChallenge(userK *big.Int, Ws map[string]*big.Int) *big.Int {
	Wcontrib := prepareKeyshareContributions(Ws)
	hashList := make([]*big.Int, 1+len(Wcontrib))
	hashList[0] = userK
	copy(hashList[1:], Wcontrib)
	return common.HashCommit(hashList, false, true)
}
