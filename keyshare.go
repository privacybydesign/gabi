package gabi

import (
	"crypto/sha256"
	"crypto/subtle"

	"github.com/fxamacker/cbor"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/internal/common"
)

var bigOne = big.NewInt(1)

type KeyshareCommitmentRequest struct {
	HashedUserCommitments []byte `json:"hashedComms"`
}

type KeyshareResponseRequest[T any] struct {
	Context            *big.Int `json:"context,omitempty"`
	Nonce              *big.Int `json:"nonce"`
	UserResponse       *big.Int `json:"resp"`
	IsSignatureSession bool     `json:"sig"`

	ChallengeInput []KeyshareChallengeInput[T]
}

type KeyshareChallengeInput[T any] struct {
	KeyID            *T         `json:"key,omitempty"`
	Value            *big.Int   `json:"val"`
	Commitment       *big.Int   `json:"comm"`
	OtherCommitments []*big.Int `json:"otherComms,omitempty"`
}

func KeyshareUserCommitmentsHash[T any](i []KeyshareChallengeInput[T]) ([]byte, error) {
	bts, err := cbor.Marshal(i, cbor.EncOptions{})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(bts)
	return h[:], nil
}

func KeyshareResponseNew[T comparable](
	secret *big.Int,
	randomizer *big.Int,
	req KeyshareCommitmentRequest,
	res KeyshareResponseRequest[T],
	keys map[T]*gabikeys.PublicKey,
) (*ProofP, error) {
	// Sanity checks
	for _, k := range res.ChallengeInput {
		if k.KeyID != nil && keys[*k.KeyID] == nil {
			return nil, errors.Errorf("missing public key for key %v", k)
		}
	}
	if res.Context == nil {
		res.Context = bigOne
	}

	hashContribs := make([]KeyshareChallengeInput[T], 0, len(res.ChallengeInput))
	challengeContribs := make([]*big.Int, 0, len(res.ChallengeInput)*2)

	for _, data := range res.ChallengeInput {
		hashContribs = append(hashContribs, data)
		if data.KeyID == nil {
			challengeContribs = append(challengeContribs, data.Value, data.Commitment)
			challengeContribs = append(challengeContribs, data.OtherCommitments...)
			continue
		}

		// Compute challenge contributions
		pk := keys[*data.KeyID]
		totalW := new(big.Int)
		totalW.Mul(data.Commitment, new(big.Int).Exp(pk.R[0], randomizer, pk.N)).Mod(totalW, pk.N)
		challengeContribs = append(challengeContribs, data.Value, totalW)
		challengeContribs = append(challengeContribs, data.OtherCommitments...)
	}

	// Check that h_W sent in the commitment request equals the hash over the expected values
	b, err := KeyshareUserCommitmentsHash(hashContribs)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(b, req.HashedUserCommitments) != 1 {
		return nil, errors.New("incorrect commitment hash sent in commitment request")
	}

	challenge := createChallenge(res.Context, res.Nonce, challengeContribs, res.IsSignatureSession)

	// Compute our response and return the total response
	ourResponse := new(big.Int).Add(randomizer, new(big.Int).Mul(challenge, secret))
	totalResponse := new(big.Int).Add(ourResponse, res.UserResponse)
	return &ProofP{C: challenge, SResponse: totalResponse}, nil
}

// NewKeyshareSecret generates keyshare secret
func NewKeyshareSecret() (*big.Int, error) {
	// This value should be 1 bit less than indicated by Lm, as it is combined with an equal-length value
	// from the client, resulting in a combined value that should fit in Lm bits.
	return common.RandomBigInt(gabikeys.DefaultSystemParameters[1024].Lm - 1)
}

// keyshareSecretRandomizerLength is the length of the randomizer used by the keyshare server
// in the zero knowledge proof over its secret.
// Given that with this zero knowledge proof we are hiding a secret of length params[1024].Lm,
// normally we would use params[1024].LmCommit here. Generally LmCommit = Lm + Lh + Lstatzk,
// where Lstatzk is the level of security with which the proof hides the secret.
// However, params[1024].Lstatzk = 80 while everywhere else we use Lstatzk = 128.
// So we set it to 128 for extra security.
var keyshareSecretRandomizerLength = gabikeys.DefaultSystemParameters[2048].Lstatzk

// NewKeyshareCommitments generates commitments for the keyshare server for given set of keys
func NewKeyshareCommitments(secret *big.Int, keys []*gabikeys.PublicKey) (*big.Int, []*ProofPCommitment, error) {
	// Generate randomizer value.
	randLength := gabikeys.DefaultSystemParameters[1024].Lm +
		gabikeys.DefaultSystemParameters[1024].Lh +
		keyshareSecretRandomizerLength

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
