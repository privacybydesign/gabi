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

type (
	// KeyshareCommitmentRequest contains the data the user must send to the keyshare server when it
	// requests the keyshare server's contributions to the commitments, in the joint computation of
	// the zero knowledge proof.
	KeyshareCommitmentRequest struct {
		HashedUserCommitments []byte `json:"hashedComms"`
	}

	// KeyshareResponseRequest contains the data the user must send to the keyshare server when it
	// requests the keyshare server's contributions to the responses, in the joint computation of
	// the zero knowledge proof.
	KeyshareResponseRequest[T any] struct {
		Context            *big.Int `json:"context,omitempty"`
		Nonce              *big.Int `json:"nonce"`
		UserResponse       *big.Int `json:"resp"`
		IsSignatureSession bool     `json:"sig"`

		// UserChallengeInput contains the arguments used by the user to compute the
		// HashedUserCommitments sent earlier in the commitment request.
		UserChallengeInput []KeyshareUserChallengeInput[T]
	}

	// KeyshareUserChallengeInput contains the user's contributions to the challenge, in the joint
	// computation of the zero knowledge proof.
	KeyshareUserChallengeInput[T any] struct {
		// KeyID identifies the public key for this value and commitment. If nil, the keyshare
		// server does not participate for this value and commitment.
		KeyID *T `json:"key,omitempty"`

		// Value of whose exponents the user proves knowledge; A' = AS^r (disclosure) or U (issuance).
		Value *big.Int `json:"val"`
		// Commitment is the user's contributions to the commitment of this proof of knowledge.
		Commitment *big.Int `json:"comm"`

		// OtherCommitments contain commitments for non-revocation proofs and range proofs
		// (if present).
		OtherCommitments []*big.Int `json:"otherComms,omitempty"`
	}
)

type publicKeyIdentifier struct {
	issuer  string
	counter uint
}

// KeyshareUserCommitmentRequest computes the user's first message to the keyshare server in the
// keyshare protocol, containing its commitment (h_W) to its contributions to the
// challenge, in the joint computation of the zero knowledge proof of the secret key.
func KeyshareUserCommitmentRequest[T comparable](
	builders ProofBuilderList, randomizers map[string]*big.Int, keys map[T]*gabikeys.PublicKey,
) (KeyshareCommitmentRequest, []KeyshareUserChallengeInput[T], error) {
	var hashInput []KeyshareUserChallengeInput[T]

	// Compute a lookup map for the iteration over `builders` below, to fetch the key ID of the
	// public key of the builder (or nil if the key is not in `keys`, i.e., if it does not
	// participate in the keyshare protocol).
	keyIDs := map[publicKeyIdentifier]*T{}
	for keyID, key := range keys {
		keyID := keyID
		keyIDs[publicKeyIdentifier{issuer: key.Issuer, counter: key.Counter}] = &keyID
	}

	for _, builder := range builders {
		c, err := builder.Commit(randomizers)
		if err != nil {
			return KeyshareCommitmentRequest{}, nil, err
		}
		var otherComms []*big.Int
		if len(c) > 2 {
			otherComms = c[2:]
		}
		pk := builder.PublicKey()
		hashInput = append(hashInput, KeyshareUserChallengeInput[T]{
			KeyID:            keyIDs[publicKeyIdentifier{issuer: pk.Issuer, counter: pk.Counter}],
			Value:            new(big.Int).Set(c[0]),
			Commitment:       new(big.Int).Set(c[1]),
			OtherCommitments: otherComms,
		})
	}

	bts, err := keyshareUserCommitmentsHash(hashInput)
	if err != nil {
		return KeyshareCommitmentRequest{}, nil, err
	}
	return KeyshareCommitmentRequest{HashedUserCommitments: bts}, hashInput, nil
}

// KeyshareUserResponseRequest computes the user's second message to the keyshare server in the
// keyshare protocol, containing its response in the joint computation of the zero- knowledgeproof
// of the secret key. Also returns the challenge to be used in constructing the proofs.
func KeyshareUserResponseRequest[T comparable](
	builders ProofBuilderList,
	randomizers map[string]*big.Int,
	hashInput []KeyshareUserChallengeInput[T],
	context, nonce *big.Int,
	signature bool,
) (KeyshareResponseRequest[T], *big.Int, error) {
	// Extract the user secret from the builders. Since this secret will be the same across all
	// builders, we can just take it off the first one.
	// (We extract it manually like this instead of adding a method to the ProofBuilder interface,
	// because we don't want to expose a method to retrieve the secret in the gabi public API.)
	var userSecret *big.Int
	builder := builders[0]
	switch b := builder.(type) {
	case *CredentialBuilder:
		userSecret = b.secret
	case *DisclosureProofBuilder:
		userSecret = b.attributes[0]
	default:
		return KeyshareResponseRequest[T]{}, nil, errors.New("Unsupported proof builder")
	}

	challenge, err := builders.ChallengeWithRandomizers(context, nonce, randomizers, signature)
	if err != nil {
		return KeyshareResponseRequest[T]{}, nil, err
	}
	userResponse := new(big.Int).Add(randomizers["secretkey"], new(big.Int).Mul(challenge, userSecret))

	return KeyshareResponseRequest[T]{
		Nonce:              nonce,
		UserResponse:       userResponse,
		IsSignatureSession: signature,
		UserChallengeInput: hashInput,
	}, challenge, nil
}

func keyshareUserCommitmentsHash[T any](i []KeyshareUserChallengeInput[T]) ([]byte, error) {
	bts, err := cbor.Marshal(i, cbor.EncOptions{})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(bts)
	return h[:], nil
}

// KeyshareResponse generates the keyshare response, using the keyshare secret and the user's
// input in the keyshare protocol so far.
func KeyshareResponse[T comparable](
	secret *big.Int,
	randomizer *big.Int,
	req KeyshareCommitmentRequest,
	res KeyshareResponseRequest[T],
	keys map[T]*gabikeys.PublicKey,
) (*ProofP, error) {
	// Sanity checks
	for i, k := range res.UserChallengeInput {
		if k.KeyID != nil && keys[*k.KeyID] == nil {
			return nil, errors.Errorf("missing public key for element %d of challenge input", i)
		}
	}
	if res.Context == nil {
		res.Context = bigOne
	}

	// Assemble the input for the computation of h_W
	challengeContribs := make([]*big.Int, 0, len(res.UserChallengeInput)*2)
	for _, data := range res.UserChallengeInput {
		if data.KeyID == nil {
			challengeContribs = append(challengeContribs, data.Value, data.Commitment)
			challengeContribs = append(challengeContribs, data.OtherCommitments...)
			continue
		}

		pk := keys[*data.KeyID]
		totalW := new(big.Int)
		totalW.Mul(data.Commitment, new(big.Int).Exp(pk.R[0], randomizer, pk.N)).Mod(totalW, pk.N)
		challengeContribs = append(challengeContribs, data.Value, totalW)
		challengeContribs = append(challengeContribs, data.OtherCommitments...)
	}

	// Check that h_W sent in the commitment request equals the hash over the expected values
	recalculatedHash, err := keyshareUserCommitmentsHash(res.UserChallengeInput)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(recalculatedHash, req.HashedUserCommitments) != 1 {
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
	// During disclosure the client is required to prove that the secret is not larger in bits
	// than an upper bound specified by the Lm parameter. So we must make the secret no larger than
	// the smallest supported upper bound, i.e., that of 1024 bit keys, because otherwise the client
	// won't be able to prove that its secret is smaller than params[1024].Lm bits, because it won't be.
	// In practice this is fine because params[1024].Lm = 256 which is quite sufficient.
	// Additionally, this value should be 1 bit less than indicated by Lm, as it is combined with an
	// equal-length value from the client, resulting in a combined value that should fit in Lm bits.
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
