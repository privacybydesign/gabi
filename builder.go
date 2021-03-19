// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"encoding/json"
	"time"

	"github.com/go-errors/errors"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/revocation"
)

// IssueCommitmentMessage encapsulates the messages sent by the receiver to the
// issuer in the second step of the issuance protocol.
type IssueCommitmentMessage struct {
	U                    *big.Int            `json:"U,omitempty"`
	Nonce2               *big.Int            `json:"n_2"`
	Proofs               ProofList           `json:"combinedProofs"`
	ProofPjwt            string              `json:"proofPJwt,omitempty"`
	ProofPjwts           map[string]string   `json:"proofPJwts,omitempty"`
	KeyshareWs           map[string]*big.Int `json:"keyshareWs,omitempty"`
	KeyshareContribution string              `json:"keyshareContribution,omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler (json's default unmarshaler
// is unable to handle a list of interfaces).
func (pl *ProofList) UnmarshalJSON(bytes []byte) error {
	proofs := []Proof{}
	temp := []json.RawMessage{}
	if err := json.Unmarshal(bytes, &temp); err != nil {
		return err
	}
	for _, proofbytes := range temp {
		proofd := &ProofD{}
		if err := json.Unmarshal(proofbytes, proofd); err != nil {
			return err
		}
		if proofd.A != nil {
			proofs = append(proofs, proofd)
			continue
		}
		proofu := &ProofU{}
		if err := json.Unmarshal(proofbytes, proofu); err != nil {
			return err
		}
		if proofu.U != nil {
			proofs = append(proofs, proofu)
			continue
		}
		return errors.New("Unknown proof type found in ProofList")
	}
	*pl = proofs
	return nil
}

// IssueSignatureMessage encapsulates the messages sent from the issuer to the
// reciver in the final step of the issuance protocol.
type IssueSignatureMessage struct {
	Proof                *ProofS             `json:"proof"`
	Signature            *CLSignature        `json:"signature"`
	NonRevocationWitness *revocation.Witness `json:"nonrev,omitempty"`
	MIssuer              map[int]*big.Int    `json:"m_issuer,omitempty"` // Issuers shares of random blind attributes
}

// Commits to the provided secret and user's share of random blind attributes "msg"
func userCommitment(pk *PublicKey, secret *big.Int, vPrime *big.Int, msg map[int]*big.Int) (U *big.Int) {
	// U = S^{vPrime} * R0^{secret} * Ri^{mi}
	U = new(big.Int).Exp(pk.S, vPrime, pk.N)
	U.Mul(U, new(big.Int).Exp(pk.R[0], secret, pk.N))
	for i, mi := range msg {
		U.Mul(U, new(big.Int).Exp(pk.R[i], mi, pk.N))
	}
	U.Mod(U, pk.N)
	return
}

// NewCredentialBuilder creates a new credential builder.
// The resulting credential builder is already committed to the provided secret.
// arg blind: list of indices of random blind attributes (exlcuding the secret key)
func NewCredentialBuilder(pk *PublicKey, context, secret *big.Int, nonce2 *big.Int, blind []int) *CredentialBuilder {
	vPrime, _ := common.RandomBigInt(pk.Params.LvPrime)
	mUser := make(map[int]*big.Int, len(blind))
	for _, i := range blind {
		mUser[i+1], _ = common.RandomBigInt(pk.Params.Lm - 1)
	}

	// Commit to secret and, optionally, user's shares of random blind attributes
	U := userCommitment(pk, secret, vPrime, mUser)

	return &CredentialBuilder{
		pk:      pk,
		context: context,
		secret:  secret,
		vPrime:  vPrime,
		u:       U,
		uCommit: big.NewInt(1),
		nonce2:  nonce2,
		mUser:   mUser,
	}
}

// CommitToSecretAndProve creates the response to the initial challenge nonce
// nonce1 sent by the issuer. The response consists of a commitment to the
// secret (set on creation of the builder, see NewBuilder) and a proof of
// correctness of this commitment.
func (b *CredentialBuilder) CommitToSecretAndProve(nonce1 *big.Int) *IssueCommitmentMessage {
	proofU := b.proveCommitment(nonce1)

	return &IssueCommitmentMessage{U: b.u, Proofs: ProofList{proofU}, Nonce2: b.nonce2}
}

// CreateIssueCommitmentMessage creates the IssueCommitmentMessage based on the
// provided prooflist, to be sent to the issuer.
func (b *CredentialBuilder) CreateIssueCommitmentMessage(proofs ProofList) *IssueCommitmentMessage {
	return &IssueCommitmentMessage{U: b.u, Proofs: proofs, Nonce2: b.nonce2}
}

var (
	// ErrIncorrectProofOfSignatureCorrectness is issued when the the proof of
	// correctness on the signature does not verify.
	ErrIncorrectProofOfSignatureCorrectness = errors.New("Proof of correctness on signature does not verify.")
	// ErrIncorrectAttributeSignature is issued when the signature on the
	// attributes is not correct.
	ErrIncorrectAttributeSignature = errors.New("The Signature on the attributes is not correct.")
)

// ConstructCredential creates a credential using the IssueSignatureMessage from
// the issuer and the content of the attributes.
func (b *CredentialBuilder) ConstructCredential(msg *IssueSignatureMessage, attributes []*big.Int) (*Credential, error) {
	if !msg.Proof.Verify(b.pk, msg.Signature, b.context, b.nonce2) {
		return nil, ErrIncorrectProofOfSignatureCorrectness
	}

	// Construct actual signature
	signature := &CLSignature{
		A: msg.Signature.A,
		E: msg.Signature.E,
		V: new(big.Int).Add(msg.Signature.V, b.vPrime),
	}
	if b.proofPcomm != nil {
		signature.KeyshareP = b.proofPcomm.P
	}

	// For all attributes that are sums of shares between user/issuer, compute this sum
	ms := append([]*big.Int{b.secret}, attributes...)
	for i, miUser := range b.mUser {
		if i >= len(ms) {
			return nil, errors.New("got too few attributes")
		}
		if ms[i] != nil {
			return nil, errors.New("attribute at random blind index should be nil before issuance")
		}
		ms[i] = new(big.Int).Add(msg.MIssuer[i], miUser) // mi = mi' + mi", for i \in randomblind
	}

	if msg.NonRevocationWitness != nil {
		rpk, err := b.pk.RevocationKey()
		if err != nil {
			return nil, err
		}
		if err = msg.NonRevocationWitness.Verify(rpk); err != nil {
			return nil, err
		}
		msg.NonRevocationWitness.Updated = time.Unix(msg.NonRevocationWitness.SignedAccumulator.Accumulator.Time, 0)
	}
	if !signature.Verify(b.pk, ms) {
		return nil, ErrIncorrectAttributeSignature
	}

	cred := &Credential{
		Pk:                   b.pk,
		Signature:            signature,
		Attributes:           ms,
		NonRevocationWitness: msg.NonRevocationWitness,
	}
	if msg.NonRevocationWitness != nil {
		if _, err := cred.NonrevIndex(); err != nil {
			return nil, err
		}
	}
	return cred, nil
}

// Creates a proofU using a provided nonce
func (b *CredentialBuilder) proveCommitment(nonce1 *big.Int) Proof {
	sCommit, _ := common.RandomBigInt(b.pk.Params.LsCommit)
	contrib := b.Commit(map[string]*big.Int{"secretkey": sCommit})
	c := createChallenge(b.context, nonce1, contrib, nil, false)
	return b.CreateProof(c)
}

// CredentialBuilder is a temporary object to hold some state for the protocol
// that is used to create (build) a credential. It also implements the
// ProofBuilder interface.
type CredentialBuilder struct {
	secret       *big.Int
	vPrime       *big.Int
	vPrimeCommit *big.Int
	nonce2       *big.Int
	u            *big.Int
	uCommit      *big.Int
	skRandomizer *big.Int

	pk         *PublicKey
	context    *big.Int
	proofPcomm *ProofPCommitment

	mUser       map[int]*big.Int // Map of users shares of random blind attributes
	mUserCommit map[int]*big.Int

	newStyleKeyshareSession bool
}

func (b *CredentialBuilder) MergeProofPCommitment(commitment *ProofPCommitment) {
	b.proofPcomm = commitment
	b.uCommit.Mod(
		b.uCommit.Mul(b.uCommit, commitment.Pcommit),
		b.pk.N,
	)
}

func (b *CredentialBuilder) MergeKeyshareP(keyshareP *big.Int) {
	b.proofPcomm = &ProofPCommitment{P: new(big.Int).Set(keyshareP)}
	b.newStyleKeyshareSession = true
}

// PublicKey returns the Idemix public key against which the credential will verify.
func (b *CredentialBuilder) PublicKey() *PublicKey {
	return b.pk
}

// Commit commits to the secret (first attribute) using the provided randomizer.
// Optionally commits to the user shares of random blind attributes if any are present.
func (b *CredentialBuilder) Commit(randomizers map[string]*big.Int) []*big.Int {
	b.skRandomizer = randomizers["secretkey"]
	b.vPrimeCommit, _ = common.RandomBigInt(b.pk.Params.LvPrimeCommit)
	b.mUserCommit = make(map[int]*big.Int)
	for i := range b.mUser {
		b.mUserCommit[i], _ = common.RandomBigInt(b.pk.Params.LmCommit)
	}

	// U_commit = U_commit * S^{v_prime_commit} * R_0^{s_commit}
	sv := new(big.Int).Exp(b.pk.S, b.vPrimeCommit, b.pk.N)
	r0s := new(big.Int).Exp(b.pk.R[0], b.skRandomizer, b.pk.N)
	b.uCommit.Mul(b.uCommit, sv).Mul(b.uCommit, r0s)
	b.uCommit.Mod(b.uCommit, b.pk.N)

	// U_commit = U_commit * R_i^{m_iUserCommit} for i in random blind
	for i := range b.mUser {
		b.uCommit.Mul(b.uCommit, new(big.Int).Exp(b.pk.R[i], b.mUserCommit[i], b.pk.N))
		b.uCommit.Mod(b.uCommit, b.pk.N)
	}

	ucomm := new(big.Int).Set(b.u)
	if b.proofPcomm != nil {
		ucomm.Mul(ucomm, b.proofPcomm.P).Mod(ucomm, b.pk.N)
	}

	return []*big.Int{ucomm, b.uCommit}
}

// CreateProof creates a (ProofU) Proof using the provided challenge.
func (b *CredentialBuilder) CreateProof(challenge *big.Int) Proof {
	sResponse := new(big.Int).Add(b.skRandomizer, new(big.Int).Mul(challenge, b.secret))
	vPrimeResponse := new(big.Int).Add(b.vPrimeCommit, new(big.Int).Mul(challenge, b.vPrime))

	mUserResponses := make(map[int]*big.Int)
	for i, miUser := range b.mUser {
		mUserResponses[i] = new(big.Int).Add(b.mUserCommit[i], new(big.Int).Mul(challenge, miUser))
	}

	var U *big.Int
	if b.newStyleKeyshareSession {
		U = new(big.Int).Mul(b.u, b.proofPcomm.P)
		U.Mod(U, b.pk.N)
	} else {
		// U can be modified in the proof, so make sure this is a copy
		U = new(big.Int).Set(b.u)
	}

	return &ProofU{
		U:              U,
		C:              challenge,
		VPrimeResponse: vPrimeResponse,
		SResponse:      sResponse,
		MUserResponses: mUserResponses,
	}
}
