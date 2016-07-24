// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
)

// IssueCommitmentMessage encapsulates the messages sent by the receiver to the
// issuer in the second step of the issuance protocol.
type IssueCommitmentMessage struct {
	U      *big.Int
	Nonce2 *big.Int
	Proofs ProofList
}

// IssueSignatureMessage encapsulates the messages sent from the issuer to the
// reciver in the final step of the issuance protocol.
type IssueSignatureMessage struct {
	Proof     *ProofS
	Signature *CLSignature
}

// commitmentToSecret produces a commitment to the provided secret
func commitmentToSecret(pk *PublicKey, secret *big.Int) (vPrime, U *big.Int) {
	vPrime, _ = randomBigInt(pk.Params.LvPrime)
	// U = S^{vPrime} * R_0^{s}
	Sv := new(big.Int).Exp(pk.S, vPrime, pk.N)
	R0s := new(big.Int).Exp(pk.R[0], secret, pk.N)
	U = new(big.Int).Mul(Sv, R0s)
	U.Mod(U, pk.N)
	return
}

// NewCredentialBuilder creates a new credential builder. The resulting credential builder
// is already committed to the provided secret.
func NewCredentialBuilder(pk *PublicKey, context, secret *big.Int) *CredentialBuilder {
	vPrime, U := commitmentToSecret(pk, secret)

	return &CredentialBuilder{pk: pk, context: context, secret: secret, vPrime: vPrime, u: U}
}

// CommitToSecretAndProve creates the response to the initial challenge nonce
// nonce1 sent by the issuer. The response consists of a commitment to the
// secret (set on creation of the builder, see NewBuilder) and a proof of
// correctness of this commitment.
func (b *CredentialBuilder) CommitToSecretAndProve(nonce1 *big.Int) *IssueCommitmentMessage {
	proofU := b.proveCommitment(b.u, nonce1)
	b.nonce2, _ = randomBigInt(b.pk.Params.Lstatzk)

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
	signature := &CLSignature{msg.Signature.A, msg.Signature.E, new(big.Int).Add(msg.Signature.V, b.vPrime)}

	// Verify signature
	exponents := make([]*big.Int, len(attributes)+1)
	exponents[0] = b.secret
	copy(exponents[1:], attributes)

	if !signature.Verify(b.pk, exponents) {
		return nil, ErrIncorrectAttributeSignature
	}
	return &Credential{Pk: b.pk, Signature: signature, Attributes: exponents}, nil
}

// intHashSha256 is a utility function compute the sha256 hash over a byte array
// and return this hash as a big.Int.
func intHashSha256(input []byte) *big.Int {
	h := sha256.New()
	h.Write(input)
	return new(big.Int).SetBytes(h.Sum(nil))
}

// hashCommit computes the sha256 hash over the asn1 representation of a slice
// of big integers and returns a positive big integer that can be represented
// with that hash.
func hashCommit(values []*big.Int) *big.Int {
	// The first element is the number of elements
	tmp := make([]*big.Int, len(values)+1)
	tmp[0] = big.NewInt(int64(len(values)))
	copy(tmp[1:], values)
	r, _ := asn1.Marshal(tmp)

	h := sha256.New()
	_, _ = h.Write(r)
	return new(big.Int).SetBytes(h.Sum(nil))
}

func (b *CredentialBuilder) proveCommitment(U, nonce1 *big.Int) *ProofU {
	sCommit, _ := randomBigInt(b.pk.Params.LsCommit)
	vPrimeCommit, _ := randomBigInt(b.pk.Params.LvPrimeCommit)

	// Ucommit = S^{vPrimeCommit} * R_0^{sCommit}
	Sv := new(big.Int).Exp(b.pk.S, vPrimeCommit, b.pk.N)
	R0s := new(big.Int).Exp(b.pk.R[0], sCommit, b.pk.N)
	Ucommit := new(big.Int).Mul(Sv, R0s)
	Ucommit.Mod(Ucommit, b.pk.N)

	c := hashCommit([]*big.Int{b.context, U, Ucommit, nonce1})
	sResponse := new(big.Int).Mul(c, b.secret)
	sResponse.Add(sResponse, sCommit)

	vPrimeResponse := new(big.Int).Mul(c, b.vPrime)
	vPrimeResponse.Add(vPrimeResponse, vPrimeCommit)

	return &ProofU{u: U, c: c, vPrimeResponse: vPrimeResponse, sResponse: sResponse}
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

	pk      *PublicKey
	context *big.Int
}

// Commit commits to the secret (first) attribute using the provided randomizer.
func (b *CredentialBuilder) Commit(skRandomizer *big.Int) []*big.Int {
	// create receiver nonce (nonce2)
	b.nonce2, _ = randomBigInt(b.pk.Params.Lstatzk)

	b.skRandomizer = skRandomizer
	// vPrimeCommit
	b.vPrimeCommit, _ = randomBigInt(b.pk.Params.LvPrimeCommit)

	// U_commit = S^{v_prime_commit} * R_0^{s_commit}
	sv := new(big.Int).Exp(b.pk.S, b.vPrimeCommit, b.pk.N)
	r0s := new(big.Int).Exp(b.pk.R[0], b.skRandomizer, b.pk.N)
	b.uCommit = new(big.Int).Mul(sv, r0s)
	b.uCommit.Mod(b.uCommit, b.pk.N)

	return []*big.Int{b.u, b.uCommit}
}

// CreateProof creates a (ProofU) Proof using the provided challenge.
func (b *CredentialBuilder) CreateProof(challenge *big.Int) Proof {
	sResponse := new(big.Int).Add(b.skRandomizer, new(big.Int).Mul(challenge, b.secret))
	vPrimeResponse := new(big.Int).Add(b.vPrimeCommit, new(big.Int).Mul(challenge, b.vPrime))

	return &ProofU{u: b.u, c: challenge, vPrimeResponse: vPrimeResponse, sResponse: sResponse}
}
