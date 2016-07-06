package credential

// TODO: properly comment all data structures and functions
import (
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
)

type IssueCommitmentMessage struct {
	U      *big.Int
	Nonce2 *big.Int
	Proofs ProofList
}

type IssueSignatureMessage struct {
	Proof     *ProofS
	Signature *CLSignature
}

// TODO: this needs to be changed, too much state!
// func (b *Builder) commitmentToSecret(secret *big.Int) *big.Int {
// 	b.secret = secret
// 	b.vPrime, _ = randomBigInt(b.pk.Params.LvPrime)

// 	// U = S^{vPrime} * R_0^{s}
// 	Sv := new(big.Int).Exp(&b.pk.S, b.vPrime, &b.pk.N)
// 	R0s := new(big.Int).Exp(b.pk.R[0], b.secret, &b.pk.N)
// 	U := new(big.Int).Mul(Sv, R0s)
// 	U.Mod(U, &b.pk.N)
// 	return U
// }

// TODO: needs checking!
func commitmentToSecretNew(pk *PublicKey, secret *big.Int) (vPrime, U *big.Int) {

	vPrime, _ = randomBigInt(pk.Params.LvPrime)
	// U = S^{vPrime} * R_0^{s}
	Sv := new(big.Int).Exp(&pk.S, vPrime, &pk.N)
	R0s := new(big.Int).Exp(pk.R[0], secret, &pk.N)
	U = new(big.Int).Mul(Sv, R0s)
	U.Mod(U, &pk.N)
	return
}

func (b *Builder) CommitToSecretAndProve(nonce1 *big.Int) *IssueCommitmentMessage {
	proofU := b.proveCommitment(b.u, nonce1)
	b.nonce2, _ = randomBigInt(b.pk.Params.Lstatzk)

	return &IssueCommitmentMessage{U: b.u, Proofs: ProofList{proofU}, Nonce2: b.nonce2}
}

func (b *Builder) CreateIssueCommitmentMessage(proofs ProofList) *IssueCommitmentMessage {
	return &IssueCommitmentMessage{U: b.u, Proofs: proofs, Nonce2: b.nonce2}
}

var (
	ErrIncorrectProofOfSignatureCorrectness = errors.New("Proof of correctness on signature does not verify.")
	ErrIncorrectAttributeSignature          = errors.New("The Signature on the attributes is not correct.")
)

// NewBuilder creates a new credential builder. The resulting credential builder
// is already committed to the provided secret.
func NewBuilder(pk *PublicKey, context, secret *big.Int) *Builder {
	vPrime, U := commitmentToSecretNew(pk, secret)

	return &Builder{pk: pk, context: context, secret: secret, vPrime: vPrime, u: U}
}

func (b *Builder) ConstructCredential(msg *IssueSignatureMessage, attributes []*big.Int) (*IdemixCredential, error) {
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
	return &IdemixCredential{Pk: b.pk, Signature: signature, Attributes: exponents}, nil
}

func intHashSha256(input []byte) *big.Int {
	h := sha256.New()
	h.Write(input)
	r := h.Sum(nil)
	return new(big.Int).SetBytes(r)
}

// hashCommit computes the sha256 hash over the asn1 representation of a slice of big integers
// and returns a positive big integer that can be represented with that hash.
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

func (b *Builder) proveCommitment(U, nonce1 *big.Int) *ProofU {
	sCommit, _ := randomBigInt(b.pk.Params.LsCommit)
	vPrimeCommit, _ := randomBigInt(b.pk.Params.LvPrimeCommit)

	// Ucommit = S^{vPrimeCommit} * R_0^{sCommit}
	Sv := new(big.Int).Exp(&b.pk.S, vPrimeCommit, &b.pk.N)
	R0s := new(big.Int).Exp(b.pk.R[0], sCommit, &b.pk.N)
	Ucommit := new(big.Int).Mul(Sv, R0s)
	Ucommit.Mod(Ucommit, &b.pk.N)

	c := hashCommit([]*big.Int{b.context, U, Ucommit, nonce1})
	sResponse := new(big.Int).Mul(c, b.secret)
	sResponse.Add(sResponse, sCommit)

	vPrimeResponse := new(big.Int).Mul(c, b.vPrime)
	vPrimeResponse.Add(vPrimeResponse, vPrimeCommit)

	return &ProofU{u: U, c: c, vPrimeResponse: vPrimeResponse, sResponse: sResponse}
}

type Builder struct {
	secret       *big.Int
	vPrime       *big.Int
	vPrimeCommit *big.Int
	nonce2       *big.Int
	u            *big.Int
	uCommit      *big.Int
	skCommitment *big.Int

	pk      *PublicKey
	context *big.Int
}

// TODO: rename skCommitment
func (b *Builder) Commit(skCommitment *big.Int) []*big.Int {
	// create receiver nonce (nonce2)
	b.nonce2, _ = randomBigInt(b.pk.Params.Lstatzk)

	b.skCommitment = skCommitment
	// vPrimeCommit
	b.vPrimeCommit, _ = randomBigInt(b.pk.Params.LvPrimeCommit)

	// U_commit = S^{v_prime_commit} * R_0^{s_commit}
	sv := new(big.Int).Exp(&b.pk.S, b.vPrimeCommit, &b.pk.N)
	r0s := new(big.Int).Exp(b.pk.R[0], b.skCommitment, &b.pk.N)
	b.uCommit = new(big.Int).Mul(sv, r0s)
	b.uCommit.Mod(b.uCommit, &b.pk.N)

	return []*big.Int{b.u, b.uCommit}
}

func (b *Builder) CreateProof(challenge *big.Int) Proof {
	sResponse := new(big.Int).Add(b.skCommitment, new(big.Int).Mul(challenge, b.secret))
	vPrimeResponse := new(big.Int).Add(b.vPrimeCommit, new(big.Int).Mul(challenge, b.vPrime))

	return &ProofU{u: b.u, c: challenge, vPrimeResponse: vPrimeResponse, sResponse: sResponse}
}
