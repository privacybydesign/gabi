package credential

// TODO: properly comment all data structures and functions
import (
	"crypto/rand"
	"errors"
	"math/big"
)

type Issuer struct {
	sk      *PrivateKey
	pk      *PublicKey
	context *big.Int
}

var (
	ErrIncorrectCommitment = errors.New("The commitment proof is not correct.")
)

// NewIssuer creates a new credential issuer.
func NewIssuer(sk *PrivateKey, pk *PublicKey, context *big.Int) *Issuer {
	return &Issuer{sk: sk, pk: pk, context: context}
}

// IssueSignature produces an IssueSignatureMessage for the attributes based on
// the IssueCommitmentMessage provided. Note that this function DOES NOT check
// the proofs containted in the IssueCommitmentMessage! That needs to be done at
// a higher level!
func (i *Issuer) IssueSignature(msg *IssueCommitmentMessage, attributes []*big.Int, nonce1 *big.Int) (*IssueSignatureMessage, error) {

	signature, err := i.signCommitmentAndAttributes(msg.U, attributes)
	if err != nil {
		return nil, err
	}
	proof := i.proveSignature(signature, msg.Nonce2)

	return &IssueSignatureMessage{Signature: signature, Proof: proof}, nil
}

func (i *Issuer) ProofSignature(signature CLSignature, n2 big.Int) *ProofS {
	return nil
}

func (i *Issuer) signCommitmentAndAttributes(U *big.Int, attributes []*big.Int) (*CLSignature, error) {
	// Skip the first generator
	return signMessageBlockAndCommitment(i.sk, i.pk, U, attributes, i.pk.R[1:])
}

// randomElementMultiplicativeGroup returns a random element in the
// multiplicative group Z_{modulus}^*.
func randomElementMultiplicativeGroup(modulus *big.Int) *big.Int {
	r := big.NewInt(0)
	t := new(big.Int)
	for r.Sign() <= 0 || t.GCD(nil, nil, r, modulus).Cmp(bigONE) != 0 {
		// TODO: for memory/cpu efficiency re-use r's memory. See Go's
		// implementation for finding a random prime.
		r, _ = rand.Int(rand.Reader, modulus)
	}
	return r
}

func (i *Issuer) proveSignature(signature *CLSignature, nonce2 *big.Int) *ProofS {
	Q := new(big.Int).Exp(signature.A, signature.E, &i.pk.N)
	groupModulus := new(big.Int).Mul(&i.sk.PPrime, &i.sk.QPrime)
	d := new(big.Int).ModInverse(signature.E, groupModulus)

	eCommit := randomElementMultiplicativeGroup(groupModulus)
	ACommit := new(big.Int).Exp(Q, eCommit, &i.pk.N)

	c := hashCommit([]*big.Int{i.context, Q, signature.A, nonce2, ACommit})
	eResponse := new(big.Int).Mul(c, d)
	eResponse.Sub(eCommit, eResponse).Mod(eResponse, groupModulus)

	return &ProofS{c, eResponse}
}
