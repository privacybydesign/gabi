package credential

import (
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
)

type Builder struct {
	secret *big.Int
	vPrime *big.Int
	nonce2 *big.Int

	pk      *PublicKey
	context *big.Int
}

type IssueCommitmentMessage struct {
	U      *big.Int
	Nonce2 *big.Int
	ProofU
}

type IssueSignatureMessage struct {
	proof     *ProofS
	signature *CLSignature
}

type IdemixCredential struct {
	signature  *CLSignature
	issuerPK   *PublicKey
	attributes []*big.Int
}

func (b *Builder) CommitToSecretAndProve(secret, nonce1 *big.Int) *IssueCommitmentMessage {
	b.secret = secret
	U := b.commitmentToSecret()
	proofU := b.proveCommitment(U, nonce1)
	b.nonce2, _ = randomBigInt(b.pk.Params.Lstatzk)

	return &IssueCommitmentMessage{U: U, ProofU: *proofU, Nonce2: b.nonce2}
}

var (
	IncorrectProofOfSignatureCorrectness = errors.New("Proof of correctness on signature does not verify.")
	IncorrectAttributeSignature          = errors.New("The Signature on the attributes is not correct.")
)

func (b *Builder) ConstructCredential(msg *IssueSignatureMessage, attributes []*big.Int) (*IdemixCredential, error) {
	if !msg.proof.Verify(b.pk, msg.signature, b.context, b.nonce2) {
		return nil, IncorrectProofOfSignatureCorrectness
	}

	// Construct actual signature
	signature := &CLSignature{msg.signature.A, msg.signature.E, new(big.Int).Add(msg.signature.V, b.vPrime)}

	// Verify signature
	exponents := make([]*big.Int, len(attributes)+1)
	exponents[0] = b.secret
	copy(exponents[1:], attributes)

	if !signature.Verify(b.pk, exponents) {
		return nil, IncorrectAttributeSignature
	}
	return &IdemixCredential{issuerPK: b.pk, signature: signature, attributes: exponents}, nil
}

func (b *Builder) commitmentToSecret() *big.Int {
	b.vPrime, _ = randomBigInt(b.pk.Params.LvPrime)

	// U = S^{vPrime} * R_0^{s}
	Sv := new(big.Int).Exp(&b.pk.S, b.vPrime, &b.pk.N)
	R0s := new(big.Int).Exp(b.pk.R[0], b.secret, &b.pk.N)
	U := new(big.Int).Mul(Sv, R0s)
	U.Mod(U, &b.pk.N)
	return U
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

	return &ProofU{c: c, vPrimeResponse: vPrimeResponse, sResponse: sResponse}
}

func getUndisclosedAttributes(disclosedAttributes []int, numAttributes int) []int {
	check := make([]bool, numAttributes)
	for _, v := range disclosedAttributes {
		check[v] = true
	}
	r := make([]int, 0, numAttributes)
	for i, v := range check {
		if !v {
			r = append(r, i)
		}
	}
	return r
}

func (ic *IdemixCredential) CreateDisclosureProof(disclosedAttributes []int, context, nonce1 *big.Int) *ProofD {
	undisclosedAttributes := getUndisclosedAttributes(disclosedAttributes, len(ic.attributes))

	randSig := ic.signature.Randomize(ic.issuerPK)

	eCommit, _ := randomBigInt(ic.issuerPK.Params.LeCommit)
	vCommit, _ := randomBigInt(ic.issuerPK.Params.LvCommit)

	aCommits := make(map[int]*big.Int)
	for _, v := range undisclosedAttributes {
		aCommits[v], _ = randomBigInt(ic.issuerPK.Params.LmCommit)
	}

	// Z = A^{e_commit} * S^{v_commit}
	//     PROD_{i \in undisclosed} ( R_i^{a_commits{i}} )
	Ae := modPow(randSig.A, eCommit, &ic.issuerPK.N)
	Sv := modPow(&ic.issuerPK.S, vCommit, &ic.issuerPK.N)
	Z := new(big.Int).Mul(Ae, Sv)
	Z.Mod(Z, &ic.issuerPK.N)

	for _, v := range undisclosedAttributes {
		Z.Mul(Z, modPow(ic.issuerPK.R[v], aCommits[v], &ic.issuerPK.N))
		Z.Mod(Z, &ic.issuerPK.N)
	}

	c := hashCommit([]*big.Int{context, randSig.A, Z, nonce1})

	ePrime := new(big.Int).Sub(randSig.E, new(big.Int).Lsh(bigONE, ic.issuerPK.Params.Le-1))
	eResponse := new(big.Int).Mul(c, ePrime)
	eResponse.Add(eCommit, eResponse)
	vResponse := new(big.Int).Mul(c, randSig.V)
	vResponse.Add(vCommit, vResponse)

	aResponses := make(map[int]*big.Int)
	for _, v := range undisclosedAttributes {
		t := new(big.Int).Mul(c, ic.attributes[v])
		aResponses[v] = t.Add(aCommits[v], t)
	}

	aDisclosed := make(map[int]*big.Int)
	for _, v := range disclosedAttributes {
		aDisclosed[v] = ic.attributes[v]
	}

	return &ProofD{c: c, A: randSig.A, eResponse: eResponse, vResponse: vResponse, aResponses: aResponses, aDisclosed: aDisclosed}
}
