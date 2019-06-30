// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
)

// Credential represents an Idemix credential.
type Credential struct {
	Signature  *CLSignature `json:"signature"`
	Pk         *PublicKey   `json:"-"`
	Attributes []*big.Int   `json:"attributes"`
}

// DisclosureProofBuilder is an object that holds the state for the protocol to
// produce a disclosure proof.
type DisclosureProofBuilder struct {
	randomizedSignature   *CLSignature
	eCommit, vCommit      *big.Int
	attrRandomizers       map[int]*big.Int
	z                     *big.Int
	disclosedAttributes   []int
	undisclosedAttributes []int
	pk                    *PublicKey
	attributes            []*big.Int
}

// getUndisclosedAttributes computes, given a list of (indices of) disclosed
// attributes, a list of undisclosed attributes.
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

// CreateDisclosureProof creates a disclosure proof (ProofD) voor the provided
// indices of disclosed attributes.
func (ic *Credential) CreateDisclosureProof(disclosedAttributes []int, context, nonce1 *big.Int) *ProofD {
	undisclosedAttributes := getUndisclosedAttributes(disclosedAttributes, len(ic.Attributes))

	randSig := ic.Signature.Randomize(ic.Pk)

	eCommit, _ := common.RandomBigInt(ic.Pk.Params.LeCommit)
	vCommit, _ := common.RandomBigInt(ic.Pk.Params.LvCommit)

	aCommits := make(map[int]*big.Int)
	for _, v := range undisclosedAttributes {
		aCommits[v], _ = common.RandomBigInt(ic.Pk.Params.LmCommit)
	}

	// Z = A^{e_commit} * S^{v_commit}
	//     PROD_{i \in undisclosed} ( R_i^{a_commits{i}} )
	Ae := common.ModPow(randSig.A, eCommit, ic.Pk.N)
	Sv := common.ModPow(ic.Pk.S, vCommit, ic.Pk.N)
	Z := new(big.Int).Mul(Ae, Sv)
	Z.Mod(Z, ic.Pk.N)

	for _, v := range undisclosedAttributes {
		Z.Mul(Z, common.ModPow(ic.Pk.R[v], aCommits[v], ic.Pk.N))
		Z.Mod(Z, ic.Pk.N)
	}

	c := common.HashCommit([]*big.Int{context, randSig.A, Z, nonce1}, false)

	ePrime := new(big.Int).Sub(randSig.E, new(big.Int).Lsh(big.NewInt(1), ic.Pk.Params.Le-1))
	eResponse := new(big.Int).Mul(c, ePrime)
	eResponse.Add(eCommit, eResponse)
	vResponse := new(big.Int).Mul(c, randSig.V)
	vResponse.Add(vCommit, vResponse)

	aResponses := make(map[int]*big.Int)
	for _, v := range undisclosedAttributes {
		exp := ic.Attributes[v]
		if exp.BitLen() > int(ic.Pk.Params.Lm) {
			exp = common.IntHashSha256(exp.Bytes())
		}
		t := new(big.Int).Mul(c, exp)
		aResponses[v] = t.Add(aCommits[v], t)
	}

	aDisclosed := make(map[int]*big.Int)
	for _, v := range disclosedAttributes {
		aDisclosed[v] = ic.Attributes[v]
	}

	return &ProofD{C: c, A: randSig.A, EResponse: eResponse, VResponse: vResponse, AResponses: aResponses, ADisclosed: aDisclosed}
}

// CreateDisclosureProofBuilder produces a DisclosureProofBuilder, an object to
// hold the state in the protocol for producing a disclosure proof that is
// linked to other proofs.
func (ic *Credential) CreateDisclosureProofBuilder(disclosedAttributes []int) *DisclosureProofBuilder {
	d := &DisclosureProofBuilder{}
	d.z = big.NewInt(1)
	d.pk = ic.Pk
	d.randomizedSignature = ic.Signature.Randomize(ic.Pk)
	d.eCommit, _ = common.RandomBigInt(ic.Pk.Params.LeCommit)
	d.vCommit, _ = common.RandomBigInt(ic.Pk.Params.LvCommit)

	d.attrRandomizers = make(map[int]*big.Int)
	d.disclosedAttributes = disclosedAttributes
	d.undisclosedAttributes = getUndisclosedAttributes(disclosedAttributes, len(ic.Attributes))
	d.attributes = ic.Attributes
	for _, v := range d.undisclosedAttributes {
		d.attrRandomizers[v], _ = common.RandomBigInt(ic.Pk.Params.LmCommit)
	}

	return d
}

func (d *DisclosureProofBuilder) MergeProofPCommitment(commitment *ProofPCommitment) {
	d.z.Mod(
		d.z.Mul(d.z, commitment.Pcommit),
		d.pk.N,
	)
}

// PublicKey returns the Idemix public key against which this disclosure proof will verify.
func (d *DisclosureProofBuilder) PublicKey() *PublicKey {
	return d.pk
}

// Commit commits to the first attribute (the secret) using the provided
// randomizer.
func (d *DisclosureProofBuilder) Commit(randomizers map[string]*big.Int) []*big.Int {
	d.attrRandomizers[0] = randomizers["secretkey"]

	// Z = A^{e_commit} * S^{v_commit}
	//     PROD_{i \in undisclosed} ( R_i^{a_commits{i}} )
	Ae := common.ModPow(d.randomizedSignature.A, d.eCommit, d.pk.N)
	Sv := common.ModPow(d.pk.S, d.vCommit, d.pk.N)
	d.z.Mul(d.z, Ae).Mul(d.z, Sv).Mod(d.z, d.pk.N)

	for _, v := range d.undisclosedAttributes {
		d.z.Mul(d.z, common.ModPow(d.pk.R[v], d.attrRandomizers[v], d.pk.N))
		d.z.Mod(d.z, d.pk.N)
	}

	return []*big.Int{d.randomizedSignature.A, d.z}
}

// CreateProof creates a (disclosure) proof with the provided challenge.
func (d *DisclosureProofBuilder) CreateProof(challenge *big.Int) Proof {
	ePrime := new(big.Int).Sub(d.randomizedSignature.E, new(big.Int).Lsh(big.NewInt(1), d.pk.Params.Le-1))
	eResponse := new(big.Int).Mul(challenge, ePrime)
	eResponse.Add(d.eCommit, eResponse)
	vResponse := new(big.Int).Mul(challenge, d.randomizedSignature.V)
	vResponse.Add(d.vCommit, vResponse)

	aResponses := make(map[int]*big.Int)
	for _, v := range d.undisclosedAttributes {
		exp := d.attributes[v]
		if exp.BitLen() > int(d.pk.Params.Lm) {
			exp = common.IntHashSha256(exp.Bytes())
		}
		t := new(big.Int).Mul(challenge, exp)
		aResponses[v] = t.Add(d.attrRandomizers[v], t)
	}

	aDisclosed := make(map[int]*big.Int)
	for _, v := range d.disclosedAttributes {
		aDisclosed[v] = d.attributes[v]
	}

	return &ProofD{C: challenge, A: d.randomizedSignature.A, EResponse: eResponse, VResponse: vResponse, AResponses: aResponses, ADisclosed: aDisclosed}
}

// TimestampRequestContributions returns the contributions of this disclosure proof
// to the message that is to be signed by the timestamp server:
// - A of the randomized CL-signature
// - Slice of bigints populated with the disclosed attributes and 0 for the undisclosed ones.
func (d *DisclosureProofBuilder) TimestampRequestContributions() (*big.Int, []*big.Int) {
	zero := big.NewInt(0)
	disclosed := make([]*big.Int, len(d.attributes))
	for i := 0; i < len(d.attributes); i++ {
		disclosed[i] = zero
	}
	for _, i := range d.disclosedAttributes {
		disclosed[i] = d.attributes[i]
	}
	return d.randomizedSignature.A, disclosed
}

// Generate secret attribute used prove ownership and links between credentials from the same user.
func GenerateSecretAttribute() (*big.Int, error) {
	return common.RandomBigInt(DefaultSystemParameters[1024].Lm)
}
