// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"math/big"
)

// Credential represents an Idemix credential.
type Credential struct {
	Signature  *CLSignature
	Pk         *PublicKey
	Attributes []*big.Int
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

	eCommit, _ := randomBigInt(ic.Pk.Params.LeCommit)
	vCommit, _ := randomBigInt(ic.Pk.Params.LvCommit)

	aCommits := make(map[int]*big.Int)
	for _, v := range undisclosedAttributes {
		aCommits[v], _ = randomBigInt(ic.Pk.Params.LmCommit)
	}

	// Z = A^{e_commit} * S^{v_commit}
	//     PROD_{i \in undisclosed} ( R_i^{a_commits{i}} )
	Ae := modPow(randSig.A, eCommit, ic.Pk.N)
	Sv := modPow(ic.Pk.S, vCommit, ic.Pk.N)
	Z := new(big.Int).Mul(Ae, Sv)
	Z.Mod(Z, ic.Pk.N)

	for _, v := range undisclosedAttributes {
		Z.Mul(Z, modPow(ic.Pk.R[v], aCommits[v], ic.Pk.N))
		Z.Mod(Z, ic.Pk.N)
	}

	c := hashCommit([]*big.Int{context, randSig.A, Z, nonce1})

	ePrime := new(big.Int).Sub(randSig.E, new(big.Int).Lsh(bigONE, ic.Pk.Params.Le-1))
	eResponse := new(big.Int).Mul(c, ePrime)
	eResponse.Add(eCommit, eResponse)
	vResponse := new(big.Int).Mul(c, randSig.V)
	vResponse.Add(vCommit, vResponse)

	aResponses := make(map[int]*big.Int)
	for _, v := range undisclosedAttributes {
		t := new(big.Int).Mul(c, ic.Attributes[v])
		aResponses[v] = t.Add(aCommits[v], t)
	}

	aDisclosed := make(map[int]*big.Int)
	for _, v := range disclosedAttributes {
		aDisclosed[v] = ic.Attributes[v]
	}

	return &ProofD{c: c, A: randSig.A, eResponse: eResponse, vResponse: vResponse, aResponses: aResponses, aDisclosed: aDisclosed}
}

// CreateDisclosureProofBuilder produces a DisclosureProofBuilder, an object to
// hold the state in the protocol for producing a disclosure proof that is
// linked to other proofs.
func (ic *Credential) CreateDisclosureProofBuilder(disclosedAttributes []int) *DisclosureProofBuilder {
	d := &DisclosureProofBuilder{}
	d.pk = ic.Pk
	d.randomizedSignature = ic.Signature.Randomize(ic.Pk)
	d.eCommit, _ = randomBigInt(ic.Pk.Params.LeCommit)
	d.vCommit, _ = randomBigInt(ic.Pk.Params.LvCommit)

	d.attrRandomizers = make(map[int]*big.Int)
	d.disclosedAttributes = disclosedAttributes
	d.undisclosedAttributes = getUndisclosedAttributes(disclosedAttributes, len(ic.Attributes))
	d.attributes = ic.Attributes
	for _, v := range d.undisclosedAttributes {
		d.attrRandomizers[v], _ = randomBigInt(ic.Pk.Params.LmCommit)
	}

	return d
}

// TODO: Eventually replace skRandomizer with an array

// Commit commits to the first attribute (the secret) using the provided
// randomizer.
func (d *DisclosureProofBuilder) Commit(skRandomizer *big.Int) []*big.Int {
	d.attrRandomizers[0] = skRandomizer

	// Z = A^{e_commit} * S^{v_commit}
	//     PROD_{i \in undisclosed} ( R_i^{a_commits{i}} )
	Ae := modPow(d.randomizedSignature.A, d.eCommit, d.pk.N)
	Sv := modPow(d.pk.S, d.vCommit, d.pk.N)
	d.z = new(big.Int).Mul(Ae, Sv)
	d.z.Mod(d.z, d.pk.N)

	for _, v := range d.undisclosedAttributes {
		d.z.Mul(d.z, modPow(d.pk.R[v], d.attrRandomizers[v], d.pk.N))
		d.z.Mod(d.z, d.pk.N)
	}

	return []*big.Int{d.randomizedSignature.A, d.z}
}

// CreateProof creates a (disclosure) proof with the provided challenge.
func (d *DisclosureProofBuilder) CreateProof(challenge *big.Int) Proof {
	ePrime := new(big.Int).Sub(d.randomizedSignature.E, new(big.Int).Lsh(bigONE, d.pk.Params.Le-1))
	eResponse := new(big.Int).Mul(challenge, ePrime)
	eResponse.Add(d.eCommit, eResponse)
	vResponse := new(big.Int).Mul(challenge, d.randomizedSignature.V)
	vResponse.Add(d.vCommit, vResponse)

	aResponses := make(map[int]*big.Int)
	for _, v := range d.undisclosedAttributes {
		t := new(big.Int).Mul(challenge, d.attributes[v])
		aResponses[v] = t.Add(d.attrRandomizers[v], t)
	}

	aDisclosed := make(map[int]*big.Int)
	for _, v := range d.disclosedAttributes {
		aDisclosed[v] = d.attributes[v]
	}

	return &ProofD{c: challenge, A: d.randomizedSignature.A, eResponse: eResponse, vResponse: vResponse, aResponses: aResponses, aDisclosed: aDisclosed}
}
