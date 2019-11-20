// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/revocation"
)

// Credential represents an Idemix credential.
type Credential struct {
	Signature            *CLSignature        `json:"signature"`
	Pk                   *PublicKey          `json:"-"`
	Attributes           []*big.Int          `json:"attributes"`
	NonRevocationWitness *revocation.Witness `json:"nonrevWitness,omitempty"`

	nonrevCache chan *NonRevocationProofBuilder
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

	nonrevAttr, nonrevRandomizer *big.Int
	nonrevBuilder                *NonRevocationProofBuilder
}

type NonRevocationProofBuilder struct {
	pk          *PublicKey
	witness     *revocation.Witness
	commit      *revocation.ProofCommit
	commitments []*big.Int
	randomizer  *big.Int
	index       uint64
}

// UpdateCommit updates the builder to the latest accumulator contained in the specified (updated) witness.
func (b *NonRevocationProofBuilder) UpdateCommit(witness *revocation.Witness) error {
	if b == nil || b.commit == nil || len(b.commitments) < 5 {
		return errors.New("cannot update noninitialized NonRevocationProofBuilder")
	}
	if b.index >= witness.Accumulator.Index {
		return nil
	}
	b.witness = witness
	b.commit.Update(b.commitments, witness)
	return nil
}

func (b *NonRevocationProofBuilder) Commit() ([]*big.Int, error) {
	if b.commitments == nil {
		revPk, err := b.pk.RevocationKey()
		if err != nil {
			return nil, err
		}
		b.commitments, b.commit, err = revocation.NewProofCommit(revPk.Group, b.witness, b.randomizer)
		if err != nil {
			return nil, err
		}
	}
	return b.commitments, nil
}

func (b *NonRevocationProofBuilder) CreateProof(challenge *big.Int) *revocation.Proof {
	return b.commit.BuildProof(challenge)
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
func (ic *Credential) CreateDisclosureProofBuilder(disclosedAttributes []int, nonrev bool) (*DisclosureProofBuilder, error) {
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

	if nonrev && ic.NonRevocationWitness == nil {
		return nil, errors.New("cannot prove nonrevocation: credential has no witness")
	}
	if ic.NonRevocationWitness != nil {
		// Even if the requestor did not request a nonrevocation proof, it will require
		// a proof of knowledge of the nonrevocation attribute e to be included in the
		// ProofD, in order to be able to verify it. (This breaks backwards compatibility
		// with pre-revocation requestors)
		if nonrev {
			var err error
			d.nonrevBuilder, err = ic.nonrevConsumeBuilder()
			if err != nil {
				return nil, err
			}
			d.nonrevRandomizer = d.nonrevBuilder.randomizer
		} else {
			d.nonrevRandomizer = revocation.NewProofRandomizer()
		}
		d.nonrevAttr = ic.NonRevocationWitness.E
	}

	return d, nil
}

func (ic *Credential) nonrevConsumeBuilder() (*NonRevocationProofBuilder, error) {
	// Using either the channel value or a new one ensures that our output is used at most once,
	// lest we totally break security: reusing randomizers in a second session makes it possible
	// for the verifier to compute our revocation witness e from the proofs
	select {
	case b := <-ic.nonrevCache:
		return b, b.UpdateCommit(ic.NonRevocationWitness)
	default:
		return ic.NonrevBuildProofBuilder()
	}
}

// NonrevPrepareCache ensures that the Credential's nonrevocation proof builder cache is
// usable, by creating one if it does not exist, or otherwise updating it to the latest accumulator
// contained in the credential's witness.
func (ic *Credential) NonrevPrepareCache() error {
	if ic.NonRevocationWitness == nil {
		return nil
	}
	if ic.nonrevCache == nil {
		ic.nonrevCache = make(chan *NonRevocationProofBuilder, 1)
	}
	var b *NonRevocationProofBuilder
	var err error
	select {
	case b = <-ic.nonrevCache:
		err = b.UpdateCommit(ic.NonRevocationWitness)
	default:
		b, err = ic.NonrevBuildProofBuilder()
	}
	if err != nil {
		return err
	}

	// put it back in the channel, waiting to be consumed by nonrevConsumeBuilder()
	// if the channel has already been populated by another goroutine in the meantime we just discard
	select {
	case ic.nonrevCache <- b:
	default:
	}

	return err
}

// NonrevBuildProofBuilder builds and returns a new commited-to NonRevocationProofBuilder.
func (ic *Credential) NonrevBuildProofBuilder() (*NonRevocationProofBuilder, error) {
	if ic.NonRevocationWitness == nil {
		return nil, errors.New("credential has no nonrevocation witness")
	}
	b := &NonRevocationProofBuilder{
		pk:         ic.Pk,
		witness:    ic.NonRevocationWitness,
		index:      ic.NonRevocationWitness.Accumulator.Index,
		randomizer: revocation.NewProofRandomizer(),
	}
	_, err := b.Commit()
	if err != nil {
		return nil, err
	}
	return b, nil
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
	if d.nonrevAttr != nil {
		d.z.Mul(d.z, common.ModPow(d.pk.T, d.nonrevRandomizer, d.pk.N)).Mod(d.z, d.pk.N)
	}

	list := []*big.Int{d.randomizedSignature.A, d.z}

	if d.nonrevBuilder != nil {
		l, err := d.nonrevBuilder.Commit()
		if err != nil {
			panic(err)
		}
		list = append(list, l...)
	}
	return list
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

	var nonrevProof *revocation.Proof
	var nrResponse *big.Int
	if d.nonrevAttr != nil && d.nonrevRandomizer != nil {
		nrResponse = new(big.Int).Add(d.nonrevRandomizer, new(big.Int).Mul(challenge, d.nonrevAttr))
	}
	if d.nonrevBuilder != nil {
		nonrevProof = d.nonrevBuilder.CreateProof(challenge)
	}

	return &ProofD{
		C:                     challenge,
		A:                     d.randomizedSignature.A,
		EResponse:             eResponse,
		VResponse:             vResponse,
		AResponses:            aResponses,
		ADisclosed:            aDisclosed,
		NonRevocationResponse: nrResponse,
		NonRevocationProof:    nonrevProof,
	}
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
