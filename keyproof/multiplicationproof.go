package keyproof

import (
	"strings"

	"github.com/privacybydesign/gabi/big"
)

type (
	multiplicationProofStructure struct {
		m1                 string
		m2                 string
		mod                string
		result             string
		myname             string
		modMultPedersen    pedersenStructure
		modMultRange       rangeProofStructure
		multRepresentation RepresentationProofStructure
	}

	MultiplicationProof struct {
		ModMultProof PedersenProof
		Hider        Proof
		RangeProof   RangeProof
	}

	multiplicationProofCommit struct {
		modMultPedersen pedersenCommit
		hider           secret
		rangeCommit     rangeCommit
	}
)

// Note, m1, m2, mod and result should be names of pedersen commitments
func newMultiplicationProofStructure(m1, m2, mod, result string, l uint) multiplicationProofStructure {
	structure := multiplicationProofStructure{
		m1:     m1,
		m2:     m2,
		mod:    mod,
		result: result,
		myname: strings.Join([]string{m1, m2, mod, result, "mul"}, "_"),
	}
	structure.multRepresentation = RepresentationProofStructure{
		[]LhsContribution{
			{result, big.NewInt(1)},
		},
		[]RhsContribution{
			{m2, m1, 1},
			{mod, strings.Join([]string{structure.myname, "mod"}, "_"), -1},
			{"h", strings.Join([]string{structure.myname, "hider"}, "_"), 1},
		},
	}
	structure.modMultPedersen = newPedersenStructure(strings.Join([]string{structure.myname, "mod"}, "_"))
	structure.modMultRange = newPedersenRangeProofStructure(strings.Join([]string{structure.myname, "mod"}, "_"), 0, l)
	return structure
}

func (s *multiplicationProofStructure) commitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) ([]*big.Int, multiplicationProofCommit) {
	var commit multiplicationProofCommit

	// Generate the neccesary commit data for our parts of the proof
	list, commit.modMultPedersen = s.modMultPedersen.commitmentsFromSecrets(g, list, new(big.Int).Div(
		new(big.Int).Sub(
			new(big.Int).Mul(
				secretdata.Secret(s.m1),
				secretdata.Secret(s.m2)),
			secretdata.Secret(s.result)),
		secretdata.Secret(s.mod)))
	commit.hider = newSecret(g, strings.Join([]string{s.myname, "hider"}, "_"), new(big.Int).Mod(
		new(big.Int).Add(
			new(big.Int).Sub(
				secretdata.Secret(strings.Join([]string{s.result, "hider"}, "_")),
				new(big.Int).Mul(
					secretdata.Secret(s.m1),
					secretdata.Secret(strings.Join([]string{s.m2, "hider"}, "_")))),
			new(big.Int).Mul(
				commit.modMultPedersen.secretv.secretv,
				secretdata.Secret(strings.Join([]string{s.mod, "hider"}, "_")))),
		g.order))

	// Build inner secrets
	secrets := NewSecretMerge(&commit.hider, &commit.modMultPedersen, secretdata)

	// Generate commitments for the two main proofs (pedersen was handled above when generating its commit)
	list = s.multRepresentation.commitmentsFromSecrets(g, list, bases, &secrets)
	list, commit.rangeCommit = s.modMultRange.commitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *multiplicationProofStructure) buildProof(g group, challenge *big.Int, commit multiplicationProofCommit, secretdata SecretLookup) MultiplicationProof {
	// Generate the proofs
	rangeSecrets := NewSecretMerge(&commit.hider, &commit.modMultPedersen, secretdata)
	return MultiplicationProof{
		RangeProof:   s.modMultRange.buildProof(g, challenge, commit.rangeCommit, &rangeSecrets),
		ModMultProof: s.modMultPedersen.buildProof(g, challenge, commit.modMultPedersen),
		Hider:        commit.hider.buildProof(g, challenge),
	}
}

func (s *multiplicationProofStructure) fakeProof(g group) MultiplicationProof {
	return MultiplicationProof{
		RangeProof:   s.modMultRange.fakeProof(g),
		ModMultProof: s.modMultPedersen.fakeProof(g),
		Hider:        fakeProof(g),
	}
}

func (s *multiplicationProofStructure) verifyProofStructure(proof MultiplicationProof) bool {
	if !s.modMultRange.verifyProofStructure(proof.RangeProof) {
		return false
	}
	if !s.modMultPedersen.verifyProofStructure(proof.ModMultProof) {
		return false
	}
	if !proof.Hider.verifyStructure() {
		return false
	}
	return true
}

func (s *multiplicationProofStructure) commitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proofdata ProofLookup, proof MultiplicationProof) []*big.Int {
	// Build inner proof lookup
	proof.ModMultProof.setName(strings.Join([]string{s.myname, "mod"}, "_"))
	proof.Hider.setName(strings.Join([]string{s.myname, "hider"}, "_"))
	proofs := NewProofMerge(&proof.Hider, &proof.ModMultProof, proofdata)
	innerBases := NewBaseMerge(&proof.ModMultProof, bases)

	// And regenerate the commitments
	list = s.modMultPedersen.commitmentsFromProof(g, list, challenge, proof.ModMultProof)
	list = s.multRepresentation.commitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.modMultRange.commitmentsFromProof(g, list, challenge, &innerBases, proof.RangeProof)

	return list
}

func (s *multiplicationProofStructure) isTrue(secretdata SecretLookup) bool {
	div := new(big.Int)
	mod := new(big.Int)

	div.DivMod(
		new(big.Int).Sub(
			new(big.Int).Mul(
				secretdata.Secret(s.m1),
				secretdata.Secret(s.m2)),
			secretdata.Secret(s.result)),
		secretdata.Secret(s.mod),
		mod)

	return mod.Cmp(big.NewInt(0)) == 0 && uint(div.BitLen()) <= s.modMultRange.l2
}

func (s *multiplicationProofStructure) numRangeProofs() int {
	return 1
}

func (s *multiplicationProofStructure) numCommitments() int {
	return s.multRepresentation.numCommitments() +
		s.modMultPedersen.numCommitments() +
		s.modMultRange.numCommitments()
}
