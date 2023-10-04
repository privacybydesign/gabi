package keyproof

import (
	"strings"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/zkproof"
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
		multRepresentation zkproof.RepresentationProofStructure
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
	structure.multRepresentation = zkproof.RepresentationProofStructure{
		Lhs: []zkproof.LhsContribution{
			{Base: result, Power: big.NewInt(1)},
		},
		Rhs: []zkproof.RhsContribution{
			{Base: m2, Secret: m1, Power: 1},
			{Base: mod, Secret: strings.Join([]string{structure.myname, "mod"}, "_"), Power: -1},
			{Base: "h", Secret: strings.Join([]string{structure.myname, "hider"}, "_"), Power: 1},
		},
	}
	structure.modMultPedersen = newPedersenStructure(strings.Join([]string{structure.myname, "mod"}, "_"))
	structure.modMultRange = newPedersenRangeProofStructure(strings.Join([]string{structure.myname, "mod"}, "_"), 0, l)
	return structure
}

func (s *multiplicationProofStructure) commitmentsFromSecrets(g zkproof.Group, list []*big.Int, bases zkproof.BaseLookup, secretdata zkproof.SecretLookup) ([]*big.Int, multiplicationProofCommit) {
	var commit multiplicationProofCommit

	// Generate the necessary commit data for our parts of the proof
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
		g.Order))

	// Build inner secrets
	secrets := zkproof.NewSecretMerge(&commit.hider, &commit.modMultPedersen, secretdata)

	// Generate commitments for the two main proofs (pedersen was handled above when generating its commit)
	list = s.multRepresentation.CommitmentsFromSecrets(g, list, bases, &secrets)
	list, commit.rangeCommit = s.modMultRange.commitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *multiplicationProofStructure) buildProof(g zkproof.Group, challenge *big.Int, commit multiplicationProofCommit, secretdata zkproof.SecretLookup) MultiplicationProof {
	// Generate the proofs
	rangeSecrets := zkproof.NewSecretMerge(&commit.hider, &commit.modMultPedersen, secretdata)
	return MultiplicationProof{
		RangeProof:   s.modMultRange.buildProof(g, challenge, commit.rangeCommit, &rangeSecrets),
		ModMultProof: s.modMultPedersen.buildProof(g, challenge, commit.modMultPedersen),
		Hider:        commit.hider.buildProof(g, challenge),
	}
}

func (s *multiplicationProofStructure) fakeProof(g zkproof.Group) MultiplicationProof {
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

func (s *multiplicationProofStructure) commitmentsFromProof(g zkproof.Group, list []*big.Int, challenge *big.Int, bases zkproof.BaseLookup, proofdata zkproof.ProofLookup, proof MultiplicationProof) []*big.Int {
	// Build inner proof lookup
	proof.ModMultProof.setName(strings.Join([]string{s.myname, "mod"}, "_"))
	proof.Hider.setName(strings.Join([]string{s.myname, "hider"}, "_"))
	proofs := zkproof.NewProofMerge(&proof.Hider, &proof.ModMultProof, proofdata)
	innerBases := zkproof.NewBaseMerge(&proof.ModMultProof, bases)

	// And regenerate the commitments
	list = s.modMultPedersen.commitmentsFromProof(g, list, challenge, proof.ModMultProof)
	list = s.multRepresentation.CommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.modMultRange.commitmentsFromProof(g, list, challenge, &innerBases, proof.RangeProof)

	return list
}

func (s *multiplicationProofStructure) isTrue(secretdata zkproof.SecretLookup) bool {
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
	return s.multRepresentation.NumCommitments() +
		s.modMultPedersen.numCommitments() +
		s.modMultRange.numCommitments()
}
