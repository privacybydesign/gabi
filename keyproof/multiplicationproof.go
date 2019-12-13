package keyproof

import (
	"strings"

	"github.com/privacybydesign/gabi/big"
)

type multiplicationProofStructure struct {
	m1                 string
	m2                 string
	mod                string
	result             string
	myname             string
	modMultPedersen    pedersenStructure
	modMultRange       rangeProofStructure
	multRepresentation representationProofStructure
}

type MultiplicationProof struct {
	ModMultProof PedersenProof
	Hider        Proof
	RangeProof   RangeProof
}

type multiplicationProofCommit struct {
	modMultPedersen pedersenCommit
	hider           secret
	rangeCommit     rangeCommit
}

// Note, m1, m2, mod and result should be names of pedersen commitments
func newMultiplicationProofStructure(m1, m2, mod, result string, l uint) multiplicationProofStructure {
	var structure multiplicationProofStructure
	structure.m1 = m1
	structure.m2 = m2
	structure.mod = mod
	structure.result = result
	structure.myname = strings.Join([]string{m1, m2, mod, result, "mul"}, "_")
	structure.multRepresentation = representationProofStructure{
		[]lhsContribution{
			{result, big.NewInt(1)},
		},
		[]rhsContribution{
			{m2, m1, 1},
			{mod, strings.Join([]string{structure.myname, "mod"}, "_"), -1},
			{"h", strings.Join([]string{structure.myname, "hider"}, "_"), 1},
		},
	}
	structure.modMultPedersen = newPedersenStructure(strings.Join([]string{structure.myname, "mod"}, "_"))
	structure.modMultRange = newPedersenRangeProofStructure(strings.Join([]string{structure.myname, "mod"}, "_"), 0, l)
	return structure
}

func (s *multiplicationProofStructure) generateCommitmentsFromSecrets(g group, list []*big.Int, bases baseLookup, secretdata secretLookup) ([]*big.Int, multiplicationProofCommit) {
	var commit multiplicationProofCommit

	// Generate the neccesary commit data for our parts of the proof
	list, commit.modMultPedersen = s.modMultPedersen.generateCommitmentsFromSecrets(g, list, new(big.Int).Div(
		new(big.Int).Sub(
			new(big.Int).Mul(
				secretdata.getSecret(s.m1),
				secretdata.getSecret(s.m2)),
			secretdata.getSecret(s.result)),
		secretdata.getSecret(s.mod)))
	commit.hider = newSecret(g, strings.Join([]string{s.myname, "hider"}, "_"), new(big.Int).Mod(
		new(big.Int).Add(
			new(big.Int).Sub(
				secretdata.getSecret(strings.Join([]string{s.result, "hider"}, "_")),
				new(big.Int).Mul(
					secretdata.getSecret(s.m1),
					secretdata.getSecret(strings.Join([]string{s.m2, "hider"}, "_")))),
			new(big.Int).Mul(
				commit.modMultPedersen.secret.secret,
				secretdata.getSecret(strings.Join([]string{s.mod, "hider"}, "_")))),
		g.order))

	// Build inner secrets
	secrets := newSecretMerge(&commit.hider, &commit.modMultPedersen, secretdata)

	// Generate commitments for the two main proofs (pedersen was handled above when generating its commit)
	list = s.multRepresentation.generateCommitmentsFromSecrets(g, list, bases, &secrets)
	list, commit.rangeCommit = s.modMultRange.generateCommitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *multiplicationProofStructure) buildProof(g group, challenge *big.Int, commit multiplicationProofCommit, secretdata secretLookup) MultiplicationProof {
	var proof MultiplicationProof

	// Generate the proofs
	rangeSecrets := newSecretMerge(&commit.hider, &commit.modMultPedersen, secretdata)
	proof.RangeProof = s.modMultRange.buildProof(g, challenge, commit.rangeCommit, &rangeSecrets)
	proof.ModMultProof = s.modMultPedersen.buildProof(g, challenge, commit.modMultPedersen)
	proof.Hider = commit.hider.buildProof(g, challenge)

	return proof
}

func (s *multiplicationProofStructure) fakeProof(g group) MultiplicationProof {
	var proof MultiplicationProof
	proof.RangeProof = s.modMultRange.fakeProof(g)
	proof.ModMultProof = s.modMultPedersen.fakeProof(g)
	proof.Hider = fakeProof(g)
	return proof
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

func (s *multiplicationProofStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases baseLookup, proofdata proofLookup, proof MultiplicationProof) []*big.Int {
	// Build inner proof lookup
	proof.ModMultProof.setName(strings.Join([]string{s.myname, "mod"}, "_"))
	proof.Hider.setName(strings.Join([]string{s.myname, "hider"}, "_"))
	proofs := newProofMerge(&proof.Hider, &proof.ModMultProof, proofdata)
	innerBases := newBaseMerge(&proof.ModMultProof, bases)

	// And regenerate the commitments
	list = s.modMultPedersen.generateCommitmentsFromProof(g, list, challenge, proof.ModMultProof)
	list = s.multRepresentation.generateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.modMultRange.generateCommitmentsFromProof(g, list, challenge, &innerBases, proof.RangeProof)

	return list
}

func (s *multiplicationProofStructure) isTrue(secretdata secretLookup) bool {
	div := new(big.Int)
	mod := new(big.Int)

	div.DivMod(
		new(big.Int).Sub(
			new(big.Int).Mul(
				secretdata.getSecret(s.m1),
				secretdata.getSecret(s.m2)),
			secretdata.getSecret(s.result)),
		secretdata.getSecret(s.mod),
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
