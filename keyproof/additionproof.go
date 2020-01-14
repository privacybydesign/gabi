package keyproof

import (
	"strings"

	"github.com/privacybydesign/gabi/big"
)

type (
	additionProofStructure struct {
		a1                string
		a2                string
		mod               string
		result            string
		myname            string
		addRepresentation representationProofStructure
		addRange          rangeProofStructure
	}

	AdditionProof struct {
		ModAddProof Proof
		HiderProof  Proof
		RangeProof  RangeProof
	}

	additionProofCommit struct {
		modAdd      secret
		hider       secret
		rangeCommit rangeCommit
	}
)

func newAdditionProofStructure(a1, a2, mod, result string, l uint) additionProofStructure {
	structure := additionProofStructure{
		a1:     a1,
		a2:     a2,
		mod:    mod,
		result: result,
		myname: strings.Join([]string{a1, a2, mod, result, "add"}, "_"),
	}
	structure.addRepresentation = representationProofStructure{
		[]lhsContribution{
			{result, big.NewInt(1)},
			{a1, big.NewInt(-1)},
			{a2, big.NewInt(-1)},
		},
		[]rhsContribution{
			{mod, strings.Join([]string{structure.myname, "mod"}, "_"), 1},
			{"h", strings.Join([]string{structure.myname, "hider"}, "_"), 1},
		},
	}
	structure.addRange = rangeProofStructure{
		structure.addRepresentation,
		strings.Join([]string{structure.myname, "mod"}, "_"),
		0,
		l,
	}
	return structure
}

func (s *additionProofStructure) commitmentsFromSecrets(g group, list []*big.Int, bases baseLookup, secretdata secretLookup) ([]*big.Int, additionProofCommit) {
	var commit additionProofCommit

	// Generate needed commit data
	commit.modAdd = newSecret(g, strings.Join([]string{s.myname, "mod"}, "_"),
		new(big.Int).Div(
			new(big.Int).Sub(
				secretdata.secret(s.result),
				new(big.Int).Add(
					secretdata.secret(s.a1),
					secretdata.secret(s.a2))),
			secretdata.secret(s.mod)))
	commit.hider = newSecret(g, strings.Join([]string{s.myname, "hider"}, "_"),
		new(big.Int).Mod(
			new(big.Int).Sub(
				secretdata.secret(strings.Join([]string{s.result, "hider"}, "_")),
				new(big.Int).Add(
					new(big.Int).Add(
						secretdata.secret(strings.Join([]string{s.a1, "hider"}, "_")),
						secretdata.secret(strings.Join([]string{s.a2, "hider"}, "_"))),
					new(big.Int).Mul(
						secretdata.secret(strings.Join([]string{s.mod, "hider"}, "_")),
						commit.modAdd.secretv))),
			g.order))

	// build inner secrets
	secrets := newSecretMerge(&commit.hider, &commit.modAdd, secretdata)

	// and build commits
	list = s.addRepresentation.commitmentsFromSecrets(g, list, bases, &secrets)
	list, commit.rangeCommit = s.addRange.commitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *additionProofStructure) buildProof(g group, challenge *big.Int, commit additionProofCommit, secretdata secretLookup) AdditionProof {
	rangeSecrets := newSecretMerge(&commit.hider, &commit.modAdd, secretdata)
	return AdditionProof{
		RangeProof:  s.addRange.buildProof(g, challenge, commit.rangeCommit, &rangeSecrets),
		ModAddProof: commit.modAdd.buildProof(g, challenge),
		HiderProof:  commit.hider.buildProof(g, challenge),
	}
}

func (s *additionProofStructure) fakeProof(g group) AdditionProof {
	return AdditionProof{
		RangeProof:  s.addRange.fakeProof(g),
		ModAddProof: fakeProof(g),
		HiderProof:  fakeProof(g),
	}
}

func (s *additionProofStructure) verifyProofStructure(proof AdditionProof) bool {
	if !s.addRange.verifyProofStructure(proof.RangeProof) {
		return false
	}
	if !proof.HiderProof.verifyStructure() || !proof.ModAddProof.verifyStructure() {
		return false
	}
	return true
}

func (s *additionProofStructure) commitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases baseLookup, proofdata proofLookup, proof AdditionProof) []*big.Int {
	// build inner proof lookup
	proof.ModAddProof.setName(strings.Join([]string{s.myname, "mod"}, "_"))
	proof.HiderProof.setName(strings.Join([]string{s.myname, "hider"}, "_"))
	proofs := newProofMerge(&proof.HiderProof, &proof.ModAddProof, proofdata)

	// build commitments
	list = s.addRepresentation.commitmentsFromProof(g, list, challenge, bases, &proofs)
	list = s.addRange.commitmentsFromProof(g, list, challenge, bases, proof.RangeProof)

	return list
}

func (s *additionProofStructure) isTrue(secretdata secretLookup) bool {
	div := new(big.Int)
	mod := new(big.Int)

	div.DivMod(
		new(big.Int).Sub(
			secretdata.secret(s.result),
			new(big.Int).Add(
				secretdata.secret(s.a1),
				secretdata.secret(s.a2))),
		secretdata.secret(s.mod),
		mod)

	return mod.Cmp(big.NewInt(0)) == 0 && uint(div.BitLen()) <= s.addRange.l2
}

func (s *additionProofStructure) numRangeProofs() int {
	return 1
}

func (s *additionProofStructure) numCommitments() int {
	return s.addRepresentation.numCommitments() + s.addRange.numCommitments()
}
