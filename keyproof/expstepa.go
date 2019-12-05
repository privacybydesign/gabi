package keyproof

import (
	"strings"

	"github.com/privacybydesign/gabi/big"
)

type expStepAStructure struct {
	bitname     string
	prename     string
	postname    string
	myname      string
	bitRep      representationProofStructure
	equalityRep representationProofStructure
}

type ExpStepAProof struct {
	Bit           Proof // Needed to make sure we can fake these proofs, which is needed for the OR in expstep
	EqualityHider Proof
}

type expStepACommit struct {
	bit           secret // Needed to make sure we can fake these proofs, which is needed for the OR in expstep
	equalityHider secret
}

func newExpStepAStructure(bitname, prename, postname string) expStepAStructure {
	var structure expStepAStructure
	structure.bitname = bitname
	structure.prename = prename
	structure.postname = postname
	structure.myname = strings.Join([]string{bitname, prename, postname, "expa"}, "_")
	structure.bitRep = representationProofStructure{
		[]lhsContribution{
			lhsContribution{bitname, big.NewInt(1)},
		},
		[]rhsContribution{
			rhsContribution{"h", strings.Join([]string{bitname, "hider"}, "_"), 1},
		},
	}
	structure.equalityRep = representationProofStructure{
		[]lhsContribution{
			lhsContribution{prename, big.NewInt(1)},
			lhsContribution{postname, big.NewInt(-1)},
		},
		[]rhsContribution{
			rhsContribution{"h", strings.Join([]string{structure.myname, "eqhider"}, "_"), 1},
		},
	}
	return structure
}

func (s *expStepAStructure) numRangeProofs() int {
	return 0
}

func (s *expStepAStructure) numCommitments() int {
	return s.bitRep.numCommitments() + s.equalityRep.numCommitments()
}

func (s *expStepAStructure) generateCommitmentsFromSecrets(g group, list []*big.Int, bases baseLookup, secretdata secretLookup) ([]*big.Int, expStepACommit) {
	var commit expStepACommit

	// Build commit structure
	commit.bit = newSecret(g, strings.Join([]string{s.bitname, "hider"}, "_"), secretdata.getSecret(strings.Join([]string{s.bitname, "hider"}, "_")))
	commit.equalityHider = newSecret(g, strings.Join([]string{s.myname, "eqhider"}, "_"), new(big.Int).Mod(
		new(big.Int).Sub(
			secretdata.getSecret(strings.Join([]string{s.prename, "hider"}, "_")),
			secretdata.getSecret(strings.Join([]string{s.postname, "hider"}, "_"))),
		g.order))

	// inner secrets
	secrets := newSecretMerge(&commit.bit, &commit.equalityHider, secretdata)

	// Generate commitments
	list = s.bitRep.generateCommitmentsFromSecrets(g, list, bases, &secrets)
	list = s.equalityRep.generateCommitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *expStepAStructure) buildProof(g group, challenge *big.Int, commit expStepACommit, secretdata secretLookup) ExpStepAProof {
	var proof ExpStepAProof

	// Build our results
	proof.Bit = commit.bit.buildProof(g, challenge)
	proof.EqualityHider = commit.equalityHider.buildProof(g, challenge)

	return proof
}

func (s *expStepAStructure) fakeProof(g group) ExpStepAProof {
	var proof ExpStepAProof

	proof.Bit = fakeProof(g)
	proof.EqualityHider = fakeProof(g)

	return proof
}

func (s *expStepAStructure) verifyProofStructure(proof ExpStepAProof) bool {
	return proof.Bit.verifyStructure() && proof.EqualityHider.verifyStructure()
}

func (s *expStepAStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases baseLookup, proof ExpStepAProof) []*big.Int {
	// inner proof data
	proof.Bit.setName(strings.Join([]string{s.bitname, "hider"}, "_"))
	proof.EqualityHider.setName(strings.Join([]string{s.myname, "eqhider"}, "_"))
	proofMerge := newProofMerge(&proof.Bit, &proof.EqualityHider)

	// Generate commitments
	list = s.bitRep.generateCommitmentsFromProof(g, list, challenge, bases, &proofMerge)
	list = s.equalityRep.generateCommitmentsFromProof(g, list, challenge, bases, &proofMerge)

	return list
}

func (s *expStepAStructure) isTrue(secretdata secretLookup) bool {
	if secretdata.getSecret(s.bitname).Cmp(big.NewInt(0)) != 0 {
		return false
	}
	if secretdata.getSecret(s.prename).Cmp(secretdata.getSecret(s.postname)) != 0 {
		return false
	}
	return true
}
