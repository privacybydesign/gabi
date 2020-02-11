package keyproof

import (
	"strings"

	"github.com/privacybydesign/gabi/big"
)

type (
	expStepAStructure struct {
		bitname     string
		prename     string
		postname    string
		myname      string
		bitRep      RepresentationProofStructure
		equalityRep RepresentationProofStructure
	}

	ExpStepAProof struct {
		Bit           Proof // Needed to make sure we can fake these proofs, which is needed for the OR in expstep
		EqualityHider Proof
	}

	expStepACommit struct {
		bit           secret // Needed to make sure we can fake these proofs, which is needed for the OR in expstep
		equalityHider secret
	}
)

func newExpStepAStructure(bitname, prename, postname string) expStepAStructure {
	structure := expStepAStructure{
		bitname:  bitname,
		prename:  prename,
		postname: postname,
		myname:   strings.Join([]string{bitname, prename, postname, "expa"}, "_"),
	}
	structure.bitRep = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{bitname, big.NewInt(1)},
		},
		[]RhsContribution{
			RhsContribution{"h", strings.Join([]string{bitname, "hider"}, "_"), 1},
		},
	}
	structure.equalityRep = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{prename, big.NewInt(1)},
			LhsContribution{postname, big.NewInt(-1)},
		},
		[]RhsContribution{
			RhsContribution{"h", strings.Join([]string{structure.myname, "eqhider"}, "_"), 1},
		},
	}
	return structure
}

func (s *expStepAStructure) commitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) ([]*big.Int, expStepACommit) {
	var commit expStepACommit

	// Build commit structure
	commit.bit = newSecret(g, strings.Join([]string{s.bitname, "hider"}, "_"), secretdata.Secret(strings.Join([]string{s.bitname, "hider"}, "_")))
	commit.equalityHider = newSecret(g, strings.Join([]string{s.myname, "eqhider"}, "_"), new(big.Int).Mod(
		new(big.Int).Sub(
			secretdata.Secret(strings.Join([]string{s.prename, "hider"}, "_")),
			secretdata.Secret(strings.Join([]string{s.postname, "hider"}, "_"))),
		g.order))

	// inner secrets
	secrets := NewSecretMerge(&commit.bit, &commit.equalityHider, secretdata)

	// Generate commitments
	list = s.bitRep.commitmentsFromSecrets(g, list, bases, &secrets)
	list = s.equalityRep.commitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *expStepAStructure) buildProof(g group, challenge *big.Int, commit expStepACommit, secretdata SecretLookup) ExpStepAProof {
	return ExpStepAProof{
		Bit:           commit.bit.buildProof(g, challenge),
		EqualityHider: commit.equalityHider.buildProof(g, challenge),
	}
}

func (s *expStepAStructure) fakeProof(g group) ExpStepAProof {
	return ExpStepAProof{
		Bit:           fakeProof(g),
		EqualityHider: fakeProof(g),
	}
}

func (s *expStepAStructure) verifyProofStructure(proof ExpStepAProof) bool {
	return proof.Bit.verifyStructure() && proof.EqualityHider.verifyStructure()
}

func (s *expStepAStructure) commitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proof ExpStepAProof) []*big.Int {
	// inner proof data
	proof.Bit.setName(strings.Join([]string{s.bitname, "hider"}, "_"))
	proof.EqualityHider.setName(strings.Join([]string{s.myname, "eqhider"}, "_"))
	proofMerge := NewProofMerge(&proof.Bit, &proof.EqualityHider)

	// Generate commitments
	list = s.bitRep.commitmentsFromProof(g, list, challenge, bases, &proofMerge)
	list = s.equalityRep.commitmentsFromProof(g, list, challenge, bases, &proofMerge)

	return list
}

func (s *expStepAStructure) isTrue(secretdata SecretLookup) bool {
	if secretdata.Secret(s.bitname).Cmp(big.NewInt(0)) != 0 {
		return false
	}
	if secretdata.Secret(s.prename).Cmp(secretdata.Secret(s.postname)) != 0 {
		return false
	}
	return true
}

func (s *expStepAStructure) numRangeProofs() int {
	return 0
}

func (s *expStepAStructure) numCommitments() int {
	return s.bitRep.numCommitments() + s.equalityRep.numCommitments()
}
