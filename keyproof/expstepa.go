package keyproof

import (
	"strings"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/zkproof"
)

type (
	expStepAStructure struct {
		bitname     string
		prename     string
		postname    string
		myname      string
		bitRep      zkproof.RepresentationProofStructure
		equalityRep zkproof.RepresentationProofStructure
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
	structure.bitRep = zkproof.RepresentationProofStructure{
		[]zkproof.LhsContribution{
			zkproof.LhsContribution{bitname, big.NewInt(1)},
		},
		[]zkproof.RhsContribution{
			zkproof.RhsContribution{"h", strings.Join([]string{bitname, "hider"}, "_"), 1},
		},
	}
	structure.equalityRep = zkproof.RepresentationProofStructure{
		[]zkproof.LhsContribution{
			zkproof.LhsContribution{prename, big.NewInt(1)},
			zkproof.LhsContribution{postname, big.NewInt(-1)},
		},
		[]zkproof.RhsContribution{
			zkproof.RhsContribution{"h", strings.Join([]string{structure.myname, "eqhider"}, "_"), 1},
		},
	}
	return structure
}

func (s *expStepAStructure) commitmentsFromSecrets(g zkproof.Group, list []*big.Int, bases zkproof.BaseLookup, secretdata zkproof.SecretLookup) ([]*big.Int, expStepACommit) {
	var commit expStepACommit

	// Build commit structure
	commit.bit = newSecret(g, strings.Join([]string{s.bitname, "hider"}, "_"), secretdata.Secret(strings.Join([]string{s.bitname, "hider"}, "_")))
	commit.equalityHider = newSecret(g, strings.Join([]string{s.myname, "eqhider"}, "_"), new(big.Int).Mod(
		new(big.Int).Sub(
			secretdata.Secret(strings.Join([]string{s.prename, "hider"}, "_")),
			secretdata.Secret(strings.Join([]string{s.postname, "hider"}, "_"))),
		g.Order))

	// inner secrets
	secrets := zkproof.NewSecretMerge(&commit.bit, &commit.equalityHider, secretdata)

	// Generate commitments
	list = s.bitRep.CommitmentsFromSecrets(g, list, bases, &secrets)
	list = s.equalityRep.CommitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *expStepAStructure) buildProof(g zkproof.Group, challenge *big.Int, commit expStepACommit, secretdata zkproof.SecretLookup) ExpStepAProof {
	return ExpStepAProof{
		Bit:           commit.bit.buildProof(g, challenge),
		EqualityHider: commit.equalityHider.buildProof(g, challenge),
	}
}

func (s *expStepAStructure) fakeProof(g zkproof.Group) ExpStepAProof {
	return ExpStepAProof{
		Bit:           fakeProof(g),
		EqualityHider: fakeProof(g),
	}
}

func (s *expStepAStructure) verifyProofStructure(proof ExpStepAProof) bool {
	return proof.Bit.verifyStructure() && proof.EqualityHider.verifyStructure()
}

func (s *expStepAStructure) commitmentsFromProof(g zkproof.Group, list []*big.Int, challenge *big.Int, bases zkproof.BaseLookup, proof ExpStepAProof) []*big.Int {
	// inner proof data
	proof.Bit.setName(strings.Join([]string{s.bitname, "hider"}, "_"))
	proof.EqualityHider.setName(strings.Join([]string{s.myname, "eqhider"}, "_"))
	proofMerge := zkproof.NewProofMerge(&proof.Bit, &proof.EqualityHider)

	// Generate commitments
	list = s.bitRep.CommitmentsFromProof(g, list, challenge, bases, &proofMerge)
	list = s.equalityRep.CommitmentsFromProof(g, list, challenge, bases, &proofMerge)

	return list
}

func (s *expStepAStructure) isTrue(secretdata zkproof.SecretLookup) bool {
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
	return s.bitRep.NumCommitments() + s.equalityRep.NumCommitments()
}
