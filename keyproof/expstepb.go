package keyproof

import (
	"strings"

	"github.com/privacybydesign/gabi/big"
)

type (
	expStepBStructure struct {
		bitname    string
		mulname    string
		myname     string
		bitRep     representationProofStructure
		mul        pedersenStructure
		prePostMul multiplicationProofStructure
	}

	ExpStepBProof struct {
		Mul                 PedersenProof
		Bit                 Proof
		MultiplicationProof MultiplicationProof
	}

	expStepBCommit struct {
		mul                  pedersenCommit
		bit                  secret
		multiplicationCommit multiplicationProofCommit
	}
)

func newExpStepBStructure(bitname, prename, postname, mulname, modname string, bitlen uint) expStepBStructure {
	structure := expStepBStructure{
		bitname:    bitname,
		mulname:    mulname,
		myname:     strings.Join([]string{bitname, prename, postname, "expb"}, "_"),
		mul:        newPedersenStructure(mulname),
		prePostMul: newMultiplicationProofStructure(mulname, prename, modname, postname, bitlen),
	}
	structure.bitRep = representationProofStructure{
		[]lhsContribution{
			{bitname, big.NewInt(1)},
			{"g", big.NewInt(-1)},
		},
		[]rhsContribution{
			{"h", strings.Join([]string{bitname, "hider"}, "_"), 1},
		},
	}
	return structure
}

func (s *expStepBStructure) commitmentsFromSecrets(g group, list []*big.Int, bases baseLookup, secretdata secretLookup) ([]*big.Int, expStepBCommit) {
	var commit expStepBCommit

	// build up commit structure
	commit.bit = newSecret(g, strings.Join([]string{s.bitname, "hider"}, "_"), secretdata.secret(strings.Join([]string{s.bitname, "hider"}, "_")))
	list, commit.mul = s.mul.commitmentsDuplicate(g, list, secretdata.secret(s.mulname),
		secretdata.secret(strings.Join([]string{s.mulname, "hider"}, "_")))

	// Inner secrets
	secrets := newSecretMerge(&commit.mul, &commit.bit, secretdata)

	// Generate commitment list
	list = s.bitRep.commitmentsFromSecrets(g, list, bases, &secrets)
	list, commit.multiplicationCommit = s.prePostMul.commitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *expStepBStructure) buildProof(g group, challenge *big.Int, commit expStepBCommit, secretdata secretLookup) ExpStepBProof {
	// inner secrets
	secrets := newSecretMerge(&commit.mul, &commit.bit, secretdata)

	// Build proof
	return ExpStepBProof{
		Bit:                 commit.bit.buildProof(g, challenge),
		Mul:                 s.mul.buildProof(g, challenge, commit.mul),
		MultiplicationProof: s.prePostMul.buildProof(g, challenge, commit.multiplicationCommit, &secrets),
	}
}

func (s *expStepBStructure) fakeProof(g group) ExpStepBProof {
	return ExpStepBProof{
		Bit:                 fakeProof(g),
		Mul:                 s.mul.fakeProof(g),
		MultiplicationProof: s.prePostMul.fakeProof(g),
	}
}

func (s *expStepBStructure) verifyProofStructure(proof ExpStepBProof) bool {
	if !s.prePostMul.verifyProofStructure(proof.MultiplicationProof) {
		return false
	}
	if !s.mul.verifyProofStructure(proof.Mul) {
		return false
	}
	return proof.Bit.verifyStructure()
}

func (s *expStepBStructure) commitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases baseLookup, proof ExpStepBProof) []*big.Int {
	// inner proof
	proof.Bit.setName(strings.Join([]string{s.bitname, "hider"}, "_"))
	proof.Mul.setName(s.mulname)
	proofs := newProofMerge(&proof.Bit, &proof.Mul)

	// Generate commitments
	list = s.mul.commitmentsFromProof(g, list, challenge, proof.Mul)
	list = s.bitRep.commitmentsFromProof(g, list, challenge, bases, &proofs)
	list = s.prePostMul.commitmentsFromProof(g, list, challenge, bases, &proofs, proof.MultiplicationProof)

	return list
}

func (s *expStepBStructure) isTrue(secretdata secretLookup) bool {
	if secretdata.secret(s.bitname).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	return s.prePostMul.isTrue(secretdata)
}

func (s *expStepBStructure) numRangeProofs() int {
	return s.prePostMul.numRangeProofs()
}

func (s *expStepBStructure) numCommitments() int {
	return s.bitRep.numCommitments() + s.mul.numCommitments() + s.prePostMul.numCommitments()
}
