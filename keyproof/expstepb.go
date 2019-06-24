package keyproof

import "github.com/privacybydesign/gabi/internal/common"
import "github.com/privacybydesign/gabi/big"
import "strings"

type expStepBStructure struct {
	bitname    string
	mulname    string
	myname     string
	bitRep     representationProofStructure
	mulRep     representationProofStructure
	prePostMul multiplicationProofStructure
}

type ExpStepBProof struct {
	bitname             string
	mulname             string
	mulhidername        string
	MulResult           *big.Int
	MulHiderResult      *big.Int
	BitHiderResult      *big.Int
	MultiplicationProof MultiplicationProof
}

type expStepBCommit struct {
	bitname              string
	mulname              string
	mulhidername         string
	mulRandomizer        *big.Int
	mulHiderRandomizer   *big.Int
	bitHiderRandomizer   *big.Int
	multiplicationCommit multiplicationProofCommit
}

func (p *ExpStepBProof) getResult(name string) *big.Int {
	if name == p.bitname {
		return p.BitHiderResult
	}
	if name == p.mulname {
		return p.MulResult
	}
	if name == p.mulhidername {
		return p.MulHiderResult
	}
	return nil
}

func (c *expStepBCommit) getSecret(name string) *big.Int {
	return nil
}

func (c *expStepBCommit) getRandomizer(name string) *big.Int {
	if name == c.bitname {
		return c.bitHiderRandomizer
	}
	if name == c.mulname {
		return c.mulRandomizer
	}
	if name == c.mulhidername {
		return c.mulHiderRandomizer
	}
	return nil
}

func newExpStepBStructure(bitname, prename, postname, mulname, modname string, bitlen uint) expStepBStructure {
	var structure expStepBStructure
	structure.bitname = bitname
	structure.mulname = mulname
	structure.myname = strings.Join([]string{bitname, prename, postname, "expb"}, "_")
	structure.bitRep = representationProofStructure{
		[]lhsContribution{
			{bitname, big.NewInt(1)},
			{"g", big.NewInt(-1)},
		},
		[]rhsContribution{
			{"h", strings.Join([]string{bitname, "hider"}, "_"), 1},
		},
	}
	structure.mulRep = newPedersonRepresentationProofStructure(mulname)
	structure.prePostMul = newMultiplicationProofStructure(mulname, prename, modname, postname, bitlen)
	return structure
}

func (s *expStepBStructure) numRangeProofs() int {
	return s.prePostMul.numRangeProofs()
}

func (s *expStepBStructure) numCommitments() int {
	return s.bitRep.numCommitments() + s.mulRep.numCommitments() + s.prePostMul.numCommitments()
}

func (s *expStepBStructure) generateCommitmentsFromSecrets(g group, list []*big.Int, bases baseLookup, secretdata secretLookup) ([]*big.Int, expStepBCommit) {
	var commit expStepBCommit

	// build up commit structure
	commit.bitname = strings.Join([]string{s.bitname, "hider"}, "_")
	commit.mulname = s.mulname
	commit.mulhidername = strings.Join([]string{s.mulname, "hider"}, "_")
	commit.mulRandomizer = common.FastRandomBigInt(g.order)
	commit.mulHiderRandomizer = common.FastRandomBigInt(g.order)
	commit.bitHiderRandomizer = common.FastRandomBigInt(g.order)

	// Inner secrets
	secrets := newSecretMerge(&commit, secretdata)

	// Generate commitment list
	list = s.bitRep.generateCommitmentsFromSecrets(g, list, bases, &secrets)
	list = s.mulRep.generateCommitmentsFromSecrets(g, list, bases, &secrets)
	list, commit.multiplicationCommit = s.prePostMul.generateCommitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *expStepBStructure) buildProof(g group, challenge *big.Int, commit expStepBCommit, secretdata secretLookup) ExpStepBProof {
	// inner secrets
	secrets := newSecretMerge(&commit, secretdata)

	// Build proof
	var proof ExpStepBProof
	proof.MulResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.mulRandomizer,
			new(big.Int).Mul(
				challenge,
				secretdata.getSecret(s.mulname))),
		g.order)
	proof.MulHiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.mulHiderRandomizer,
			new(big.Int).Mul(
				challenge,
				secretdata.getSecret(strings.Join([]string{s.mulname, "hider"}, "_")))),
		g.order)
	proof.BitHiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.bitHiderRandomizer,
			new(big.Int).Mul(
				challenge,
				secretdata.getSecret(strings.Join([]string{s.bitname, "hider"}, "_")))),
		g.order)
	proof.MultiplicationProof = s.prePostMul.buildProof(g, challenge, commit.multiplicationCommit, &secrets)
	return proof
}

func (s *expStepBStructure) fakeProof(g group) ExpStepBProof {
	var proof ExpStepBProof
	proof.MulResult = common.FastRandomBigInt(g.order)
	proof.MulHiderResult = common.FastRandomBigInt(g.order)
	proof.BitHiderResult = common.FastRandomBigInt(g.order)
	proof.MultiplicationProof = s.prePostMul.fakeProof(g)
	return proof
}

func (s *expStepBStructure) verifyProofStructure(proof ExpStepBProof) bool {
	if !s.prePostMul.verifyProofStructure(proof.MultiplicationProof) {
		return false
	}

	return proof.MulResult != nil && proof.MulHiderResult != nil && proof.BitHiderResult != nil
}

func (s *expStepBStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases baseLookup, proof ExpStepBProof) []*big.Int {
	// inner proof
	proof.bitname = strings.Join([]string{s.bitname, "hider"}, "_")
	proof.mulname = s.mulname
	proof.mulhidername = strings.Join([]string{s.mulname, "hider"}, "_")

	// Generate commitments
	list = s.bitRep.generateCommitmentsFromProof(g, list, challenge, bases, &proof)
	list = s.mulRep.generateCommitmentsFromProof(g, list, challenge, bases, &proof)
	list = s.prePostMul.generateCommitmentsFromProof(g, list, challenge, bases, &proof, proof.MultiplicationProof)

	return list
}

func (s *expStepBStructure) isTrue(secretdata secretLookup) bool {
	if secretdata.getSecret(s.bitname).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	return s.prePostMul.isTrue(secretdata)
}
