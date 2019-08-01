package keyproof

import "github.com/privacybydesign/gabi/internal/common"
import "github.com/privacybydesign/gabi/big"
import "strings"

type expStepAStructure struct {
	bitname     string
	prename     string
	postname    string
	myname      string
	bitRep      RepresentationProofStructure
	equalityRep RepresentationProofStructure
}

type ExpStepAProof struct {
	nameBit             string
	nameEquality        string
	BitHiderResult      *big.Int
	EqualityHiderResult *big.Int
}

type expStepACommit struct {
	nameBit                 string
	nameEquality            string
	bitHiderRandomizer      *big.Int
	equalityHider           *big.Int
	equalityHiderRandomizer *big.Int
}

func (p *ExpStepAProof) GetResult(name string) *big.Int {
	if name == p.nameBit {
		return p.BitHiderResult
	}
	if name == p.nameEquality {
		return p.EqualityHiderResult
	}
	return nil
}

func (c *expStepACommit) GetSecret(name string) *big.Int {
	if name == c.nameEquality {
		return c.equalityHider
	}
	return nil
}

func (c *expStepACommit) GetRandomizer(name string) *big.Int {
	if name == c.nameBit {
		return c.bitHiderRandomizer
	}
	if name == c.nameEquality {
		return c.equalityHiderRandomizer
	}
	return nil
}

func newExpStepAStructure(bitname, prename, postname string) expStepAStructure {
	var structure expStepAStructure
	structure.bitname = bitname
	structure.prename = prename
	structure.postname = postname
	structure.myname = strings.Join([]string{bitname, prename, postname, "expa"}, "_")
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

func (s *expStepAStructure) numRangeProofs() int {
	return 0
}

func (s *expStepAStructure) numCommitments() int {
	return s.bitRep.numCommitments() + s.equalityRep.numCommitments()
}

func (s *expStepAStructure) generateCommitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) ([]*big.Int, expStepACommit) {
	var commit expStepACommit

	// Build commit structure
	commit.nameBit = strings.Join([]string{s.bitname, "hider"}, "_")
	commit.nameEquality = strings.Join([]string{s.myname, "eqhider"}, "_")
	commit.bitHiderRandomizer = common.FastRandomBigInt(g.order)
	commit.equalityHider = new(big.Int).Mod(
		new(big.Int).Sub(
			secretdata.GetSecret(strings.Join([]string{s.prename, "hider"}, "_")),
			secretdata.GetSecret(strings.Join([]string{s.postname, "hider"}, "_"))),
		g.order)
	commit.equalityHiderRandomizer = common.FastRandomBigInt(g.order)

	// inner secrets
	secrets := NewSecretMerge(&commit, secretdata)

	// Generate commitments
	list = s.bitRep.generateCommitmentsFromSecrets(g, list, bases, &secrets)
	list = s.equalityRep.generateCommitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *expStepAStructure) buildProof(g group, challenge *big.Int, commit expStepACommit, secretdata SecretLookup) ExpStepAProof {
	var proof ExpStepAProof

	// Build our results
	proof.BitHiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.bitHiderRandomizer,
			new(big.Int).Mul(
				challenge,
				secretdata.GetSecret(strings.Join([]string{s.bitname, "hider"}, "_")))),
		g.order)
	proof.EqualityHiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.equalityHiderRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.equalityHider)),
		g.order)

	return proof
}

func (s *expStepAStructure) fakeProof(g group) ExpStepAProof {
	var proof ExpStepAProof

	proof.BitHiderResult = common.FastRandomBigInt(g.order)
	proof.EqualityHiderResult = common.FastRandomBigInt(g.order)

	return proof
}

func (s *expStepAStructure) verifyProofStructure(proof ExpStepAProof) bool {
	return proof.BitHiderResult != nil && proof.EqualityHiderResult != nil
}

func (s *expStepAStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proof ExpStepAProof) []*big.Int {
	// inner proof data
	proof.nameBit = strings.Join([]string{s.bitname, "hider"}, "_")
	proof.nameEquality = strings.Join([]string{s.myname, "eqhider"}, "_")

	// Generate commitments
	list = s.bitRep.generateCommitmentsFromProof(g, list, challenge, bases, &proof)
	list = s.equalityRep.generateCommitmentsFromProof(g, list, challenge, bases, &proof)

	return list
}

func (s *expStepAStructure) isTrue(secretdata SecretLookup) bool {
	if secretdata.GetSecret(s.bitname).Cmp(big.NewInt(0)) != 0 {
		return false
	}
	if secretdata.GetSecret(s.prename).Cmp(secretdata.GetSecret(s.postname)) != 0 {
		return false
	}
	return true
}
