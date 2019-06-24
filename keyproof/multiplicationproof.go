package keyproof

import "github.com/privacybydesign/gabi/internal/common"
import "github.com/privacybydesign/gabi/big"
import "strings"

type multiplicationProofStructure struct {
	m1                    string
	m2                    string
	mod                   string
	result                string
	myname                string
	multRepresentation    representationProofStructure
	modMultRepresentation representationProofStructure
	modMultRange          rangeProofStructure
}

type MultiplicationProof struct {
	nameHider    string
	ModMultProof PedersonProof
	HiderResult  *big.Int
	RangeProof   RangeProof
}

type multiplicationProofCommit struct {
	nameHider       string
	modMultPederson pedersonSecret
	hider           *big.Int
	hiderRandomizer *big.Int
	rangeCommit     rangeCommit
}

func (p *MultiplicationProof) getResult(name string) *big.Int {
	if name == p.nameHider {
		return p.HiderResult
	}
	return nil
}

func (c *multiplicationProofCommit) getSecret(name string) *big.Int {
	if name == c.nameHider {
		return c.hider
	}
	return nil
}

func (c *multiplicationProofCommit) getRandomizer(name string) *big.Int {
	if name == c.nameHider {
		return c.hiderRandomizer
	}
	return nil
}

// Note, m1, m2, mod and result should be names of pederson commitments
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
	structure.modMultRepresentation = newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "mod"}, "_"))
	structure.modMultRange = newPedersonRangeProofStructure(strings.Join([]string{structure.myname, "mod"}, "_"), 0, l)
	return structure
}

func (s *multiplicationProofStructure) numRangeProofs() int {
	return 1
}

func (s *multiplicationProofStructure) numCommitments() int {
	return s.multRepresentation.numCommitments() +
		s.modMultRepresentation.numCommitments() +
		s.modMultRange.numCommitments() +
		1
}

func (s *multiplicationProofStructure) generateCommitmentsFromSecrets(g group, list []*big.Int, bases baseLookup, secretdata secretLookup) ([]*big.Int, multiplicationProofCommit) {
	var commit multiplicationProofCommit

	// Generate the neccesary commit data for our parts of the proof
	commit.nameHider = strings.Join([]string{s.myname, "hider"}, "_")
	commit.modMultPederson = newPedersonSecret(
		g,
		strings.Join([]string{s.myname, "mod"}, "_"),
		new(big.Int).Div(
			new(big.Int).Sub(
				new(big.Int).Mul(
					secretdata.getSecret(s.m1),
					secretdata.getSecret(s.m2)),
				secretdata.getSecret(s.result)),
			secretdata.getSecret(s.mod)))
	commit.hider = new(big.Int).Mod(
		new(big.Int).Add(
			new(big.Int).Sub(
				secretdata.getSecret(strings.Join([]string{s.result, "hider"}, "_")),
				new(big.Int).Mul(
					secretdata.getSecret(s.m1),
					secretdata.getSecret(strings.Join([]string{s.m2, "hider"}, "_")))),
			new(big.Int).Mul(
				commit.modMultPederson.secret,
				secretdata.getSecret(strings.Join([]string{s.mod, "hider"}, "_")))),
		g.order)
	commit.hiderRandomizer = common.FastRandomBigInt(g.order)

	// Build inner secrets
	secrets := newSecretMerge(&commit, &commit.modMultPederson, secretdata)

	// Generate commitments for the two proofs
	list = commit.modMultPederson.generateCommitments(list)
	list = s.multRepresentation.generateCommitmentsFromSecrets(g, list, bases, &secrets)
	list = s.modMultRepresentation.generateCommitmentsFromSecrets(g, list, bases, &secrets)
	list, commit.rangeCommit = s.modMultRange.generateCommitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *multiplicationProofStructure) buildProof(g group, challenge *big.Int, commit multiplicationProofCommit, secretdata secretLookup) MultiplicationProof {
	var proof MultiplicationProof

	// Generate the proofs
	rangeSecrets := newSecretMerge(&commit, &commit.modMultPederson, secretdata)
	proof.RangeProof = s.modMultRange.buildProof(g, challenge, commit.rangeCommit, &rangeSecrets)
	proof.ModMultProof = commit.modMultPederson.buildProof(g, challenge)
	proof.HiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.hiderRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.hider)),
		g.order)

	return proof
}

func (s *multiplicationProofStructure) fakeProof(g group) MultiplicationProof {
	var proof MultiplicationProof
	proof.RangeProof = s.modMultRange.fakeProof(g)
	proof.ModMultProof = newPedersonFakeProof(g)
	proof.HiderResult = common.FastRandomBigInt(g.order)
	return proof
}

func (s *multiplicationProofStructure) verifyProofStructure(proof MultiplicationProof) bool {
	if !s.modMultRange.verifyProofStructure(proof.RangeProof) {
		return false
	}
	if !proof.ModMultProof.verifyStructure() || proof.HiderResult == nil {
		return false
	}
	return true
}

func (s *multiplicationProofStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases baseLookup, proofdata proofLookup, proof MultiplicationProof) []*big.Int {
	// Build inner proof lookup
	proof.ModMultProof.setName(strings.Join([]string{s.myname, "mod"}, "_"))
	proof.nameHider = strings.Join([]string{s.myname, "hider"}, "_")
	proofs := newProofMerge(&proof, &proof.ModMultProof, proofdata)
	innerBases := newBaseMerge(&proof.ModMultProof, bases)

	// And regenerate the commitments
	list = proof.ModMultProof.generateCommitments(list)
	list = s.multRepresentation.generateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.modMultRepresentation.generateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
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
