package keyproof

import (
	"strings"

	"github.com/privacybydesign/gabi/big"
)

type additionProofStructure struct {
	a1                string
	a2                string
	mod               string
	result            string
	myname            string
	addRepresentation representationProofStructure
	addRange          rangeProofStructure
}

type AdditionProof struct {
	ModAddProof Proof
	HiderProof  Proof
	RangeProof  RangeProof
}

type additionProofCommit struct {
	modAdd      secret
	hider       secret
	rangeCommit rangeCommit
}

func (p *AdditionProof) getResult(name string) *big.Int {
	result := p.ModAddProof.getResult(name)
	if result == nil {
		result = p.HiderProof.getResult(name)
	}
	return result
}

func (c *additionProofCommit) getSecret(name string) *big.Int {
	result := c.modAdd.getSecret(name)
	if result == nil {
		result = c.hider.getSecret(name)
	}
	return result
}

func (c *additionProofCommit) getRandomizer(name string) *big.Int {
	result := c.modAdd.getRandomizer(name)
	if result == nil {
		result = c.hider.getRandomizer(name)
	}
	return result
}

func newAdditionProofStructure(a1, a2, mod, result string, l uint) additionProofStructure {
	var structure additionProofStructure
	structure.a1 = a1
	structure.a2 = a2
	structure.mod = mod
	structure.result = result
	structure.myname = strings.Join([]string{a1, a2, mod, result, "add"}, "_")
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

func (s *additionProofStructure) numRangeProofs() int {
	return 1
}

func (s *additionProofStructure) numCommitments() int {
	return s.addRepresentation.numCommitments() + s.addRange.numCommitments()
}

func (s *additionProofStructure) generateCommitmentsFromSecrets(g group, list []*big.Int, bases baseLookup, secretdata secretLookup) ([]*big.Int, additionProofCommit) {
	var commit additionProofCommit

	// Generate needed commit data
	commit.modAdd = newSecret(g, strings.Join([]string{s.myname, "mod"}, "_"),
		new(big.Int).Div(
			new(big.Int).Sub(
				secretdata.getSecret(s.result),
				new(big.Int).Add(
					secretdata.getSecret(s.a1),
					secretdata.getSecret(s.a2))),
			secretdata.getSecret(s.mod)))
	commit.hider = newSecret(g, strings.Join([]string{s.myname, "hider"}, "_"),
		new(big.Int).Mod(
			new(big.Int).Sub(
				secretdata.getSecret(strings.Join([]string{s.result, "hider"}, "_")),
				new(big.Int).Add(
					new(big.Int).Add(
						secretdata.getSecret(strings.Join([]string{s.a1, "hider"}, "_")),
						secretdata.getSecret(strings.Join([]string{s.a2, "hider"}, "_"))),
					new(big.Int).Mul(
						secretdata.getSecret(strings.Join([]string{s.mod, "hider"}, "_")),
						commit.modAdd.secret))),
			g.order))

	// build inner secrets
	secrets := newSecretMerge(&commit, secretdata)

	// and build commits
	list = s.addRepresentation.generateCommitmentsFromSecrets(g, list, bases, &secrets)
	list, commit.rangeCommit = s.addRange.generateCommitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *additionProofStructure) buildProof(g group, challenge *big.Int, commit additionProofCommit, secretdata secretLookup) AdditionProof {
	var proof AdditionProof

	rangeSecrets := newSecretMerge(&commit, secretdata)
	proof.RangeProof = s.addRange.buildProof(g, challenge, commit.rangeCommit, &rangeSecrets)
	proof.ModAddProof = commit.modAdd.buildProof(g, challenge)
	proof.HiderProof = commit.hider.buildProof(g, challenge)

	return proof
}

func (s *additionProofStructure) fakeProof(g group) AdditionProof {
	var proof AdditionProof

	proof.RangeProof = s.addRange.fakeProof(g)
	proof.ModAddProof = fakeProof(g)
	proof.HiderProof = fakeProof(g)

	return proof
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

func (s *additionProofStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases baseLookup, proofdata proofLookup, proof AdditionProof) []*big.Int {
	// build inner proof lookup
	proof.ModAddProof.setName(strings.Join([]string{s.myname, "mod"}, "_"))
	proof.HiderProof.setName(strings.Join([]string{s.myname, "hider"}, "_"))
	proofs := newProofMerge(&proof, proofdata)

	// build commitments
	list = s.addRepresentation.generateCommitmentsFromProof(g, list, challenge, bases, &proofs)
	list = s.addRange.generateCommitmentsFromProof(g, list, challenge, bases, proof.RangeProof)

	return list
}

func (s *additionProofStructure) isTrue(secretdata secretLookup) bool {
	div := new(big.Int)
	mod := new(big.Int)

	div.DivMod(
		new(big.Int).Sub(
			secretdata.getSecret(s.result),
			new(big.Int).Add(
				secretdata.getSecret(s.a1),
				secretdata.getSecret(s.a2))),
		secretdata.getSecret(s.mod),
		mod)

	return mod.Cmp(big.NewInt(0)) == 0 && uint(div.BitLen()) <= s.addRange.l2
}
