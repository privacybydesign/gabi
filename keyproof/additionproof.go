package keyproof

import "github.com/privacybydesign/gabi/internal/common"
import "github.com/privacybydesign/gabi/big"
import "strings"

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
	nameMod      string
	nameHider    string
	ModAddResult *big.Int
	HiderResult  *big.Int
	RangeProof   RangeProof
}

type additionProofCommit struct {
	nameMod          string
	nameHider        string
	modAdd           *big.Int
	modAddRandomizer *big.Int
	hider            *big.Int
	hiderRandomizer  *big.Int
	rangeCommit      rangeCommit
}

func (p *AdditionProof) getResult(name string) *big.Int {
	if name == p.nameMod {
		return p.ModAddResult
	}
	if name == p.nameHider {
		return p.HiderResult
	}
	return nil
}

func (c *additionProofCommit) getSecret(name string) *big.Int {
	if name == c.nameMod {
		return c.modAdd
	}
	if name == c.nameHider {
		return c.hider
	}
	return nil
}

func (c *additionProofCommit) getRandomizer(name string) *big.Int {
	if name == c.nameMod {
		return c.modAddRandomizer
	}
	if name == c.nameHider {
		return c.hiderRandomizer
	}
	return nil
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
	commit.nameMod = strings.Join([]string{s.myname, "mod"}, "_")
	commit.nameHider = strings.Join([]string{s.myname, "hider"}, "_")
	commit.modAdd = new(big.Int).Div(
		new(big.Int).Sub(
			secretdata.getSecret(s.result),
			new(big.Int).Add(
				secretdata.getSecret(s.a1),
				secretdata.getSecret(s.a2))),
		secretdata.getSecret(s.mod))
	commit.modAddRandomizer = common.FastRandomBigInt(g.order)
	commit.hider = new(big.Int).Mod(
		new(big.Int).Sub(
			secretdata.getSecret(strings.Join([]string{s.result, "hider"}, "_")),
			new(big.Int).Add(
				new(big.Int).Add(
					secretdata.getSecret(strings.Join([]string{s.a1, "hider"}, "_")),
					secretdata.getSecret(strings.Join([]string{s.a2, "hider"}, "_"))),
				new(big.Int).Mul(
					secretdata.getSecret(strings.Join([]string{s.mod, "hider"}, "_")),
					commit.modAdd))),
		g.order)
	commit.hiderRandomizer = common.FastRandomBigInt(g.order)

	// build inner secrets
	secrets := newSecretMerge(&commit, secretdata)

	// And build commits
	list = s.addRepresentation.generateCommitmentsFromSecrets(g, list, bases, &secrets)
	list, commit.rangeCommit = s.addRange.generateCommitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *additionProofStructure) buildProof(g group, challenge *big.Int, commit additionProofCommit, secretdata secretLookup) AdditionProof {
	var proof AdditionProof

	rangeSecrets := newSecretMerge(&commit, secretdata)
	proof.RangeProof = s.addRange.buildProof(g, challenge, commit.rangeCommit, &rangeSecrets)
	proof.ModAddResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.modAddRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.modAdd)),
		g.order)
	proof.HiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.hiderRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.hider)),
		g.order)

	return proof
}

func (s *additionProofStructure) fakeProof(g group) AdditionProof {
	var proof AdditionProof

	proof.RangeProof = s.addRange.fakeProof(g)
	proof.ModAddResult = common.FastRandomBigInt(g.order)
	proof.HiderResult = common.FastRandomBigInt(g.order)

	return proof
}

func (s *additionProofStructure) verifyProofStructure(proof AdditionProof) bool {
	if !s.addRange.verifyProofStructure(proof.RangeProof) {
		return false
	}
	if proof.ModAddResult == nil || proof.HiderResult == nil {
		return false
	}
	return true
}

func (s *additionProofStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases baseLookup, proofdata proofLookup, proof AdditionProof) []*big.Int {
	// build inner proof lookup
	proof.nameMod = strings.Join([]string{s.myname, "mod"}, "_")
	proof.nameHider = strings.Join([]string{s.myname, "hider"}, "_")
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
