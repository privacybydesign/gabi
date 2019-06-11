package keyproof

import "github.com/privacybydesign/gabi/internal/common"
import "github.com/privacybydesign/gabi/big"
import "strings"

type primeProofStructure struct {
	primeName string
	myname    string
	bitlen    uint

	halfPRep representationProofStructure

	preaRep   representationProofStructure
	preaRange rangeProofStructure

	aRep   representationProofStructure
	aRange rangeProofStructure

	anegRep   representationProofStructure
	anegRange rangeProofStructure

	aResRep      representationProofStructure
	aPlus1ResRep representationProofStructure
	aMin1ResRep  representationProofStructure

	anegResRep representationProofStructure

	aExp    expProofStructure
	anegExp expProofStructure
}

type PrimeProof struct {
	namePreaMod   string
	namePreaHider string
	nameAplus1    string
	nameAmin1     string

	HalfPCommit   PedersonProof
	PreaCommit    PedersonProof
	ACommit       PedersonProof
	AnegCommit    PedersonProof
	AResCommit    PedersonProof
	AnegResCommit PedersonProof

	PreaModResult   *big.Int
	PreaHiderResult *big.Int

	APlus1Result    *big.Int
	AMin1Result     *big.Int
	APlus1Challenge *big.Int
	AMin1Challenge  *big.Int

	PreaRangeProof    RangeProof
	ARangeProof       RangeProof
	AnegRangeProof    RangeProof
	PreaModRangeProof RangeProof

	AExpProof    ExpProof
	AnegExpProof ExpProof
}

type primeProofCommit struct {
	namePreaMod   string
	namePreaHider string
	nameAValid    string
	nameAInvalid  string

	halfPPederson   pedersonSecret
	preaPederson    pedersonSecret
	aPederson       pedersonSecret
	anegPederson    pedersonSecret
	aResPederson    pedersonSecret
	anegResPederson pedersonSecret

	preaMod             *big.Int
	preaModRandomizer   *big.Int
	preaHider           *big.Int
	preaHiderRandomizer *big.Int

	aValid            *big.Int
	aValidRandomizer  *big.Int
	aInvalidResult    *big.Int
	aInvalidChallenge *big.Int
	aPositive         bool

	preaRangeCommit    rangeCommit
	aRangeCommit       rangeCommit
	anegRangeCommit    rangeCommit
	preaModRangeCommit rangeCommit

	aExpCommit    expProofCommit
	anegExpCommit expProofCommit
}

func (p *PrimeProof) getResult(name string) *big.Int {
	if name == p.namePreaMod {
		return p.PreaModResult
	}
	if name == p.namePreaHider {
		return p.PreaHiderResult
	}
	if name == p.nameAplus1 {
		return p.APlus1Result
	}
	if name == p.nameAmin1 {
		return p.AMin1Result
	}
	return nil
}

func (c *primeProofCommit) getSecret(name string) *big.Int {
	if name == c.namePreaMod {
		return c.preaMod
	}
	if name == c.namePreaHider {
		return c.preaHider
	}
	if name == c.nameAValid {
		return c.aValid
	}
	return nil
}

func (c *primeProofCommit) getRandomizer(name string) *big.Int {
	if name == c.namePreaMod {
		return c.preaModRandomizer
	}
	if name == c.namePreaHider {
		return c.preaHiderRandomizer
	}
	if name == c.nameAValid {
		return c.aValidRandomizer
	}
	return nil
}

func (c *primeProofCommit) getResult(name string) *big.Int {
	if name == c.nameAInvalid {
		return c.aInvalidResult
	}
	return nil
}

func newPrimeProofStructure(name string, bitlen uint) primeProofStructure {
	var structure primeProofStructure
	structure.primeName = name
	structure.myname = strings.Join([]string{name, "primeproof"}, "_")
	structure.bitlen = bitlen

	structure.halfPRep = representationProofStructure{
		[]lhsContribution{
			lhsContribution{name, big.NewInt(1)},
			lhsContribution{strings.Join([]string{structure.myname, "halfp"}, "_"), big.NewInt(-2)},
			lhsContribution{"g", big.NewInt(-1)},
		},
		[]rhsContribution{
			rhsContribution{"h", strings.Join([]string{name, "hider"}, "_"), 1},
			rhsContribution{"h", strings.Join([]string{structure.myname, "halfp", "hider"}, "_"), -2},
		},
	}

	structure.preaRep = newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "prea"}, "_"))
	structure.preaRange = newPedersonRangeProofStructure(strings.Join([]string{structure.myname, "prea"}, "_"), 0, bitlen)

	structure.aRep = newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "a"}, "_"))
	structure.aRange = newPedersonRangeProofStructure(strings.Join([]string{structure.myname, "a"}, "_"), 0, bitlen)

	structure.anegRep = newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "aneg"}, "_"))
	structure.anegRange = newPedersonRangeProofStructure(strings.Join([]string{structure.myname, "aneg"}, "_"), 0, bitlen)

	structure.aResRep = newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "ares"}, "_"))
	structure.aPlus1ResRep = representationProofStructure{
		[]lhsContribution{
			lhsContribution{strings.Join([]string{structure.myname, "ares"}, "_"), big.NewInt(1)},
			lhsContribution{"g", big.NewInt(-1)},
		},
		[]rhsContribution{
			rhsContribution{"h", strings.Join([]string{structure.myname, "aresplus1hider"}, "_"), 1},
		},
	}
	structure.aMin1ResRep = representationProofStructure{
		[]lhsContribution{
			lhsContribution{strings.Join([]string{structure.myname, "ares"}, "_"), big.NewInt(1)},
			lhsContribution{"g", big.NewInt(1)},
		},
		[]rhsContribution{
			rhsContribution{"h", strings.Join([]string{structure.myname, "aresmin1hider"}, "_"), 1},
		},
	}

	structure.anegResRep = representationProofStructure{
		[]lhsContribution{
			lhsContribution{strings.Join([]string{structure.myname, "anegres"}, "_"), big.NewInt(1)},
			lhsContribution{"g", big.NewInt(1)},
		},
		[]rhsContribution{
			rhsContribution{"h", strings.Join([]string{structure.myname, "anegres", "hider"}, "_"), 1},
		},
	}

	structure.aExp = newExpProofStructure(
		strings.Join([]string{structure.myname, "a"}, "_"),
		strings.Join([]string{structure.myname, "halfp"}, "_"),
		name,
		strings.Join([]string{structure.myname, "ares"}, "_"),
		bitlen)
	structure.anegExp = newExpProofStructure(
		strings.Join([]string{structure.myname, "aneg"}, "_"),
		strings.Join([]string{structure.myname, "halfp"}, "_"),
		name,
		strings.Join([]string{structure.myname, "anegres"}, "_"),
		bitlen)
	return structure
}

func (s *primeProofStructure) numRangeProofs() int {
	res := 4
	res += s.aExp.numRangeProofs()
	res += s.anegExp.numRangeProofs()
	return res
}

func (s *primeProofStructure) numCommitments() int {
	res := 6
	res += s.halfPRep.numCommitments()
	res += s.preaRep.numCommitments()
	res += s.preaRange.numCommitments()
	res += s.aRep.numCommitments()
	res += s.aRange.numCommitments()
	res += s.anegRep.numCommitments()
	res += s.anegRange.numCommitments()
	res += 1
	res += rangeProofIters
	res += s.aResRep.numCommitments()
	res += s.anegResRep.numCommitments()
	res += s.aPlus1ResRep.numCommitments()
	res += s.aMin1ResRep.numCommitments()
	res += s.aExp.numCommitments()
	res += s.anegExp.numCommitments()
	return res
}

func (s *primeProofStructure) generateCommitmentsFromSecrets(g group, list []*big.Int, bases baseLookup, secretdata secretLookup) ([]*big.Int, primeProofCommit) {
	var commit primeProofCommit

	// basic setup
	commit.namePreaMod = strings.Join([]string{s.myname, "preamod"}, "_")
	commit.namePreaHider = strings.Join([]string{s.myname, "preahider"}, "_")

	// Build prea
	commit.preaPederson = newPedersonSecret(g, strings.Join([]string{s.myname, "prea"}, "_"), common.FastRandomBigInt(secretdata.getSecret(s.primeName)))

	// Calculate aAdd, a, and d
	aAdd := common.GetHashNumber(commit.preaPederson.commit, nil, 0, s.bitlen)
	d, a := new(big.Int).DivMod(
		new(big.Int).Add(
			commit.preaPederson.secret,
			aAdd),
		secretdata.getSecret(s.primeName),
		new(big.Int))

	// Catch rare generation error
	if a.Cmp(big.NewInt(0)) == 0 {
		panic("Generated a outside of Z*")
	}

	// Generate a related commitments
	commit.aPederson = newPedersonSecret(g, strings.Join([]string{s.myname, "a"}, "_"), a)
	commit.preaMod = d
	commit.preaModRandomizer = common.FastRandomBigInt(g.order)
	commit.preaHider = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.preaPederson.hider,
			new(big.Int).Add(
				commit.aPederson.hider,
				new(big.Int).Mul(
					d,
					secretdata.getSecret(strings.Join([]string{s.primeName, "hider"}, "_"))))),
		g.order)
	commit.preaHiderRandomizer = common.FastRandomBigInt(g.order)

	// Find aneg
	aneg := common.FastRandomBigInt(secretdata.getSecret(s.primeName))
	anegPow := new(big.Int).Exp(aneg, new(big.Int).Rsh(secretdata.getSecret(s.primeName), 1), secretdata.getSecret(s.primeName))
	for anegPow.Cmp(new(big.Int).Sub(secretdata.getSecret(s.primeName), big.NewInt(1))) != 0 {
		aneg.Set(common.FastRandomBigInt(secretdata.getSecret(s.primeName)))
		anegPow.Exp(aneg, new(big.Int).Rsh(secretdata.getSecret(s.primeName), 1), secretdata.getSecret(s.primeName))
	}

	// And build its pederson commitment
	commit.anegPederson = newPedersonSecret(g, strings.Join([]string{s.myname, "aneg"}, "_"), aneg)

	// Generate result pederson commits and proof data
	aRes := new(big.Int).Exp(a, new(big.Int).Rsh(secretdata.getSecret(s.primeName), 1), secretdata.getSecret(s.primeName))
	if aRes.Cmp(big.NewInt(1)) != 0 {
		aRes.Sub(aRes, secretdata.getSecret(s.primeName))
	}
	anegRes := new(big.Int).Exp(aneg, new(big.Int).Rsh(secretdata.getSecret(s.primeName), 1), secretdata.getSecret(s.primeName))
	anegRes.Sub(anegRes, secretdata.getSecret(s.primeName))
	commit.aResPederson = newPedersonSecret(g, strings.Join([]string{s.myname, "ares"}, "_"), aRes)
	commit.anegResPederson = newPedersonSecret(g, strings.Join([]string{s.myname, "anegres"}, "_"), anegRes)
	commit.aInvalidResult = common.FastRandomBigInt(g.order)
	commit.aInvalidChallenge = common.FastRandomBigInt(new(big.Int).Lsh(big.NewInt(1), 256))
	commit.aValid = commit.aResPederson.hider
	commit.aValidRandomizer = common.FastRandomBigInt(g.order)
	if aRes.Cmp(big.NewInt(1)) == 0 {
		commit.nameAValid = strings.Join([]string{s.myname, "aresplus1hider"}, "_")
		commit.nameAInvalid = strings.Join([]string{s.myname, "aresmin1hider"}, "_")
		commit.aPositive = true
	} else {
		commit.nameAValid = strings.Join([]string{s.myname, "aresmin1hider"}, "_")
		commit.nameAInvalid = strings.Join([]string{s.myname, "aresplus1hider"}, "_")
		commit.aPositive = false
	}

	// the half p pederson commit
	commit.halfPPederson = newPedersonSecret(g, strings.Join([]string{s.myname, "halfp"}, "_"), new(big.Int).Rsh(secretdata.getSecret(s.primeName), 1))

	// Build structure for the a generation proofs
	agenproof := representationProofStructure{
		[]lhsContribution{
			lhsContribution{commit.preaPederson.name, big.NewInt(1)},
			lhsContribution{"g", new(big.Int).Mod(aAdd, g.order)},
			lhsContribution{commit.aPederson.name, big.NewInt(-1)},
		},
		[]rhsContribution{
			rhsContribution{s.primeName, commit.namePreaMod, 1},
			rhsContribution{"h", commit.namePreaHider, 1},
		},
	}
	agenrange := rangeProofStructure{
		agenproof,
		commit.namePreaMod,
		0,
		s.bitlen,
	}

	// Inner secrets and bases structures
	innerBases := newBaseMerge(&commit.preaPederson, &commit.aPederson, &commit.anegPederson, &commit.aResPederson, &commit.anegResPederson, &commit.halfPPederson, bases)
	secrets := newSecretMerge(&commit, &commit.preaPederson, &commit.aPederson, &commit.anegPederson, &commit.aResPederson, &commit.anegResPederson, &commit.halfPPederson, secretdata)

	// Build all commitments
	list = commit.halfPPederson.generateCommitments(list)
	list = commit.preaPederson.generateCommitments(list)
	list = commit.aPederson.generateCommitments(list)
	list = commit.anegPederson.generateCommitments(list)
	list = commit.aResPederson.generateCommitments(list)
	list = commit.anegResPederson.generateCommitments(list)
	list = s.halfPRep.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = s.preaRep.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.preaRangeCommit = s.preaRange.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = s.aRep.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.aRangeCommit = s.aRange.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = s.anegRep.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.anegRangeCommit = s.anegRange.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = agenproof.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.preaModRangeCommit = agenrange.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = s.aResRep.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = s.anegResRep.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	if commit.aPositive {
		list = s.aPlus1ResRep.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
		list = s.aMin1ResRep.generateCommitmentsFromProof(g, list, commit.aInvalidChallenge, &innerBases, &commit)
	} else {
		list = s.aPlus1ResRep.generateCommitmentsFromProof(g, list, commit.aInvalidChallenge, &innerBases, &commit)
		list = s.aMin1ResRep.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	}
	list, commit.aExpCommit = s.aExp.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.anegExpCommit = s.anegExp.generateCommitmentsFromSecrets(g, list, &innerBases, &secrets)

	return list, commit
}

func (s *primeProofStructure) buildProof(g group, challenge *big.Int, commit primeProofCommit, secretdata secretLookup) PrimeProof {
	var proof PrimeProof

	// Rebuild structure for the a generation proofs
	aAdd := common.GetHashNumber(commit.preaPederson.commit, nil, 0, s.bitlen)
	agenproof := representationProofStructure{
		[]lhsContribution{
			lhsContribution{commit.preaPederson.name, big.NewInt(1)},
			lhsContribution{"g", new(big.Int).Mod(aAdd, g.order)},
			lhsContribution{commit.aPederson.name, big.NewInt(-1)},
		},
		[]rhsContribution{
			rhsContribution{s.primeName, commit.namePreaMod, 1},
			rhsContribution{"h", commit.namePreaHider, 1},
		},
	}
	agenrange := rangeProofStructure{
		agenproof,
		commit.namePreaMod,
		0,
		s.bitlen,
	}

	// Recreate full secrets lookup
	secrets := newSecretMerge(&commit, &commit.preaPederson, &commit.aPederson, &commit.anegPederson, secretdata)

	// Generate proofs for the pederson commitments
	proof.HalfPCommit = commit.halfPPederson.buildProof(g, challenge)
	proof.PreaCommit = commit.preaPederson.buildProof(g, challenge)
	proof.ACommit = commit.aPederson.buildProof(g, challenge)
	proof.AnegCommit = commit.anegPederson.buildProof(g, challenge)
	proof.AResCommit = commit.aResPederson.buildProof(g, challenge)
	proof.AnegResCommit = commit.anegResPederson.buildProof(g, challenge)

	// Generate range proofs
	proof.PreaRangeProof = s.preaRange.buildProof(g, challenge, commit.preaRangeCommit, &secrets)
	proof.ARangeProof = s.aRange.buildProof(g, challenge, commit.aRangeCommit, &secrets)
	proof.AnegRangeProof = s.anegRange.buildProof(g, challenge, commit.anegRangeCommit, &secrets)
	proof.PreaModRangeProof = agenrange.buildProof(g, challenge, commit.preaModRangeCommit, &secrets)

	// And calculate our results
	proof.PreaModResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.preaModRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.preaMod)),
		g.order)
	proof.PreaHiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.preaHiderRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.preaHider)),
		g.order)

	if commit.aPositive {
		proof.APlus1Challenge = new(big.Int).Xor(challenge, commit.aInvalidChallenge)
		proof.APlus1Result = new(big.Int).Mod(
			new(big.Int).Sub(
				commit.aValidRandomizer,
				new(big.Int).Mul(
					proof.APlus1Challenge,
					commit.aValid)),
			g.order)

		proof.AMin1Challenge = commit.aInvalidChallenge
		proof.AMin1Result = commit.aInvalidResult
	} else {
		proof.APlus1Challenge = commit.aInvalidChallenge
		proof.APlus1Result = commit.aInvalidResult

		proof.AMin1Challenge = new(big.Int).Xor(challenge, commit.aInvalidChallenge)
		proof.AMin1Result = new(big.Int).Mod(
			new(big.Int).Sub(
				commit.aValidRandomizer,
				new(big.Int).Mul(
					proof.AMin1Challenge,
					commit.aValid)),
			g.order)
	}

	proof.AExpProof = s.aExp.buildProof(g, challenge, commit.aExpCommit, &secrets)
	proof.AnegExpProof = s.anegExp.buildProof(g, challenge, commit.anegExpCommit, &secrets)

	return proof
}

func (s *primeProofStructure) fakeProof(g group, challenge *big.Int) PrimeProof {
	var proof PrimeProof

	// Fake the pederson proofs
	proof.HalfPCommit = newPedersonFakeProof(g)
	proof.PreaCommit = newPedersonFakeProof(g)
	proof.ACommit = newPedersonFakeProof(g)
	proof.AnegCommit = newPedersonFakeProof(g)
	proof.AResCommit = newPedersonFakeProof(g)
	proof.AnegResCommit = newPedersonFakeProof(g)

	// Build the fake proof structure for the preaMod rangeproof
	aAdd := common.GetHashNumber(proof.PreaCommit.Commit, nil, 0, s.bitlen)
	agenproof := representationProofStructure{
		[]lhsContribution{
			lhsContribution{strings.Join([]string{s.myname, "prea"}, "_"), big.NewInt(1)},
			lhsContribution{"g", new(big.Int).Mod(aAdd, g.order)},
			lhsContribution{strings.Join([]string{s.myname, "a"}, "_"), big.NewInt(-1)},
		},
		[]rhsContribution{
			rhsContribution{s.primeName, strings.Join([]string{s.myname, "preamod"}, "_"), 1},
			rhsContribution{"h", strings.Join([]string{s.myname, "preahider"}, "_"), 1},
		},
	}
	agenrange := rangeProofStructure{
		agenproof,
		strings.Join([]string{s.myname, "preamod"}, "_"),
		0,
		s.bitlen,
	}

	// Fake the range proofs
	proof.PreaRangeProof = s.preaRange.fakeProof(g)
	proof.ARangeProof = s.aRange.fakeProof(g)
	proof.AnegRangeProof = s.anegRange.fakeProof(g)
	proof.PreaModRangeProof = agenrange.fakeProof(g)

	// And fake our bits
	proof.PreaModResult = common.FastRandomBigInt(g.order)
	proof.PreaHiderResult = common.FastRandomBigInt(g.order)
	proof.APlus1Result = common.FastRandomBigInt(g.order)
	proof.AMin1Result = common.FastRandomBigInt(g.order)
	proof.APlus1Challenge = common.FastRandomBigInt(new(big.Int).Lsh(big.NewInt(1), 256))
	proof.AMin1Challenge = new(big.Int).Xor(challenge, proof.APlus1Challenge)

	proof.AExpProof = s.aExp.fakeProof(g, challenge)
	proof.AnegExpProof = s.anegExp.fakeProof(g, challenge)

	return proof
}

func (s *primeProofStructure) verifyProofStructure(challenge *big.Int, proof PrimeProof) bool {
	// Check pederson commitments
	if !proof.HalfPCommit.verifyStructure() ||
		!proof.PreaCommit.verifyStructure() ||
		!proof.ACommit.verifyStructure() ||
		!proof.AnegCommit.verifyStructure() ||
		!proof.AResCommit.verifyStructure() ||
		!proof.AnegResCommit.verifyStructure() {
		return false
	}

	// Build the proof structure for the preaMod rangeproof
	aAdd := common.GetHashNumber(proof.PreaCommit.Commit, nil, 0, s.bitlen)
	agenproof := representationProofStructure{
		[]lhsContribution{
			lhsContribution{strings.Join([]string{s.myname, "prea"}, "_"), big.NewInt(1)},
			// LhsContribution{"g", new(big.Int).Mod(aAdd, g.order)},
			lhsContribution{"g", aAdd},
			lhsContribution{strings.Join([]string{s.myname, "a"}, "_"), big.NewInt(-1)},
		},
		[]rhsContribution{
			rhsContribution{s.primeName, strings.Join([]string{s.myname, "preamod"}, "_"), 1},
			rhsContribution{"h", strings.Join([]string{s.myname, "preahider"}, "_"), 1},
		},
	}
	agenrange := rangeProofStructure{
		agenproof,
		strings.Join([]string{s.myname, "preamod"}, "_"),
		0,
		s.bitlen,
	}

	// Check the range proofs
	if !s.preaRange.verifyProofStructure(proof.PreaRangeProof) ||
		!s.aRange.verifyProofStructure(proof.ARangeProof) ||
		!s.anegRange.verifyProofStructure(proof.AnegRangeProof) ||
		!agenrange.verifyProofStructure(proof.PreaModRangeProof) {
		return false
	}

	// Check our parts are here
	if proof.PreaModResult == nil || proof.PreaHiderResult == nil {
		return false
	}
	if proof.APlus1Result == nil || proof.AMin1Result == nil {
		return false
	}
	if proof.APlus1Challenge == nil || proof.AMin1Challenge == nil {
		return false
	}
	if new(big.Int).Xor(proof.APlus1Challenge, proof.AMin1Challenge).Cmp(challenge) != 0 {
		return false
	}

	if !s.aExp.verifyProofStructure(challenge, proof.AExpProof) ||
		!s.anegExp.verifyProofStructure(challenge, proof.AnegExpProof) {
		return false
	}

	return true
}

func (s *primeProofStructure) generateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases baseLookup, proofdata proofLookup, proof PrimeProof) []*big.Int {
	// Setup
	proof.namePreaMod = strings.Join([]string{s.myname, "preamod"}, "_")
	proof.namePreaHider = strings.Join([]string{s.myname, "preahider"}, "_")
	proof.nameAplus1 = strings.Join([]string{s.myname, "aresplus1hider"}, "_")
	proof.nameAmin1 = strings.Join([]string{s.myname, "aresmin1hider"}, "_")
	proof.HalfPCommit.setName(strings.Join([]string{s.myname, "halfp"}, "_"))
	proof.PreaCommit.setName(strings.Join([]string{s.myname, "prea"}, "_"))
	proof.ACommit.setName(strings.Join([]string{s.myname, "a"}, "_"))
	proof.AnegCommit.setName(strings.Join([]string{s.myname, "aneg"}, "_"))
	proof.AResCommit.setName(strings.Join([]string{s.myname, "ares"}, "_"))
	proof.AnegResCommit.setName(strings.Join([]string{s.myname, "anegres"}, "_"))

	// Build the proof structure for the preamod proofs
	aAdd := common.GetHashNumber(proof.PreaCommit.Commit, nil, 0, s.bitlen)
	agenproof := representationProofStructure{
		[]lhsContribution{
			lhsContribution{strings.Join([]string{s.myname, "prea"}, "_"), big.NewInt(1)},
			lhsContribution{"g", new(big.Int).Mod(aAdd, g.order)},
			lhsContribution{strings.Join([]string{s.myname, "a"}, "_"), big.NewInt(-1)},
		},
		[]rhsContribution{
			rhsContribution{s.primeName, strings.Join([]string{s.myname, "preamod"}, "_"), 1},
			rhsContribution{"h", strings.Join([]string{s.myname, "preahider"}, "_"), 1},
		},
	}
	agenrange := rangeProofStructure{
		agenproof,
		strings.Join([]string{s.myname, "preamod"}, "_"),
		0,
		s.bitlen,
	}

	// inner bases
	innerBases := newBaseMerge(&proof.PreaCommit, &proof.ACommit, &proof.AnegCommit, &proof.AResCommit, &proof.AnegResCommit, &proof.HalfPCommit, bases)
	proofs := newProofMerge(&proof, &proof.PreaCommit, &proof.ACommit, &proof.AnegCommit, &proof.AResCommit, &proof.AnegResCommit, &proof.HalfPCommit, proofdata)

	// Build all commitments
	list = proof.HalfPCommit.generateCommitments(list)
	list = proof.PreaCommit.generateCommitments(list)
	list = proof.ACommit.generateCommitments(list)
	list = proof.AnegCommit.generateCommitments(list)
	list = proof.AResCommit.generateCommitments(list)
	list = proof.AnegResCommit.generateCommitments(list)
	list = s.halfPRep.generateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.preaRep.generateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.preaRange.generateCommitmentsFromProof(g, list, challenge, &innerBases, proof.PreaRangeProof)
	list = s.aRep.generateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.aRange.generateCommitmentsFromProof(g, list, challenge, &innerBases, proof.ARangeProof)
	list = s.anegRep.generateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.anegRange.generateCommitmentsFromProof(g, list, challenge, &innerBases, proof.AnegRangeProof)
	list = agenproof.generateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = agenrange.generateCommitmentsFromProof(g, list, challenge, &innerBases, proof.PreaModRangeProof)
	list = s.aResRep.generateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.anegResRep.generateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.aPlus1ResRep.generateCommitmentsFromProof(g, list, proof.APlus1Challenge, &innerBases, &proofs)
	list = s.aMin1ResRep.generateCommitmentsFromProof(g, list, proof.AMin1Challenge, &innerBases, &proofs)
	list = s.aExp.generateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs, proof.AExpProof)
	list = s.anegExp.generateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs, proof.AnegExpProof)

	return list
}

func (s *primeProofStructure) isTrue(secretdata secretLookup) bool {
	return secretdata.getSecret(s.primeName).ProbablyPrime(40)
}
