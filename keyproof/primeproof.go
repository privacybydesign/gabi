package keyproof

import (
	"strings"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/zkproof"
)

type (
	primeProofStructure struct {
		primeName string
		myname    string
		bitlen    uint

		halfP    pedersenStructure
		halfPRep zkproof.RepresentationProofStructure

		prea      pedersenStructure
		preaRange rangeProofStructure

		a      pedersenStructure
		aRange rangeProofStructure

		aneg      pedersenStructure
		anegRange rangeProofStructure

		aRes         pedersenStructure
		anegRes      pedersenStructure
		aPlus1ResRep zkproof.RepresentationProofStructure
		aMin1ResRep  zkproof.RepresentationProofStructure

		anegResRep zkproof.RepresentationProofStructure

		aExp    expProofStructure
		anegExp expProofStructure
	}

	PrimeProof struct {
		HalfPCommit   PedersenProof
		PreaCommit    PedersenProof
		ACommit       PedersenProof
		AnegCommit    PedersenProof
		AResCommit    PedersenProof
		AnegResCommit PedersenProof

		PreaMod   Proof
		PreaHider Proof

		APlus1          Proof
		AMin1           Proof
		APlus1Challenge *big.Int
		AMin1Challenge  *big.Int

		PreaRangeProof    RangeProof
		ARangeProof       RangeProof
		AnegRangeProof    RangeProof
		PreaModRangeProof RangeProof

		AExpProof    ExpProof
		AnegExpProof ExpProof
	}
)

type primeProofCommit struct {
	halfP   pedersenCommit
	prea    pedersenCommit
	a       pedersenCommit
	aneg    pedersenCommit
	aRes    pedersenCommit
	anegRes pedersenCommit

	preaMod   secret
	preaHider secret

	aValid            secret
	aInvalid          Proof
	aInvalidChallenge *big.Int
	aPositive         bool

	preaRangeCommit    rangeCommit
	aRangeCommit       rangeCommit
	anegRangeCommit    rangeCommit
	preaModRangeCommit rangeCommit

	aExpCommit    expProofCommit
	anegExpCommit expProofCommit
}

func newPrimeProofStructure(name string, bitlen uint) primeProofStructure {
	var structure primeProofStructure
	structure.primeName = name
	structure.myname = strings.Join([]string{name, "primeproof"}, "_")
	structure.bitlen = bitlen

	structure.halfP = newPedersenStructure(strings.Join([]string{structure.myname, "halfp"}, "_"))
	structure.halfPRep = zkproof.RepresentationProofStructure{
		Lhs: []zkproof.LhsContribution{
			{name, big.NewInt(1)},
			{strings.Join([]string{structure.myname, "halfp"}, "_"), big.NewInt(-2)},
			{"g", big.NewInt(-1)},
		},
		Rhs: []zkproof.RhsContribution{
			{"h", strings.Join([]string{name, "hider"}, "_"), 1},
			{"h", strings.Join([]string{structure.myname, "halfp", "hider"}, "_"), -2},
		},
	}

	structure.prea = newPedersenStructure(strings.Join([]string{structure.myname, "prea"}, "_"))
	structure.preaRange = newPedersenRangeProofStructure(strings.Join([]string{structure.myname, "prea"}, "_"), 0, bitlen)

	structure.a = newPedersenStructure(strings.Join([]string{structure.myname, "a"}, "_"))
	structure.aRange = newPedersenRangeProofStructure(strings.Join([]string{structure.myname, "a"}, "_"), 0, bitlen)

	structure.aneg = newPedersenStructure(strings.Join([]string{structure.myname, "aneg"}, "_"))
	structure.anegRange = newPedersenRangeProofStructure(strings.Join([]string{structure.myname, "aneg"}, "_"), 0, bitlen)

	structure.aRes = newPedersenStructure(strings.Join([]string{structure.myname, "ares"}, "_"))
	structure.anegRes = newPedersenStructure(strings.Join([]string{structure.myname, "anegres"}, "_"))
	structure.aPlus1ResRep = zkproof.RepresentationProofStructure{
		Lhs: []zkproof.LhsContribution{
			{strings.Join([]string{structure.myname, "ares"}, "_"), big.NewInt(1)},
			{"g", big.NewInt(-1)},
		},
		Rhs: []zkproof.RhsContribution{
			{"h", strings.Join([]string{structure.myname, "aresplus1hider"}, "_"), 1},
		},
	}
	structure.aMin1ResRep = zkproof.RepresentationProofStructure{
		Lhs: []zkproof.LhsContribution{
			{strings.Join([]string{structure.myname, "ares"}, "_"), big.NewInt(1)},
			{"g", big.NewInt(1)},
		},
		Rhs: []zkproof.RhsContribution{
			{"h", strings.Join([]string{structure.myname, "aresmin1hider"}, "_"), 1},
		},
	}

	structure.anegResRep = zkproof.RepresentationProofStructure{
		Lhs: []zkproof.LhsContribution{
			{strings.Join([]string{structure.myname, "anegres"}, "_"), big.NewInt(1)},
			{"g", big.NewInt(1)},
		},
		Rhs: []zkproof.RhsContribution{
			{"h", strings.Join([]string{structure.myname, "anegres", "hider"}, "_"), 1},
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

func (s *primeProofStructure) commitmentsFromSecrets(g zkproof.Group, list []*big.Int, bases zkproof.BaseLookup, secretdata zkproof.SecretLookup) ([]*big.Int, primeProofCommit) {
	var commit primeProofCommit

	// Build prea
	list, commit.prea = s.prea.commitmentsFromSecrets(g, list, common.FastRandomBigInt(secretdata.Secret(s.primeName)))

	// Calculate aAdd, a, and d
	aAdd := common.GetHashNumber(commit.prea.commit, nil, 0, s.bitlen)
	d, a := new(big.Int).DivMod(
		new(big.Int).Add(
			commit.prea.secretv.secretv,
			aAdd),
		secretdata.Secret(s.primeName),
		new(big.Int))

	// Catch rare generation error
	if a.Cmp(big.NewInt(0)) == 0 {
		panic("Generated a outside of Z*")
	}

	// Generate a related commitments
	list, commit.a = s.a.commitmentsFromSecrets(g, list, a)
	commit.preaMod = newSecret(g, strings.Join([]string{s.myname, "preamod"}, "_"), d)
	commit.preaHider = newSecret(g, strings.Join([]string{s.myname, "preahider"}, "_"),
		new(big.Int).Mod(
			new(big.Int).Sub(
				commit.prea.hider.secretv,
				new(big.Int).Add(
					commit.a.hider.secretv,
					new(big.Int).Mul(
						d,
						secretdata.Secret(strings.Join([]string{s.primeName, "hider"}, "_"))))),
			g.Order))

	// Find aneg
	aneg := common.FastRandomBigInt(secretdata.Secret(s.primeName))
	anegPow := new(big.Int).Exp(aneg, new(big.Int).Rsh(secretdata.Secret(s.primeName), 1), secretdata.Secret(s.primeName))
	for anegPow.Cmp(new(big.Int).Sub(secretdata.Secret(s.primeName), big.NewInt(1))) != 0 {
		aneg.Set(common.FastRandomBigInt(secretdata.Secret(s.primeName)))
		anegPow.Exp(aneg, new(big.Int).Rsh(secretdata.Secret(s.primeName), 1), secretdata.Secret(s.primeName))
	}

	// And build its pedersen commitment
	list, commit.aneg = s.aneg.commitmentsFromSecrets(g, list, aneg)

	// Generate result pedersen commits and proof data
	aRes := new(big.Int).Exp(a, new(big.Int).Rsh(secretdata.Secret(s.primeName), 1), secretdata.Secret(s.primeName))
	if aRes.Cmp(big.NewInt(1)) != 0 {
		aRes.Sub(aRes, secretdata.Secret(s.primeName))
	}
	anegRes := new(big.Int).Exp(aneg, new(big.Int).Rsh(secretdata.Secret(s.primeName), 1), secretdata.Secret(s.primeName))
	anegRes.Sub(anegRes, secretdata.Secret(s.primeName))
	list, commit.aRes = s.aRes.commitmentsFromSecrets(g, list, aRes)
	list, commit.anegRes = s.anegRes.commitmentsFromSecrets(g, list, anegRes)
	commit.aInvalid = fakeProof(g)
	commit.aInvalidChallenge = common.FastRandomBigInt(g.Order)
	if aRes.Cmp(big.NewInt(1)) == 0 {
		commit.aValid = newSecret(g, strings.Join([]string{s.myname, "aresplus1hider"}, "_"), commit.aRes.hider.secretv)
		commit.aInvalid.setName(strings.Join([]string{s.myname, "aresmin1hider"}, "_"))
		commit.aPositive = true
	} else {
		commit.aValid = newSecret(g, strings.Join([]string{s.myname, "aresmin1hider"}, "_"), commit.aRes.hider.secretv)
		commit.aInvalid.setName(strings.Join([]string{s.myname, "aresplus1hider"}, "_"))
		commit.aPositive = false
	}

	// the half p pedersen commit
	list, commit.halfP = s.halfP.commitmentsFromSecrets(g, list,
		new(big.Int).Rsh(
			secretdata.Secret(s.primeName),
			1))

	// Build structure for the a generation proofs
	agenproof := zkproof.RepresentationProofStructure{
		Lhs: []zkproof.LhsContribution{
			{commit.prea.name, big.NewInt(1)},
			{"g", new(big.Int).Mod(aAdd, g.Order)},
			{commit.a.name, big.NewInt(-1)},
		},
		Rhs: []zkproof.RhsContribution{
			{s.primeName, commit.preaMod.name, 1},
			{"h", commit.preaHider.name, 1},
		},
	}
	agenrange := rangeProofStructure{
		agenproof,
		commit.preaMod.name,
		0,
		s.bitlen,
	}

	// Inner secrets and bases structures
	innerBases := zkproof.NewBaseMerge(
		&commit.prea,
		&commit.a,
		&commit.aneg,
		&commit.aRes,
		&commit.anegRes,
		&commit.halfP,
		bases)
	secrets := zkproof.NewSecretMerge(
		&commit.preaMod,
		&commit.preaHider,
		&commit.aValid,
		&commit.prea,
		&commit.a,
		&commit.aneg,
		&commit.aRes,
		&commit.anegRes,
		&commit.halfP,
		secretdata)

	// Build all commitments
	list = s.halfPRep.CommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.preaRangeCommit = s.preaRange.commitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.aRangeCommit = s.aRange.commitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.anegRangeCommit = s.anegRange.commitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = agenproof.CommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.preaModRangeCommit = agenrange.commitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = s.anegResRep.CommitmentsFromSecrets(g, list, &innerBases, &secrets)
	if commit.aPositive {
		list = s.aPlus1ResRep.CommitmentsFromSecrets(g, list, &innerBases, &secrets)
		list = s.aMin1ResRep.CommitmentsFromProof(g, list, commit.aInvalidChallenge, &innerBases, &commit.aInvalid)
	} else {
		list = s.aPlus1ResRep.CommitmentsFromProof(g, list, commit.aInvalidChallenge, &innerBases, &commit.aInvalid)
		list = s.aMin1ResRep.CommitmentsFromSecrets(g, list, &innerBases, &secrets)
	}
	list, commit.aExpCommit = s.aExp.commitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.anegExpCommit = s.anegExp.commitmentsFromSecrets(g, list, &innerBases, &secrets)

	return list, commit
}

func (s *primeProofStructure) buildProof(g zkproof.Group, challenge *big.Int, commit primeProofCommit, secretdata zkproof.SecretLookup) PrimeProof {
	var proof PrimeProof

	// Rebuild structure for the a generation proofs
	aAdd := common.GetHashNumber(commit.prea.commit, nil, 0, s.bitlen)
	agenproof := zkproof.RepresentationProofStructure{
		Lhs: []zkproof.LhsContribution{
			{commit.prea.name, big.NewInt(1)},
			{"g", new(big.Int).Mod(aAdd, g.Order)},
			{commit.a.name, big.NewInt(-1)},
		},
		Rhs: []zkproof.RhsContribution{
			{s.primeName, commit.preaMod.name, 1},
			{"h", commit.preaHider.name, 1},
		},
	}
	agenrange := rangeProofStructure{
		agenproof,
		commit.preaMod.name,
		0,
		s.bitlen,
	}

	// Recreate full secrets lookup
	secrets := zkproof.NewSecretMerge(
		&commit.preaMod,
		&commit.preaHider,
		&commit.prea,
		&commit.a,
		&commit.aneg,
		secretdata)

	// Generate proofs for the pedersen commitments
	proof.HalfPCommit = s.halfP.buildProof(g, challenge, commit.halfP)
	proof.PreaCommit = s.prea.buildProof(g, challenge, commit.prea)
	proof.ACommit = s.a.buildProof(g, challenge, commit.a)
	proof.AnegCommit = s.aneg.buildProof(g, challenge, commit.aneg)
	proof.AResCommit = s.aRes.buildProof(g, challenge, commit.aRes)
	proof.AnegResCommit = s.anegRes.buildProof(g, challenge, commit.anegRes)

	// Generate range proofs
	proof.PreaRangeProof = s.preaRange.buildProof(g, challenge, commit.preaRangeCommit, &secrets)
	proof.ARangeProof = s.aRange.buildProof(g, challenge, commit.aRangeCommit, &secrets)
	proof.AnegRangeProof = s.anegRange.buildProof(g, challenge, commit.anegRangeCommit, &secrets)
	proof.PreaModRangeProof = agenrange.buildProof(g, challenge, commit.preaModRangeCommit, &secrets)

	// And calculate our results
	proof.PreaMod = commit.preaMod.buildProof(g, challenge)
	proof.PreaHider = commit.preaHider.buildProof(g, challenge)

	if commit.aPositive {
		proof.APlus1Challenge = new(big.Int).Xor(challenge, commit.aInvalidChallenge)
		proof.APlus1 = commit.aValid.buildProof(g, proof.APlus1Challenge)
		proof.AMin1Challenge = commit.aInvalidChallenge
		proof.AMin1 = commit.aInvalid
	} else {
		proof.APlus1Challenge = commit.aInvalidChallenge
		proof.APlus1 = commit.aInvalid
		proof.AMin1Challenge = new(big.Int).Xor(challenge, commit.aInvalidChallenge)
		proof.AMin1 = commit.aValid.buildProof(g, proof.AMin1Challenge)
	}

	proof.AExpProof = s.aExp.buildProof(g, challenge, commit.aExpCommit, &secrets)
	proof.AnegExpProof = s.anegExp.buildProof(g, challenge, commit.anegExpCommit, &secrets)

	return proof
}

func (s *primeProofStructure) fakeProof(g zkproof.Group, challenge *big.Int) PrimeProof {
	var proof PrimeProof

	// Fake the pedersen proofs
	proof.HalfPCommit = s.halfP.fakeProof(g)
	proof.PreaCommit = s.prea.fakeProof(g)
	proof.ACommit = s.a.fakeProof(g)
	proof.AnegCommit = s.aneg.fakeProof(g)
	proof.AResCommit = s.aRes.fakeProof(g)
	proof.AnegResCommit = s.anegRes.fakeProof(g)

	// Build the fake proof structure for the preaMod rangeproof
	aAdd := common.GetHashNumber(proof.PreaCommit.Commit, nil, 0, s.bitlen)
	agenproof := zkproof.RepresentationProofStructure{
		Lhs: []zkproof.LhsContribution{
			{strings.Join([]string{s.myname, "prea"}, "_"), big.NewInt(1)},
			{"g", new(big.Int).Mod(aAdd, g.Order)},
			{strings.Join([]string{s.myname, "a"}, "_"), big.NewInt(-1)},
		},
		Rhs: []zkproof.RhsContribution{
			{s.primeName, strings.Join([]string{s.myname, "preamod"}, "_"), 1},
			{"h", strings.Join([]string{s.myname, "preahider"}, "_"), 1},
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
	proof.PreaMod = fakeProof(g)
	proof.PreaHider = fakeProof(g)
	proof.APlus1 = fakeProof(g)
	proof.AMin1 = fakeProof(g)
	proof.APlus1Challenge = common.FastRandomBigInt(new(big.Int).Lsh(big.NewInt(1), 256))
	proof.AMin1Challenge = new(big.Int).Xor(challenge, proof.APlus1Challenge)

	proof.AExpProof = s.aExp.fakeProof(g, challenge)
	proof.AnegExpProof = s.anegExp.fakeProof(g, challenge)

	return proof
}

func (s *primeProofStructure) verifyProofStructure(challenge *big.Int, proof PrimeProof) bool {
	// Check pedersen commitments
	if !s.halfP.verifyProofStructure(proof.HalfPCommit) ||
		!s.prea.verifyProofStructure(proof.PreaCommit) ||
		!s.a.verifyProofStructure(proof.ACommit) ||
		!s.aneg.verifyProofStructure(proof.AnegCommit) ||
		!s.aRes.verifyProofStructure(proof.AResCommit) ||
		!s.anegRes.verifyProofStructure(proof.AnegResCommit) {
		return false
	}

	// Build the proof structure for the preaMod rangeproof
	aAdd := common.GetHashNumber(proof.PreaCommit.Commit, nil, 0, s.bitlen)
	agenproof := zkproof.RepresentationProofStructure{
		Lhs: []zkproof.LhsContribution{
			{strings.Join([]string{s.myname, "prea"}, "_"), big.NewInt(1)},
			// LhsContribution{"g", new(big.Int).Mod(aAdd, g.order)},
			{"g", aAdd},
			{strings.Join([]string{s.myname, "a"}, "_"), big.NewInt(-1)},
		},
		Rhs: []zkproof.RhsContribution{
			{s.primeName, strings.Join([]string{s.myname, "preamod"}, "_"), 1},
			{"h", strings.Join([]string{s.myname, "preahider"}, "_"), 1},
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
	if !proof.PreaMod.verifyStructure() || !proof.PreaHider.verifyStructure() {
		return false
	}
	if !proof.APlus1.verifyStructure() || !proof.AMin1.verifyStructure() {
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

func (s *primeProofStructure) commitmentsFromProof(g zkproof.Group, list []*big.Int, challenge *big.Int, bases zkproof.BaseLookup, proofdata zkproof.ProofLookup, proof PrimeProof) []*big.Int {
	// Setup
	proof.PreaMod.setName(strings.Join([]string{s.myname, "preamod"}, "_"))
	proof.PreaHider.setName(strings.Join([]string{s.myname, "preahider"}, "_"))
	proof.APlus1.setName(strings.Join([]string{s.myname, "aresplus1hider"}, "_"))
	proof.AMin1.setName(strings.Join([]string{s.myname, "aresmin1hider"}, "_"))
	proof.HalfPCommit.setName(strings.Join([]string{s.myname, "halfp"}, "_"))
	proof.PreaCommit.setName(strings.Join([]string{s.myname, "prea"}, "_"))
	proof.ACommit.setName(strings.Join([]string{s.myname, "a"}, "_"))
	proof.AnegCommit.setName(strings.Join([]string{s.myname, "aneg"}, "_"))
	proof.AResCommit.setName(strings.Join([]string{s.myname, "ares"}, "_"))
	proof.AnegResCommit.setName(strings.Join([]string{s.myname, "anegres"}, "_"))

	// Build the proof structure for the preamod proofs
	aAdd := common.GetHashNumber(proof.PreaCommit.Commit, nil, 0, s.bitlen)
	agenproof := zkproof.RepresentationProofStructure{
		Lhs: []zkproof.LhsContribution{
			{strings.Join([]string{s.myname, "prea"}, "_"), big.NewInt(1)},
			{"g", new(big.Int).Mod(aAdd, g.Order)},
			{strings.Join([]string{s.myname, "a"}, "_"), big.NewInt(-1)},
		},
		Rhs: []zkproof.RhsContribution{
			{s.primeName, strings.Join([]string{s.myname, "preamod"}, "_"), 1},
			{"h", strings.Join([]string{s.myname, "preahider"}, "_"), 1},
		},
	}
	agenrange := rangeProofStructure{
		agenproof,
		strings.Join([]string{s.myname, "preamod"}, "_"),
		0,
		s.bitlen,
	}

	// inner bases
	innerBases := zkproof.NewBaseMerge(
		&proof.PreaCommit,
		&proof.ACommit,
		&proof.AnegCommit,
		&proof.AResCommit,
		&proof.AnegResCommit,
		&proof.HalfPCommit,
		bases)
	proofs := zkproof.NewProofMerge(
		&proof.PreaMod,
		&proof.PreaHider,
		&proof.AMin1,
		&proof.APlus1,
		&proof.ACommit,
		&proof.AnegCommit,
		&proof.AResCommit,
		&proof.AnegResCommit,
		&proof.HalfPCommit,
		proofdata)

	// Build all commitments
	list = s.prea.commitmentsFromProof(g, list, challenge, proof.PreaCommit)
	list = s.a.commitmentsFromProof(g, list, challenge, proof.ACommit)
	list = s.aneg.commitmentsFromProof(g, list, challenge, proof.AnegCommit)
	list = s.aRes.commitmentsFromProof(g, list, challenge, proof.AResCommit)
	list = s.anegRes.commitmentsFromProof(g, list, challenge, proof.AnegResCommit)
	list = s.halfP.commitmentsFromProof(g, list, challenge, proof.HalfPCommit)
	list = s.halfPRep.CommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.preaRange.commitmentsFromProof(g, list, challenge, &innerBases, proof.PreaRangeProof)
	list = s.aRange.commitmentsFromProof(g, list, challenge, &innerBases, proof.ARangeProof)
	list = s.anegRange.commitmentsFromProof(g, list, challenge, &innerBases, proof.AnegRangeProof)
	list = agenproof.CommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = agenrange.commitmentsFromProof(g, list, challenge, &innerBases, proof.PreaModRangeProof)
	list = s.anegResRep.CommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.aPlus1ResRep.CommitmentsFromProof(g, list, proof.APlus1Challenge, &innerBases, &proofs)
	list = s.aMin1ResRep.CommitmentsFromProof(g, list, proof.AMin1Challenge, &innerBases, &proofs)
	list = s.aExp.commitmentsFromProof(g, list, challenge, &innerBases, &proofs, proof.AExpProof)
	list = s.anegExp.commitmentsFromProof(g, list, challenge, &innerBases, &proofs, proof.AnegExpProof)

	return list
}

func (s *primeProofStructure) isTrue(secretdata zkproof.SecretLookup) bool {
	return secretdata.Secret(s.primeName).ProbablyPrime(40)
}

func (s *primeProofStructure) numRangeProofs() int {
	res := 4
	res += s.aExp.numRangeProofs()
	res += s.anegExp.numRangeProofs()
	return res
}

func (s *primeProofStructure) numCommitments() int {
	res := 0
	res += s.halfP.numCommitments()
	res += s.halfPRep.NumCommitments()
	res += s.prea.numCommitments()
	res += s.preaRange.numCommitments()
	res += s.a.numCommitments()
	res += s.aRange.numCommitments()
	res += s.aneg.numCommitments()
	res += s.anegRange.numCommitments()
	res += 1
	res += rangeProofIters
	res += s.aRes.numCommitments()
	res += s.anegRes.numCommitments()
	res += s.anegResRep.NumCommitments()
	res += s.aPlus1ResRep.NumCommitments()
	res += s.aMin1ResRep.NumCommitments()
	res += s.aExp.numCommitments()
	res += s.anegExp.numCommitments()
	return res
}
