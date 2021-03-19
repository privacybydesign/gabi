package keyproof

import (
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/privacybydesign/gabi/safeprime"
)

type (
	ValidKeyProofStructure struct {
		n          *big.Int
		p          pedersenStructure
		q          pedersenStructure
		pprime     pedersenStructure
		qprime     pedersenStructure
		pPprimeRel RepresentationProofStructure
		qQprimeRel RepresentationProofStructure
		pQNRel     RepresentationProofStructure

		pprimeIsPrime primeProofStructure
		qprimeIsPrime primeProofStructure

		basesValid isSquareProofStructure
	}

	ValidKeyProof struct {
		PProof      PedersenProof
		QProof      PedersenProof
		PprimeProof PedersenProof
		QprimeProof PedersenProof
		PQNRel      Proof
		Challenge   *big.Int
		GroupPrime  *big.Int

		PprimeIsPrimeProof PrimeProof
		QprimeIsPrimeProof PrimeProof

		QSPPproof QuasiSafePrimeProductProof

		BasesValidProof IsSquareProof
	}
)

func NewValidKeyProofStructure(N *big.Int, Bases []*big.Int) ValidKeyProofStructure {
	var structure ValidKeyProofStructure

	structure.n = new(big.Int).Set(N)
	structure.p = newPedersenStructure("p")
	structure.q = newPedersenStructure("q")
	structure.pprime = newPedersenStructure("pprime")
	structure.qprime = newPedersenStructure("qprime")

	structure.pPprimeRel = RepresentationProofStructure{
		[]LhsContribution{
			{"p", big.NewInt(1)},
			{"pprime", big.NewInt(-2)},
			{"g", big.NewInt(-1)},
		},
		[]RhsContribution{
			{"h", "p_hider", 1},
			{"h", "pprime_hider", -2},
		},
	}

	structure.qQprimeRel = RepresentationProofStructure{
		[]LhsContribution{
			{"q", big.NewInt(1)},
			{"qprime", big.NewInt(-2)},
			{"g", big.NewInt(-1)},
		},
		[]RhsContribution{
			{"h", "q_hider", 1},
			{"h", "qprime_hider", -2},
		},
	}

	structure.pQNRel = RepresentationProofStructure{
		[]LhsContribution{
			{"g", new(big.Int).Set(N)},
		},
		[]RhsContribution{
			{"p", "q", 1},
			{"h", "pqnrel", -1},
		},
	}

	structure.pprimeIsPrime = newPrimeProofStructure("pprime", uint((N.BitLen()+1)/2))
	structure.qprimeIsPrime = newPrimeProofStructure("qprime", uint((N.BitLen()+1)/2))

	structure.basesValid = newIsSquareProofStructure(N, Bases)

	return structure
}

func CanProve(Pprime *big.Int, Qprime *big.Int) bool {
	P := new(big.Int).Add(new(big.Int).Lsh(Pprime, 1), big.NewInt(1))
	Q := new(big.Int).Add(new(big.Int).Lsh(Qprime, 1), big.NewInt(1))
	if !safeprime.ProbablySafePrime(P, 80) || !safeprime.ProbablySafePrime(Q, 80) {
		return false
	}

	bigOne := big.NewInt(1)
	bigEight := big.NewInt(8)
	PMod := new(big.Int).Mod(P, bigEight)
	QMod := new(big.Int).Mod(Q, bigEight)
	PPrimeMod := new(big.Int).Mod(Pprime, bigEight)
	QPrimeMod := new(big.Int).Mod(Qprime, bigEight)

	return PMod.Cmp(bigOne) != 0 && QMod.Cmp(bigOne) != 0 &&
		PPrimeMod.Cmp(bigOne) != 0 && QPrimeMod.Cmp(bigOne) != 0 &&
		PMod.Cmp(QMod) != 0 && PPrimeMod.Cmp(QPrimeMod) != 0
}

func (s *ValidKeyProofStructure) BuildProof(Pprime *big.Int, Qprime *big.Int) ValidKeyProof {
	// Generate proof group
	Follower.StepStart("Generating group prime", 0)
	primeSize := s.n.BitLen() + 2*rangeProofEpsilon + 10

	GroupPrime := findSafePrime(primeSize)
	g, gok := buildGroup(GroupPrime)
	if !gok {
		panic("Safe prime generated by gabi was not a safe prime!?")
	}
	Follower.StepDone()

	Follower.StepStart("Generating commitments", s.numRangeProofs())

	// Build up some derived values
	P := new(big.Int).Add(new(big.Int).Lsh(Pprime, 1), big.NewInt(1))
	Q := new(big.Int).Add(new(big.Int).Lsh(Qprime, 1), big.NewInt(1))

	// Build up the secrets
	list, PprimeSecret := s.pprime.commitmentsFromSecrets(g, nil, Pprime)
	list, QprimeSecret := s.qprime.commitmentsFromSecrets(g, list, Qprime)
	list, PSecret := s.p.commitmentsFromSecrets(g, list, P)
	list, QSecret := s.q.commitmentsFromSecrets(g, list, Q)

	PQNRel := newSecret(g, "pqnrel", new(big.Int).Mod(new(big.Int).Mul(PSecret.hider.secretv, QSecret.secretv.secretv), g.order))

	// Build up bases and secrets structures
	bases := NewBaseMerge(&g, &PSecret, &QSecret, &PprimeSecret, &QprimeSecret)
	secrets := NewSecretMerge(&PSecret, &QSecret, &PprimeSecret, &QprimeSecret, &PQNRel)

	// Build up commitment list
	var PprimeIsPrimeCommit primeProofCommit
	var QprimeIsPrimeCommit primeProofCommit
	var QSPPcommit quasiSafePrimeProductCommit
	var BasesValidCommit isSquareProofCommit
	list = append(list, GroupPrime)
	list = append(list, s.n)
	list = s.pPprimeRel.commitmentsFromSecrets(g, list, &bases, &secrets)
	list = s.qQprimeRel.commitmentsFromSecrets(g, list, &bases, &secrets)
	list = s.pQNRel.commitmentsFromSecrets(g, list, &bases, &secrets)
	list, PprimeIsPrimeCommit = s.pprimeIsPrime.commitmentsFromSecrets(g, list, &bases, &secrets)
	list, QprimeIsPrimeCommit = s.qprimeIsPrime.commitmentsFromSecrets(g, list, &bases, &secrets)
	list, QSPPcommit = quasiSafePrimeProductBuildCommitments(list, Pprime, Qprime)
	list, BasesValidCommit = s.basesValid.commitmentsFromSecrets(g, list, P, Q)
	Follower.StepDone()

	Follower.StepStart("Generating proof", 0)
	// Calculate challenge
	challenge := common.HashCommit(list, false, false)

	// Calculate proofs
	proof := ValidKeyProof{
		GroupPrime:         GroupPrime,
		PQNRel:             PQNRel.buildProof(g, challenge),
		PProof:             s.p.buildProof(g, challenge, PSecret),
		QProof:             s.q.buildProof(g, challenge, QSecret),
		PprimeProof:        s.pprime.buildProof(g, challenge, PprimeSecret),
		QprimeProof:        s.qprime.buildProof(g, challenge, QprimeSecret),
		Challenge:          challenge,
		PprimeIsPrimeProof: s.pprimeIsPrime.buildProof(g, challenge, PprimeIsPrimeCommit, &secrets),
		QprimeIsPrimeProof: s.qprimeIsPrime.buildProof(g, challenge, QprimeIsPrimeCommit, &secrets),
		QSPPproof:          quasiSafePrimeProductBuildProof(Pprime, Qprime, challenge, QSPPcommit),
		BasesValidProof:    s.basesValid.buildProof(g, challenge, BasesValidCommit),
	}
	Follower.StepDone()

	return proof
}

func (s *ValidKeyProofStructure) VerifyProof(proof ValidKeyProof) bool {
	// Check proof structure
	Follower.StepStart("Verifying structure", 0)
	defer Follower.StepDone()
	if proof.GroupPrime == nil || proof.GroupPrime.BitLen() < s.n.BitLen()+2*rangeProofEpsilon+10 {
		return false
	}
	if !proof.GroupPrime.ProbablyPrime(80) || !new(big.Int).Rsh(proof.GroupPrime, 1).ProbablyPrime(80) {
		return false
	}
	if !proof.PQNRel.verifyStructure() || proof.Challenge == nil {
		return false
	}
	if !s.p.verifyProofStructure(proof.PProof) || !s.q.verifyProofStructure(proof.QProof) {
		return false
	}
	if !s.pprime.verifyProofStructure(proof.PprimeProof) || !s.qprime.verifyProofStructure(proof.QprimeProof) {
		return false
	}
	if !s.pprimeIsPrime.verifyProofStructure(proof.Challenge, proof.PprimeIsPrimeProof) ||
		!s.qprimeIsPrime.verifyProofStructure(proof.Challenge, proof.QprimeIsPrimeProof) {
		return false
	}
	if !quasiSafePrimeProductVerifyStructure(proof.QSPPproof) {
		return false
	}
	if !s.basesValid.verifyProofStructure(proof.BasesValidProof) {
		return false
	}
	Follower.StepDone()

	Follower.StepStart("Rebuilding commitments", s.numRangeProofs())

	// Rebuild group
	g, gok := buildGroup(proof.GroupPrime)
	if !gok {
		return false
	}

	// Setup names in the pedersen proofs
	proof.PProof.setName("p")
	proof.QProof.setName("q")
	proof.PprimeProof.setName("pprime")
	proof.QprimeProof.setName("qprime")
	proof.PQNRel.setName("pqnrel")

	// Build up bases and secrets
	bases := NewBaseMerge(&g, &proof.PProof, &proof.QProof, &proof.PprimeProof, &proof.QprimeProof)
	proofs := NewProofMerge(&proof.PProof, &proof.QProof, &proof.PprimeProof, &proof.QprimeProof, &proof.PQNRel)

	// Build up commitment list
	var list []*big.Int
	list = s.pprime.commitmentsFromProof(g, list, proof.Challenge, proof.PprimeProof)
	list = s.qprime.commitmentsFromProof(g, list, proof.Challenge, proof.QprimeProof)
	list = s.p.commitmentsFromProof(g, list, proof.Challenge, proof.PProof)
	list = s.q.commitmentsFromProof(g, list, proof.Challenge, proof.QProof)
	list = append(list, proof.GroupPrime)
	list = append(list, s.n)
	list = s.pPprimeRel.commitmentsFromProof(g, list, proof.Challenge, &bases, &proofs)
	list = s.qQprimeRel.commitmentsFromProof(g, list, proof.Challenge, &bases, &proofs)
	list = s.pQNRel.commitmentsFromProof(g, list, proof.Challenge, &bases, &proofs)
	list = s.pprimeIsPrime.commitmentsFromProof(g, list, proof.Challenge, &bases, &proofs, proof.PprimeIsPrimeProof)
	list = s.qprimeIsPrime.commitmentsFromProof(g, list, proof.Challenge, &bases, &proofs, proof.QprimeIsPrimeProof)
	list = quasiSafePrimeProductExtractCommitments(list, proof.QSPPproof)
	list = s.basesValid.commitmentsFromProof(g, list, proof.Challenge, proof.BasesValidProof)

	Follower.StepDone()

	Follower.StepStart("Verifying proof", 0)

	// Check challenge
	if proof.Challenge.Cmp(common.HashCommit(list, false, false)) != 0 {
		return false
	}

	// And the QSPP proof
	return quasiSafePrimeProductVerifyProof(s.n, proof.Challenge, proof.QSPPproof)
}

func (s *ValidKeyProofStructure) numRangeProofs() int {
	return s.pprimeIsPrime.numRangeProofs() + s.qprimeIsPrime.numRangeProofs() + s.basesValid.numRangeProofs()
}
