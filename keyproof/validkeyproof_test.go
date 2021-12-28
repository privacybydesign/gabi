package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/safeprime"
	"github.com/stretchr/testify/assert"
)

// (Safe) primes to use in tests. Generating these takes a while, so we generate them once
// and then reuse them across all tests.
var testP, testQ, testPPrime, testQPrime, testN *big.Int

// We take our test primes to be this big. This size (1) avoids some degenerate cases (e.g.
// accidentally factoring the modulus n or hitting 0 in Z/nZ) with sufficient probability that they
// shouldn't occur when executing the tests, and (2) achieves reasonable execution times for the
// tests.
const testPrimeSize = 64

func init() {
	var err error
	var ok bool
	for !ok {
		testP, err = safeprime.Generate(testPrimeSize, nil)
		if err != nil {
			panic(err)
		}
		testQ, err = safeprime.Generate(testPrimeSize, nil)
		if err != nil {
			panic(err)
		}
		testPPrime = new(big.Int).Rsh(testP, 1)
		testQPrime = new(big.Int).Rsh(testQ, 1)
		ok = CanProve(testPPrime, testQPrime)
	}

	testN = new(big.Int).Mul(testP, testQ)
}

func TestValidKeyProof(t *testing.T) {
	const a = 36
	const b = 49
	const c = 64

	Follower.(*TestFollower).count = 0

	// Generate a proof once and then reuse it across subtests to save time
	s := NewValidKeyProofStructure(testN, []*big.Int{big.NewInt(a), big.NewInt(b), big.NewInt(c)})
	proof := s.BuildProof(testPPrime, testQPrime)

	t.Run("Valid", func(t *testing.T) {
		assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
		Follower.(*TestFollower).count = 0

		ok := s.VerifyProof(proof)

		assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
		assert.True(t, ok, "Proof rejected.")
	})

	t.Run("Structure", func(t *testing.T) {
		backup := proof.GroupPrime
		proof.GroupPrime = nil
		assert.False(t, s.VerifyProof(proof), "Accepting missing group prime")

		proof.GroupPrime = big.NewInt(10009)
		assert.False(t, s.VerifyProof(proof), "Accepting non-safe prime as group prime")

		proof.GroupPrime = big.NewInt(20015)
		assert.False(t, s.VerifyProof(proof), "Accepting non-prime as group prime")
		proof.GroupPrime = backup

		backup = proof.PProof.Commit
		proof.PProof.Commit = nil
		assert.False(t, s.VerifyProof(proof), "Accepting corrupted PProof")
		proof.PProof.Commit = backup

		backup = proof.QProof.Commit
		proof.QProof.Commit = nil
		assert.False(t, s.VerifyProof(proof), "Accepting corrupted QProof")
		proof.QProof.Commit = backup

		backup = proof.PprimeProof.Commit
		proof.PprimeProof.Commit = nil
		assert.False(t, s.VerifyProof(proof), "Accepting corrupted PprimeProof")
		proof.PprimeProof.Commit = backup

		backup = proof.QprimeProof.Commit
		proof.QprimeProof.Commit = nil
		assert.False(t, s.VerifyProof(proof), "Accepting corrupted QprimeProof")
		proof.QprimeProof.Commit = backup

		backup = proof.PQNRel.Result
		proof.PQNRel.Result = nil
		assert.False(t, s.VerifyProof(proof), "Accepting corrupted pqnrel")
		proof.PQNRel.Result = backup

		backup = proof.Challenge
		proof.Challenge = nil
		assert.False(t, s.VerifyProof(proof), "Accepting missing challenge")

		proof.Challenge = big.NewInt(1)
		assert.False(t, s.VerifyProof(proof), "Accepting incorrect challenge")
		proof.Challenge = backup

		backup = proof.PprimeIsPrimeProof.PreaMod.Result
		proof.PprimeIsPrimeProof.PreaMod.Result = nil
		assert.False(t, s.VerifyProof(proof), "Accepting corrupted pprimeisprimeproof")
		proof.PprimeIsPrimeProof.PreaMod.Result = backup

		backup = proof.QprimeIsPrimeProof.PreaMod.Result
		proof.QprimeIsPrimeProof.PreaMod.Result = nil
		assert.False(t, s.VerifyProof(proof), "Accepting corrupted qprimeisprimeproof")
		proof.QprimeIsPrimeProof.PreaMod.Result = backup

		backup = proof.QSPPproof.PPPproof.Responses[2]
		proof.QSPPproof.PPPproof.Responses[2] = nil
		assert.False(t, s.VerifyProof(proof), "Accepting corrupted QSPPproof")
		proof.QSPPproof.PPPproof.Responses[2] = backup

		backup = proof.BasesValidProof.NProof.Commit
		proof.BasesValidProof.NProof.Commit = nil
		assert.False(t, s.VerifyProof(proof), "Accepting corrupted BasesValidProof")
		proof.BasesValidProof.NProof.Commit = backup

		assert.True(t, s.VerifyProof(proof), "Testing corrupted proof structure!")
	})

	t.Run("JSON", func(t *testing.T) {
		proofJSON, err := json.Marshal(proof)
		assert.NoError(t, err, "error during json marshal")

		var proofAfter ValidKeyProof
		err = json.Unmarshal(proofJSON, &proofAfter)
		assert.NoError(t, err, "error during json unmarshal")

		assert.True(t, s.VerifyProof(proofAfter), "Proof rejected.")
	})
}
