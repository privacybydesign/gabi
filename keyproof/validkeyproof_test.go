package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/assert"
)

func TestValidKeyProof(t *testing.T) {
	const p = 26903
	const q = 27803
	const a = 36
	const b = 49
	const c = 64

	Follower.(*TestFollower).count = 0

	s := NewValidKeyProofStructure(big.NewInt(p*q), big.NewInt(a), big.NewInt(b), []*big.Int{big.NewInt(c)})
	proof := s.BuildProof(big.NewInt((p-1)/2), big.NewInt((q-1)/2))

	assert.Equal(t, Follower.(*TestFollower).count, s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	Follower.(*TestFollower).count = 0

	ok := s.VerifyProof(proof)

	assert.Equal(t, Follower.(*TestFollower).count, s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	assert.True(t, ok, "Proof rejected.")
}

func TestValidKeyProofStructure(t *testing.T) {
	const p = 26903
	const q = 27803
	const a = 36
	const b = 49
	const c = 64

	s := NewValidKeyProofStructure(big.NewInt(p*q), big.NewInt(a), big.NewInt(b), []*big.Int{big.NewInt(c)})
	proof := s.BuildProof(big.NewInt((p-1)/2), big.NewInt((q-1)/2))

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
}

func TestValidKeyProofJSON(t *testing.T) {
	const p = 26903
	const q = 27803
	const a = 36
	const b = 49
	const c = 64

	s := NewValidKeyProofStructure(big.NewInt(p*q), big.NewInt(a), big.NewInt(b), []*big.Int{big.NewInt(c)})
	proofBefore := s.BuildProof(big.NewInt((p-1)/2), big.NewInt((q-1)/2))
	proofJSON, err := json.Marshal(proofBefore)
	assert.NoError(t, err, "error during json marshal")

	var proofAfter ValidKeyProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	assert.NoError(t, err, "error during json unmarshal")

	assert.True(t, s.VerifyProof(proofAfter), "Proof rejected.")
}
