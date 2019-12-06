package keyproof

import (
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDisjointPrimeProductCycle(t *testing.T) {
	const p = 2063
	const q = 1187
	proof := disjointPrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(2))
	require.True(t, disjointPrimeProductVerifyStructure(proof), "Proof structure rejected")
	assert.True(t,
		disjointPrimeProductVerifyProof(big.NewInt(p*q), big.NewInt(12345), big.NewInt(2), proof),
		"DisjointPrimeProductProof rejected.")
}

func TestDisjointPrimeProductCycleIncorrect(t *testing.T) {
	const p = 2063
	const q = 1187
	proof := disjointPrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(2))
	proof.Responses[0].Add(proof.Responses[0], big.NewInt(1))
	assert.False(t,
		disjointPrimeProductVerifyProof(big.NewInt(p*q), big.NewInt(12345), big.NewInt(2), proof),
		"Incorrect DisjointPrimeProductProof accepted.")
}

func TestDisjointPrimeProductWrongChallenge(t *testing.T) {
	const p = 2063
	const q = 1187
	proof := disjointPrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(2))
	assert.False(t,
		disjointPrimeProductVerifyProof(big.NewInt(p*q), big.NewInt(12346), big.NewInt(2), proof),
		"Incorrect DisjointPrimeProductProof accepted.")
}

func TestDisjointPrimeProductWrongIndex(t *testing.T) {
	const p = 2063
	const q = 1187
	proof := disjointPrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(2))
	assert.False(t,
		disjointPrimeProductVerifyProof(big.NewInt(p*q), big.NewInt(12345), big.NewInt(3), proof),
		"Incorrect DisjointPrimeProductProof accepted.")
}

func TestDisjointPrimeProductVerifyStructure(t *testing.T) {
	const p = 2063
	const q = 1187
	proof := disjointPrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(2))

	listBackup := proof.Responses
	proof.Responses = proof.Responses[:len(proof.Responses)-1]
	assert.False(t, disjointPrimeProductVerifyStructure(proof), "Accepting too short responses")
	proof.Responses = listBackup

	valBackup := proof.Responses[2]
	proof.Responses[2] = nil
	assert.False(t, disjointPrimeProductVerifyStructure(proof), "Accepting missing response")
	proof.Responses[2] = valBackup

	assert.True(t, disjointPrimeProductVerifyStructure(proof), "Testcase corrupted testdata")
}
