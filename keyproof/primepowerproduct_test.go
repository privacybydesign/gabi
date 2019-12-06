package keyproof

import (
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrimePowerProductCycle(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := primePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))
	require.True(t, primePowerProductVerifyStructure(proof), "Proof structure rejected")
	ok := primePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(1), proof)
	assert.True(t, ok, "PrimePowerProductProof rejected")
}

func TestPrimePowerProductCycleIncorrect(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := primePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))
	proof.Responses[0].Add(proof.Responses[0], big.NewInt(1))
	ok := primePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(1), proof)
	assert.False(t, ok, "Incorrect PrimePowerProductProof accepted")
}

func TestPrimePowerProductCycleWrongChallenge(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := primePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))
	ok := primePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12346), big.NewInt(1), proof)
	assert.False(t, ok, "Incorrect PrimePowerProductProof accepted")
}

func TestPrimePowerProductCycleWrongIndex(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := primePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))
	ok := primePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(2), proof)
	assert.False(t, ok, "Incorrect PrimePowerProductProof accepted")
}

func TestPrimePowerProductVerifyStructure(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := primePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))

	listBackup := proof.Responses
	proof.Responses = proof.Responses[:len(proof.Responses)-1]
	assert.False(t, primePowerProductVerifyStructure(proof), "Accepting too short responses")
	proof.Responses = listBackup

	valBackup := proof.Responses[2]
	proof.Responses[2] = nil
	assert.False(t, primePowerProductVerifyStructure(proof), "Accepting missing response")
	proof.Responses[2] = valBackup

	assert.True(t, primePowerProductVerifyStructure(proof), "testcase corrupted testdata")
}
