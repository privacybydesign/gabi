package keyproof

import (
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/assert"
)

func TestSquareFreeCycle(t *testing.T) {
	const p = 1031
	const q = 1063
	proof := squareFreeBuildProof(big.NewInt(int64(p*q)), big.NewInt(int64((p-1)*(q-1))), big.NewInt(12345), big.NewInt(0))
	assert.True(t, squareFreeVerifyStructure(proof), "proof structure rejected")
	ok := squareFreeVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(0), proof)
	assert.True(t, ok, "SquareFreeProof rejected.")
}

func TestSquareFreeCycleIncorrect(t *testing.T) {
	const p = 1031
	const q = 1063
	proof := squareFreeBuildProof(big.NewInt(int64(p*q)), big.NewInt(int64((p-1)*(q-1))), big.NewInt(12345), big.NewInt(0))
	proof.Responses[0].Add(proof.Responses[0], big.NewInt(1))
	ok := squareFreeVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(0), proof)
	assert.False(t, ok, "Incorrect SquareFreeProof accepted.")
}

func TestSquareFreeCycleWrongChallenge(t *testing.T) {
	const p = 1031
	const q = 1063
	proof := squareFreeBuildProof(big.NewInt(int64(p*q)), big.NewInt(int64((p-1)*(q-1))), big.NewInt(12345), big.NewInt(0))
	ok := squareFreeVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12346), big.NewInt(0), proof)
	assert.False(t, ok, "Incorrect SquareFreeProof accepted.")
}

func TestSquareFreeCycleWrongIndex(t *testing.T) {
	const p = 1031
	const q = 1063
	proof := squareFreeBuildProof(big.NewInt(int64(p*q)), big.NewInt(int64((p-1)*(q-1))), big.NewInt(12345), big.NewInt(0))
	ok := squareFreeVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(1), proof)
	assert.False(t, ok, "Incorrect SquareFreeProof accepted.")
}

func TestSquareFreeVerifyStructure(t *testing.T) {
	const p = 1031
	const q = 1063
	proof := squareFreeBuildProof(big.NewInt(int64(p*q)), big.NewInt(int64((p-1)*(q-1))), big.NewInt(12345), big.NewInt(0))

	listBackup := proof.Responses
	proof.Responses = proof.Responses[:len(proof.Responses)-1]
	assert.False(t, squareFreeVerifyStructure(proof), "Accepting too short responses")
	proof.Responses = listBackup

	valBackup := proof.Responses[2]
	proof.Responses[2] = nil
	assert.False(t, squareFreeVerifyStructure(proof), "Accepting missing response")
	proof.Responses[2] = valBackup

	assert.True(t, squareFreeVerifyStructure(proof), "testcase corrupted testdata")
}
