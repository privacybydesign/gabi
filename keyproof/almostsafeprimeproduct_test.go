package keyproof

import (
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlmostSafePrimeProductCycle(t *testing.T) {
	listBefore, commit := almostSafePrimeProductBuildCommitments([]*big.Int{}, testPPrime, testQPrime)
	proof := almostSafePrimeProductBuildProof(testPPrime, testQPrime, big.NewInt(12345), big.NewInt(3), commit)
	require.True(t, almostSafePrimeProductVerifyStructure(proof), "Proof structure rejected")

	listAfter := almostSafePrimeProductExtractCommitments([]*big.Int{}, proof)
	assert.True(t,
		almostSafePrimeProductVerifyProof(testN, big.NewInt(12345), big.NewInt(3), proof),
		"AlmostSafePrimeProduct rejected")
	assert.Equal(t, listBefore, listAfter, "Difference between commitments")
}

func TestAlmostSafePrimeProductCycleIncorrectNonce(t *testing.T) {
	_, commit := almostSafePrimeProductBuildCommitments([]*big.Int{}, testPPrime, testQPrime)
	proof := almostSafePrimeProductBuildProof(testPPrime, testQPrime, big.NewInt(12345), big.NewInt(3), commit)
	proof.Nonce.Sub(proof.Nonce, big.NewInt(1))
	assert.False(t,
		almostSafePrimeProductVerifyProof(testN, big.NewInt(12345), big.NewInt(3), proof),
		"Incorrect AlmostSafePrimeProductProof accepted.")
}

func TestAlmostSafePrimeProductCycleIncorrectCommitment(t *testing.T) {
	_, commit := almostSafePrimeProductBuildCommitments([]*big.Int{}, testPPrime, testQPrime)
	proof := almostSafePrimeProductBuildProof(testPPrime, testQPrime, big.NewInt(12345), big.NewInt(3), commit)
	proof.Commitments[0].Add(proof.Commitments[0], big.NewInt(1))
	assert.False(t,
		almostSafePrimeProductVerifyProof(testN, big.NewInt(12345), big.NewInt(3), proof),
		"Incorrect AlmostSafePrimeProductProof accepted.")
}

func TestAlmostSafePrimeProductCycleIncorrectResponse(t *testing.T) {
	_, commit := almostSafePrimeProductBuildCommitments([]*big.Int{}, testPPrime, testQPrime)
	proof := almostSafePrimeProductBuildProof(testPPrime, testQPrime, big.NewInt(12345), big.NewInt(3), commit)
	proof.Responses[0].Add(proof.Responses[0], big.NewInt(1))
	assert.False(t,
		almostSafePrimeProductVerifyProof(testN, big.NewInt(12345), big.NewInt(3), proof),
		"Incorrect AlmostSafePrimeProductProof accepted.")
}

func TestAlmostSafePrimeProductVerifyStructure(t *testing.T) {
	_, commit := almostSafePrimeProductBuildCommitments([]*big.Int{}, testPPrime, testQPrime)
	proof := almostSafePrimeProductBuildProof(testPPrime, testQPrime, big.NewInt(12345), big.NewInt(3), commit)

	listBackup := proof.Commitments
	proof.Commitments = proof.Commitments[:len(proof.Commitments)-1]
	assert.False(t, almostSafePrimeProductVerifyStructure(proof), "Accepiting too short commitments")
	proof.Commitments = listBackup

	listBackup = proof.Responses
	proof.Responses = proof.Responses[:len(proof.Responses)-1]
	assert.False(t, almostSafePrimeProductVerifyStructure(proof), "Accepting too short responses")
	proof.Responses = listBackup

	valBackup := proof.Commitments[2]
	proof.Commitments[2] = nil
	assert.False(t, almostSafePrimeProductVerifyStructure(proof), "Accepting missing commitment")
	proof.Commitments[2] = valBackup

	valBackup = proof.Responses[3]
	proof.Responses[3] = nil
	assert.False(t, almostSafePrimeProductVerifyStructure(proof), "Accepting missing response")
	proof.Responses[3] = valBackup

	valBackup = proof.Nonce
	proof.Nonce = nil
	assert.False(t, almostSafePrimeProductVerifyStructure(proof), "Accepting missing nonce")
	proof.Nonce = valBackup

	assert.True(t, almostSafePrimeProductVerifyStructure(proof), "Testing messed up testdata")
}
