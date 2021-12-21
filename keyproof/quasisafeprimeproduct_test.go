package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/stretchr/testify/assert"
)

func TestQuasiSafePrimeProductCycle(t *testing.T) {
	listBefore, commit := quasiSafePrimeProductBuildCommitments([]*big.Int{}, testPPrime, testQPrime)
	proof := quasiSafePrimeProductBuildProof(testPPrime, testQPrime, big.NewInt(12345), commit)
	assert.True(t, quasiSafePrimeProductVerifyStructure(proof), "Proof structure rejected")
	listAfter := quasiSafePrimeProductExtractCommitments([]*big.Int{}, proof)
	ok := quasiSafePrimeProductVerifyProof(testN, big.NewInt(12345), proof)
	assert.True(t, ok, "QuasiSafePrimeProduct rejected")
	assert.Equal(t, listBefore, listAfter, "Difference between commitment lists")
}

func TestQuasiSafePrimeProductFullCycle(t *testing.T) {
	// Build proof
	listBefore, commit := quasiSafePrimeProductBuildCommitments([]*big.Int{}, testPPrime, testQPrime)
	challengeBefore := common.HashCommit(listBefore, false)
	proofBefore := quasiSafePrimeProductBuildProof(testPPrime, testQPrime, challengeBefore, commit)
	proofJSON, err := json.Marshal(proofBefore)
	require.NoError(t, err, "error during json marshal")

	// Validate proof json
	var proofAfter QuasiSafePrimeProductProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	require.NoError(t, err, "error during json unmarshal")
	listAfter := quasiSafePrimeProductExtractCommitments([]*big.Int{}, proofAfter)
	challengeAfter := common.HashCommit(listAfter, false)
	ok := quasiSafePrimeProductVerifyProof(testN, challengeAfter, proofAfter)
	assert.True(t, ok, "JSON proof rejected")
}

func TestQuasiSafePrimeProductVerifyStructure(t *testing.T) {
	_, commit := quasiSafePrimeProductBuildCommitments([]*big.Int{}, testPPrime, testQPrime)
	proof := quasiSafePrimeProductBuildProof(testPPrime, testQPrime, big.NewInt(12345), commit)

	valBackup := proof.SFproof.Responses[2]
	proof.SFproof.Responses[2] = nil
	assert.False(t, quasiSafePrimeProductVerifyStructure(proof), "Accepting corrupted sfproof")
	proof.SFproof.Responses[2] = valBackup

	valBackup = proof.PPPproof.Responses[2]
	proof.PPPproof.Responses[2] = nil
	assert.False(t, quasiSafePrimeProductVerifyStructure(proof), "Accepting corrupted pppproof")
	proof.PPPproof.Responses[2] = valBackup

	valBackup = proof.DPPproof.Responses[2]
	proof.DPPproof.Responses[2] = nil
	assert.False(t, quasiSafePrimeProductVerifyStructure(proof), "Accepting corrupted dppproof")
	proof.DPPproof.Responses[2] = valBackup

	valBackup = proof.ASPPproof.Responses[2]
	proof.ASPPproof.Responses[2] = nil
	assert.False(t, quasiSafePrimeProductVerifyStructure(proof), "Accepting corrupted asppproof")
	proof.ASPPproof.Responses[2] = valBackup

	assert.True(t, quasiSafePrimeProductVerifyStructure(proof), "testcase corrupted testdata")
}
