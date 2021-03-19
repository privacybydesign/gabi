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
	const p = 13451
	const q = 13901
	listBefore, commit := quasiSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := quasiSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), commit)
	assert.True(t, quasiSafePrimeProductVerifyStructure(proof), "Proof structure rejected")
	listAfter := quasiSafePrimeProductExtractCommitments([]*big.Int{}, proof)
	ok := quasiSafePrimeProductVerifyProof(big.NewInt((2*p+1)*(2*q+1)), big.NewInt(12345), proof)
	assert.True(t, ok, "QuasiSafePrimeProduct rejected")
	assert.Equal(t, listBefore, listAfter, "Difference between commitment lists")
}

func TestQuasiSafePrimeProductFullCycle(t *testing.T) {
	// Build proof
	const p = 13451
	const q = 13901
	listBefore, commit := quasiSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	challengeBefore := common.HashCommit(listBefore, false, false)
	proofBefore := quasiSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), challengeBefore, commit)
	proofJSON, err := json.Marshal(proofBefore)
	require.NoError(t, err, "error during json marshal")

	// Validate proof json
	var proofAfter QuasiSafePrimeProductProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	require.NoError(t, err, "error during json unmarshal")
	listAfter := quasiSafePrimeProductExtractCommitments([]*big.Int{}, proofAfter)
	challengeAfter := common.HashCommit(listAfter, false, false)
	ok := quasiSafePrimeProductVerifyProof(big.NewInt((2*p+1)*(2*q+1)), challengeAfter, proofAfter)
	assert.True(t, ok, "JSON proof rejected")
}

func TestQuasiSafePrimeProductVerifyStructure(t *testing.T) {
	const p = 13451
	const q = 13901
	_, commit := quasiSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := quasiSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), commit)

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
