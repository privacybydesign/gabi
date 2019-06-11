package keyproof

import "testing"
import "encoding/json"
import "github.com/privacybydesign/gabi/internal/common"
import "github.com/privacybydesign/gabi/big"

func TestQuasiSafePrimeProductCycle(t *testing.T) {
	const p = 13451
	const q = 13901
	listBefore, commit := quasiSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := quasiSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), commit)
	if !quasiSafePrimeProductVerifyStructure(proof) {
		t.Error("Proof structure rejected")
	}
	listAfter := quasiSafePrimeProductExtractCommitments([]*big.Int{}, proof)
	ok := quasiSafePrimeProductVerifyProof(big.NewInt((2*p+1)*(2*q+1)), big.NewInt(12345), proof)
	if !ok {
		t.Error("QuasiSafePrimeProduct rejected")
	}
	if len(listBefore) != len(listAfter) {
		t.Error("Difference between commitment contribution lengths")
	}
	for i, ref := range listBefore {
		if ref.Cmp(listAfter[i]) != 0 {
			t.Errorf("Difference between commitment %v\n", i)
		}
	}
}

func TestQuasiSafePrimeProductFullCycle(t *testing.T) {
	// Build proof
	const p = 13451
	const q = 13901
	listBefore, commit := quasiSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	challengeBefore := common.HashCommit(listBefore, false)
	proofBefore := quasiSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), challengeBefore, commit)
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Error(err.Error())
		return
	}

	// Validate proof json
	var proofAfter QuasiSafePrimeProductProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Error(err.Error())
		return
	}
	listAfter := quasiSafePrimeProductExtractCommitments([]*big.Int{}, proofAfter)
	challengeAfter := common.HashCommit(listAfter, false)
	ok := quasiSafePrimeProductVerifyProof(big.NewInt((2*p+1)*(2*q+1)), challengeAfter, proofAfter)
	if !ok {
		t.Error("JSON proof rejected")
	}
}

func TestQuasiSafePrimeProductVerifyStructure(t *testing.T) {
	const p = 13451
	const q = 13901
	_, commit := quasiSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := quasiSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), commit)

	valBackup := proof.SFproof.Responses[2]
	proof.SFproof.Responses[2] = nil
	if quasiSafePrimeProductVerifyStructure(proof) {
		t.Error("Accepting corrupted sfproof")
	}
	proof.SFproof.Responses[2] = valBackup

	valBackup = proof.PPPproof.Responses[2]
	proof.PPPproof.Responses[2] = nil
	if quasiSafePrimeProductVerifyStructure(proof) {
		t.Error("Accepting corrupted pppproof")
	}
	proof.PPPproof.Responses[2] = valBackup

	valBackup = proof.DPPproof.Responses[2]
	proof.DPPproof.Responses[2] = nil
	if quasiSafePrimeProductVerifyStructure(proof) {
		t.Error("Accepting corrupted dppproof")
	}
	proof.DPPproof.Responses[2] = valBackup

	valBackup = proof.ASPPproof.Responses[2]
	proof.ASPPproof.Responses[2] = nil
	if quasiSafePrimeProductVerifyStructure(proof) {
		t.Error("Accepting corrupted asppproof")
	}
	proof.ASPPproof.Responses[2] = valBackup

	if !quasiSafePrimeProductVerifyStructure(proof) {
		t.Error("testcase corrupted testdata")
	}
}
