package keyproof

import "testing"
import "github.com/privacybydesign/gabi/big"

func TestPrimePowerProductCycle(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := primePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))
	if !primePowerProductVerifyStructure(proof) {
		t.Error("Proof structure rejected")
		return
	}
	ok := primePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(1), proof)
	if !ok {
		t.Error("PrimePowerProductProof rejected")
	}
}

func TestPrimePowerProductCycleIncorrect(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := primePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))
	proof.Responses[0].Add(proof.Responses[0], big.NewInt(1))
	ok := primePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(1), proof)
	if ok {
		t.Error("Incorrect PrimePowerProductProof accepted")
	}
}

func TestPrimePowerProductCycleWrongChallenge(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := primePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))
	ok := primePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12346), big.NewInt(1), proof)
	if ok {
		t.Error("Incorrect PrimePowerProductProof accepted")
	}
}

func TestPrimePowerProductCycleWrongIndex(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := primePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))
	ok := primePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(2), proof)
	if ok {
		t.Error("Incorrect PrimePowerProductProof accepted")
	}
}

func TestPrimePowerProductVerifyStructure(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := primePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))

	listBackup := proof.Responses
	proof.Responses = proof.Responses[:len(proof.Responses)-1]
	if primePowerProductVerifyStructure(proof) {
		t.Error("Accepting too short responses")
	}
	proof.Responses = listBackup

	valBackup := proof.Responses[2]
	proof.Responses[2] = nil
	if primePowerProductVerifyStructure(proof) {
		t.Error("Accepting missing response")
	}
	proof.Responses[2] = valBackup

	if !primePowerProductVerifyStructure(proof) {
		t.Error("testcase corrupted testdata")
	}
}
