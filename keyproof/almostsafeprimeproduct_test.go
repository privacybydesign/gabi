package keyproof

import "testing"
import "github.com/privacybydesign/gabi/big"

func TestAlmostSafePrimeProductCycle(t *testing.T) {
	const p = 13451
	const q = 13901
	listBefore, commit := almostSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := almostSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(3), commit)
	if !almostSafePrimeProductVerifyStructure(proof) {
		t.Error("Proof structure rejected")
		return
	}
	listAfter := almostSafePrimeProductExtractCommitments([]*big.Int{}, proof)
	ok := almostSafePrimeProductVerifyProof(big.NewInt((2*p+1)*(2*q+1)), big.NewInt(12345), big.NewInt(3), proof)
	if !ok {
		t.Error("AlmostSafePrimeProduct rejected")
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

func TestAlmostSafePrimeProductCycleIncorrectNonce(t *testing.T) {
	const p = 13451
	const q = 13901
	_, commit := almostSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := almostSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(3), commit)
	proof.Nonce.Sub(proof.Nonce, big.NewInt(1))
	ok := almostSafePrimeProductVerifyProof(big.NewInt((2*p+1)*(2*q+1)), big.NewInt(12345), big.NewInt(3), proof)
	if ok {
		t.Error("Incorrect AlmostSafePrimeProductProof accepted.")
	}
}

func TestAlmostSafePrimeProductCycleIncorrectCommitment(t *testing.T) {
	const p = 13451
	const q = 13901
	_, commit := almostSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := almostSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(3), commit)
	proof.Commitments[0].Add(proof.Commitments[0], big.NewInt(1))
	ok := almostSafePrimeProductVerifyProof(big.NewInt((2*p+1)*(2*q+1)), big.NewInt(12345), big.NewInt(3), proof)
	if ok {
		t.Error("Incorrect AlmostSafePrimeProductProof accepted.")
	}
}

func TestAlmostSafePrimeProductCycleIncorrectResponse(t *testing.T) {
	const p = 13451
	const q = 13901
	_, commit := almostSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := almostSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(3), commit)
	proof.Responses[0].Add(proof.Responses[0], big.NewInt(1))
	ok := almostSafePrimeProductVerifyProof(big.NewInt((2*p+1)*(2*q+1)), big.NewInt(12345), big.NewInt(3), proof)
	if ok {
		t.Error("Incorrect AlmostSafePrimeProductProof accepted.")
	}
}

func TestAlmostSafePrimeProductVerifyStructure(t *testing.T) {
	const p = 13451
	const q = 13901
	_, commit := almostSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := almostSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(3), commit)

	listBackup := proof.Commitments
	proof.Commitments = proof.Commitments[:len(proof.Commitments)-1]
	if almostSafePrimeProductVerifyStructure(proof) {
		t.Error("Accepiting too short commitments")
	}
	proof.Commitments = listBackup

	listBackup = proof.Responses
	proof.Responses = proof.Responses[:len(proof.Responses)-1]
	if almostSafePrimeProductVerifyStructure(proof) {
		t.Error("Accepting too short responses")
	}
	proof.Responses = listBackup

	valBackup := proof.Commitments[2]
	proof.Commitments[2] = nil
	if almostSafePrimeProductVerifyStructure(proof) {
		t.Error("Accepting missing commitment")
	}
	proof.Commitments[2] = valBackup

	valBackup = proof.Responses[3]
	proof.Responses[3] = nil
	if almostSafePrimeProductVerifyStructure(proof) {
		t.Error("Accepting missing response")
	}
	proof.Responses[3] = valBackup

	valBackup = proof.Nonce
	proof.Nonce = nil
	if almostSafePrimeProductVerifyStructure(proof) {
		t.Error("Accepting missing nonce")
	}
	proof.Nonce = valBackup

	if !almostSafePrimeProductVerifyStructure(proof) {
		t.Error("Testing messed up testdata")
	}
}
