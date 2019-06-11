package keyproof

import "testing"
import "github.com/privacybydesign/gabi/big"

func TestDisjointPrimeProductCycle(t *testing.T) {
	const p = 2063
	const q = 1187
	proof := disjointPrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(2))
	if !disjointPrimeProductVerifyStructure(proof) {
		t.Error("Proof structure rejected")
		return
	}
	ok := disjointPrimeProductVerifyProof(big.NewInt(p*q), big.NewInt(12345), big.NewInt(2), proof)
	if !ok {
		t.Error("DisjointPrimeProductProof rejected.")
	}
}

func TestDisjointPrimeProductCycleIncorrect(t *testing.T) {
	const p = 2063
	const q = 1187
	proof := disjointPrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(2))
	proof.Responses[0].Add(proof.Responses[0], big.NewInt(1))
	ok := disjointPrimeProductVerifyProof(big.NewInt(p*q), big.NewInt(12345), big.NewInt(2), proof)
	if ok {
		t.Error("Incorrect DisjointPrimeProductProof accepted.")
	}
}

func TestDisjointPrimeProductWrongChallenge(t *testing.T) {
	const p = 2063
	const q = 1187
	proof := disjointPrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(2))
	ok := disjointPrimeProductVerifyProof(big.NewInt(p*q), big.NewInt(12346), big.NewInt(2), proof)
	if ok {
		t.Error("Incorrect DisjointPrimeProductProof accepted.")
	}
}

func TestDisjointPrimeProductWrongIndex(t *testing.T) {
	const p = 2063
	const q = 1187
	proof := disjointPrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(2))
	ok := disjointPrimeProductVerifyProof(big.NewInt(p*q), big.NewInt(12345), big.NewInt(3), proof)
	if ok {
		t.Error("Incorrect DisjointPrimeProductProof accepted.")
	}
}

func TestDisjointPrimeProductVerifyStructure(t *testing.T) {
	const p = 2063
	const q = 1187
	proof := disjointPrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), big.NewInt(2))

	listBackup := proof.Responses
	proof.Responses = proof.Responses[:len(proof.Responses)-1]
	if disjointPrimeProductVerifyStructure(proof) {
		t.Error("Accepting too short responses")
	}
	proof.Responses = listBackup

	valBackup := proof.Responses[2]
	proof.Responses[2] = nil
	if disjointPrimeProductVerifyStructure(proof) {
		t.Error("Accepting missing response")
	}
	proof.Responses[2] = valBackup

	if !disjointPrimeProductVerifyStructure(proof) {
		t.Error("Testcase corrupted testdata")
	}
}
