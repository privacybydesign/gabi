package keyproof

import "testing"
import "encoding/json"
import "github.com/privacybydesign/gabi/big"

func TestValidKeyProof(t *testing.T) {
	const p = 26903
	const q = 27803
	const a = 36
	const b = 49
	const c = 64

	Follower.(*TestFollower).count = 0

	s := NewValidKeyProofStructure(big.NewInt(p*q), big.NewInt(a), big.NewInt(b), []*big.Int{big.NewInt(c)})
	proof := s.BuildProof(big.NewInt((p-1)/2), big.NewInt((q-1)/2))

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off GenerateCommitmentsFromSecrets")
	}
	Follower.(*TestFollower).count = 0

	ok := s.VerifyProof(proof)

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}

	if !ok {
		t.Error("Proof rejected.\n")
	}
}

func TestValidKeyProofStructure(t *testing.T) {
	const p = 26903
	const q = 27803
	const a = 36
	const b = 49
	const c = 64

	s := NewValidKeyProofStructure(big.NewInt(p*q), big.NewInt(a), big.NewInt(b), []*big.Int{big.NewInt(c)})
	proof := s.BuildProof(big.NewInt((p-1)/2), big.NewInt((q-1)/2))

	backup := proof.GroupPrime
	proof.GroupPrime = nil
	if s.VerifyProof(proof) {
		t.Error("Accepting missing group prime")
	}

	proof.GroupPrime = big.NewInt(10009)
	if s.VerifyProof(proof) {
		t.Error("Accepting non-safe prime as group prime")
	}

	proof.GroupPrime = big.NewInt(20015)
	if s.VerifyProof(proof) {
		t.Error("Accepting non-prime as group prime")
	}
	proof.GroupPrime = backup

	backup = proof.PProof.Commit
	proof.PProof.Commit = nil
	if s.VerifyProof(proof) {
		t.Error("Accepting corrupted PProof")
	}
	proof.PProof.Commit = backup

	backup = proof.QProof.Commit
	proof.QProof.Commit = nil
	if s.VerifyProof(proof) {
		t.Error("Accepting corrupted QProof")
	}
	proof.QProof.Commit = backup

	backup = proof.PprimeProof.Commit
	proof.PprimeProof.Commit = nil
	if s.VerifyProof(proof) {
		t.Error("Accepting corrupted PprimeProof")
	}
	proof.PprimeProof.Commit = backup

	backup = proof.QprimeProof.Commit
	proof.QprimeProof.Commit = nil
	if s.VerifyProof(proof) {
		t.Error("Accepting corrupted QprimeProof")
	}
	proof.QprimeProof.Commit = backup

	backup = proof.PQNRel
	proof.PQNRel = nil
	if s.VerifyProof(proof) {
		t.Error("Accepting corrupted pqnrel")
	}
	proof.PQNRel = backup

	backup = proof.Challenge
	proof.Challenge = nil
	if s.VerifyProof(proof) {
		t.Error("Accepting missing challenge")
	}

	proof.Challenge = big.NewInt(1)
	if s.VerifyProof(proof) {
		t.Error("Accepting incorrect challenge")
	}
	proof.Challenge = backup

	backup = proof.PprimeIsPrimeProof.PreaModResult
	proof.PprimeIsPrimeProof.PreaModResult = nil
	if s.VerifyProof(proof) {
		t.Error("Accepting corrupted pprimeisprimeproof")
	}
	proof.PprimeIsPrimeProof.PreaModResult = backup

	backup = proof.QprimeIsPrimeProof.PreaModResult
	proof.QprimeIsPrimeProof.PreaModResult = nil
	if s.VerifyProof(proof) {
		t.Error("Accepting corrupted qprimeisprimeproof")
	}
	proof.QprimeIsPrimeProof.PreaModResult = backup

	backup = proof.QSPPproof.PPPproof.Responses[2]
	proof.QSPPproof.PPPproof.Responses[2] = nil
	if s.VerifyProof(proof) {
		t.Error("Accepting corrupted QSPPproof")
	}
	proof.QSPPproof.PPPproof.Responses[2] = backup

	backup = proof.BasesValidProof.NProof.Commit
	proof.BasesValidProof.NProof.Commit = nil
	if s.VerifyProof(proof) {
		t.Error("Accepting corrupted BasesValidProof")
	}
	proof.BasesValidProof.NProof.Commit = backup

	if !s.VerifyProof(proof) {
		t.Error("Testing corrupted proof structure!")
	}
}

func TestValidKeyProofJSON(t *testing.T) {
	const p = 26903
	const q = 27803
	const a = 36
	const b = 49
	const c = 64

	s := NewValidKeyProofStructure(big.NewInt(p*q), big.NewInt(a), big.NewInt(b), []*big.Int{big.NewInt(c)})
	proofBefore := s.BuildProof(big.NewInt((p-1)/2), big.NewInt((q-1)/2))
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter ValidKeyProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}

	ok := s.VerifyProof(proofAfter)
	if !ok {
		t.Error("Proof rejected.\n")
	}
}
