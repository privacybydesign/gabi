package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
)

func TestPedersenProofFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group")
		return
	}

	s := newPedersenStructure("x")

	Follower.(*TestFollower).count = 0

	listSecrets, commit := s.generateCommitmentsFromSecrets(g, []*big.Int{}, big.NewInt(15))
	proof := s.buildProof(g, big.NewInt(1), commit)

	if len(listSecrets) != s.numCommitments() {
		t.Errorf("NumCommitments is off, %v %v", len(listSecrets), s.numCommitments())
	}

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off GenerateCommitmentsFromSecrets")
	}
	Follower.(*TestFollower).count = 0

	proof.setName("x")

	if !s.verifyProofStructure(proof) {
		t.Errorf("Rejecting proof structure %v", proof)
	}

	listProof := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(1), proof)

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}
	Follower.(*TestFollower).count = 0

	if !listCmp(listSecrets, listProof) {
		t.Errorf("Commitment lists differ %s %s.\n", listSecrets, listProof)
	}
}

func TestPedersenProofVerifyStructure(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Representation proof testing")
		return
	}

	s := newPedersenStructure("x")

	proof := s.fakeProof(g)
	proof.Commit = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting incorrectly structured proof")
	}

	proof = s.fakeProof(g)
	proof.Sresult.Result = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting incorrectly structured proof")
	}

	proof = s.fakeProof(g)
	proof.Hresult.Result = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting incorrectly structured proof")
	}
}

func TestPedersenProofFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Representation proof testing")
		return
	}

	s := newPedersenStructure("x")
	proof := s.fakeProof(g)
	if !s.verifyProofStructure(proof) {
		t.Error("Fakeproof has incorrect structure")
	}
}

func TestPedersenProofJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Representation proof testing")
		return
	}

	s := newPedersenStructure("x")

	listSecrets, commit := s.generateCommitmentsFromSecrets(g, []*big.Int{}, big.NewInt(15))

	proofBefore := s.buildProof(g, big.NewInt(12345), commit)
	proofJSON, err := json.Marshal(&proofBefore)
	if err != nil {
		t.Error("Error converting to JSON")
	}

	var proofAfter PedersenProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Error("Error parsing json")
	}

	if !s.verifyProofStructure(proofAfter) {
		t.Error("Invalid proof structure after JSON")
	}

	listProof := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), proofAfter)
	if !listCmp(listSecrets, listProof) {
		t.Error("Commitment lists differ.\n")
	}
}
