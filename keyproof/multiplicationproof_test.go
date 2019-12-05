package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
)

func TestMultiplicationProofFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	Follower.(*TestFollower).count = 0

	const a = 2
	const b = 3
	const d = 1
	const n = 5

	m1s := newPedersonStructure("m1")
	m2s := newPedersonStructure("m2")
	mods := newPedersonStructure("mod")
	results := newPedersonStructure("result")

	_, m1 := m1s.generateCommitmentsFromSecrets(g, nil, big.NewInt(a))
	_, m2 := m2s.generateCommitmentsFromSecrets(g, nil, big.NewInt(b))
	_, mod := mods.generateCommitmentsFromSecrets(g, nil, big.NewInt(n))
	_, result := results.generateCommitmentsFromSecrets(g, nil, big.NewInt(d))

	bases := newBaseMerge(&g, &m1, &m2, &mod, &result)
	secrets := newSecretMerge(&m1, &m2, &mod, &result)

	s := newMultiplicationProofStructure("m1", "m2", "mod", "result", 3)
	if !s.isTrue(&secrets) {
		t.Error("Incorrectly assessed proof setup as incorrect.")
	}

	listSecrets, commit := s.generateCommitmentsFromSecrets(g, nil, &bases, &secrets)

	if len(listSecrets) != s.numCommitments() {
		t.Error("NumCommitments is off")
	}

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off GenerateCommitmentsFromSecrets")
	}
	Follower.(*TestFollower).count = 0

	proof := s.buildProof(g, big.NewInt(12345), commit, &secrets)
	m1proof := m1s.buildProof(g, big.NewInt(12345), m1)
	m1proof.setName("m1")
	m2proof := m2s.buildProof(g, big.NewInt(12345), m2)
	m2proof.setName("m2")
	modproof := mods.buildProof(g, big.NewInt(12345), mod)
	modproof.setName("mod")
	resultproof := results.buildProof(g, big.NewInt(12345), result)
	resultproof.setName("result")

	basesProof := newBaseMerge(&g, &m1proof, &m2proof, &modproof, &resultproof)
	proofdata := newProofMerge(&m1proof, &m2proof, &modproof, &resultproof)

	if !s.verifyProofStructure(proof) {
		t.Error("Proof structure marked as invalid.\n")
		return
	}

	listProof := s.generateCommitmentsFromProof(g, nil, big.NewInt(12345), &basesProof, &proofdata, proof)

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}
	Follower.(*TestFollower).count = 0

	if !listCmp(listSecrets, listProof) {
		t.Error("Commitment lists differ.\n")
	}
}

func TestMultiplicationProofFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	s := newMultiplicationProofStructure("m1", "m2", "mod", "result", 3)

	proof := s.fakeProof(g)

	if !s.verifyProofStructure(proof) {
		t.Error("Fake proof structure rejected.")
	}
}

func TestMultiplicationProofVerifyStructure(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	var proof MultiplicationProof
	s := newMultiplicationProofStructure("m1", "m2", "mod", "result", 3)

	proof = s.fakeProof(g)
	proof.ModMultProof.Commit = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting malformed ModMultProof")
	}

	proof = s.fakeProof(g)
	proof.Hider.Result = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting missing HiderResult")
	}

	proof = s.fakeProof(g)
	proof.RangeProof.Results = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting malformed range proof")
	}
}

func TestMultiplicationProofJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	s := newMultiplicationProofStructure("m1", "m2", "mod", "result", 3)

	proofBefore := s.fakeProof(g)
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter MultiplicationProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}

	if !s.verifyProofStructure(proofAfter) {
		t.Error("json'ed proof structure rejected")
	}
}
