package keyproof

import "testing"
import "encoding/json"
import "github.com/privacybydesign/gabi/big"

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

	m1 := newPedersonSecret(g, "m1", big.NewInt(a))
	m2 := newPedersonSecret(g, "m2", big.NewInt(b))
	mod := newPedersonSecret(g, "mod", big.NewInt(n))
	result := newPedersonSecret(g, "result", big.NewInt(d))

	bases := NewBaseMerge(&g, &m1, &m2, &mod, &result)
	secrets := NewSecretMerge(&m1, &m2, &mod, &result)

	s := newMultiplicationProofStructure("m1", "m2", "mod", "result", 3)
	if !s.isTrue(&secrets) {
		t.Error("Incorrectly assessed proof setup as incorrect.")
	}

	listSecrets, commit := s.generateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secrets)

	if len(listSecrets) != s.numCommitments() {
		t.Error("NumCommitments is off")
	}

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off GenerateCommitmentsFromSecrets")
	}
	Follower.(*TestFollower).count = 0

	proof := s.buildProof(g, big.NewInt(12345), commit, &secrets)
	m1proof := m1.buildProof(g, big.NewInt(12345))
	m1proof.setName("m1")
	m2proof := m2.buildProof(g, big.NewInt(12345))
	m2proof.setName("m2")
	modproof := mod.buildProof(g, big.NewInt(12345))
	modproof.setName("mod")
	resultproof := result.buildProof(g, big.NewInt(12345))
	resultproof.setName("result")

	basesProof := NewBaseMerge(&g, &m1proof, &m2proof, &modproof, &resultproof)
	proofdata := NewProofMerge(&m1proof, &m2proof, &modproof, &resultproof)

	if !s.verifyProofStructure(proof) {
		t.Error("Proof structure marked as invalid.\n")
		return
	}

	listProof := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &basesProof, &proofdata, proof)

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}

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
	proof.HiderResult = nil
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
