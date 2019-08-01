package keyproof

import "testing"
import "encoding/json"
import "github.com/privacybydesign/gabi/big"

func TestPrimeProofFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Prime proof testing")
		return
	}

	Follower.(*TestFollower).count = 0

	s := newPrimeProofStructure("p", 4)

	const p = 11
	pCommit := newPedersonSecret(g, "p", big.NewInt(p))
	bases := NewBaseMerge(&g, &pCommit)

	listSecrets, commit := s.generateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &pCommit)

	if len(listSecrets) != s.numCommitments() {
		t.Error("NumCommitments is off")
	}

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off GenerateCommitmentsFromSecrets")
	}
	Follower.(*TestFollower).count = 0

	proof := s.buildProof(g, big.NewInt(12345), commit, &pCommit)
	pProof := pCommit.buildProof(g, big.NewInt(12345))
	pProof.setName("p")

	basesProof := NewBaseMerge(&g, &pProof)

	if !s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Proof structure rejected.\n")
		return
	}

	listProof := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &basesProof, &pProof, proof)

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}

	if !listCmp(listSecrets, listProof) {
		t.Error("Commitment lists differ.")
	}
}

func TestPrimeProofFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Prime proof testing")
		return
	}

	s := newPrimeProofStructure("p", 4)

	proof := s.fakeProof(g, big.NewInt(12345))

	if !s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Fake proof structure rejected.")
	}
}

func TestPrimeProofJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Prime proof testing")
		return
	}

	s := newPrimeProofStructure("p", 4)

	proofBefore := s.fakeProof(g, big.NewInt(12345))
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter PrimeProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}

	if !s.verifyProofStructure(big.NewInt(12345), proofAfter) {
		t.Error("json'ed proof structure rejected")
	}
}

func TestPrimeProofVerify(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Prime proof testing")
		return
	}

	s := newPrimeProofStructure("p", 4)

	proof := s.fakeProof(g, big.NewInt(12345))
	proof.PreaCommit.Commit = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong prea pederson proof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.HalfPCommit.Commit = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong halfp pederson proof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.ACommit.Commit = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong a pederson proof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AnegCommit.Commit = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong aneg pederson proof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AResCommit.Commit = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong aRes pederson proof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AnegResCommit.Commit = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong anegRes pederson proof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.PreaModResult = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing preamodresult")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.PreaHiderResult = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing preahiderresult")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.APlus1Result = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing aPlus1Result")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AMin1Result = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing aMin1Result")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.APlus1Challenge = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing aPlus1Challenge")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AMin1Challenge = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing aMin1Challenge")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AMin1Challenge.Set(big.NewInt(1))
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting incorrect challenges")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.PreaRangeProof.Results = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong prearangeproof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.ARangeProof.Results = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong arangeproof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AnegRangeProof.Results = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong anegrangeproof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.PreaModRangeProof.Results = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong preamodrangeproof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AExpProof.ExpBitEqResult = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong aexpproof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AnegExpProof.ExpBitEqResult = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong anegexpproof")
	}
}
