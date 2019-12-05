package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
)

func TestAdditionProofFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Addition proof testing")
		return
	}

	Follower.(*TestFollower).count = 0

	const a = 4
	const b = 3
	const d = 2
	const n = 5

	a1s := newPedersenStructure("a1")
	a2s := newPedersenStructure("a2")
	mods := newPedersenStructure("mod")
	results := newPedersenStructure("result")

	_, a1 := a1s.generateCommitmentsFromSecrets(g, []*big.Int{}, big.NewInt(a))
	_, a2 := a2s.generateCommitmentsFromSecrets(g, []*big.Int{}, big.NewInt(b))
	_, mod := mods.generateCommitmentsFromSecrets(g, []*big.Int{}, big.NewInt(n))
	_, result := results.generateCommitmentsFromSecrets(g, []*big.Int{}, big.NewInt(d))

	bases := newBaseMerge(&g, &a1, &a2, &mod, &result)
	secrets := newSecretMerge(&a1, &a2, &mod, &result)

	s := newAdditionProofStructure("a1", "a2", "mod", "result", 3)
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
	a1proof := a1s.buildProof(g, big.NewInt(12345), a1)
	a1proof.setName("a1")
	a2proof := a2s.buildProof(g, big.NewInt(12345), a2)
	a2proof.setName("a2")
	modproof := mods.buildProof(g, big.NewInt(12345), mod)
	modproof.setName("mod")
	resultproof := results.buildProof(g, big.NewInt(12345), result)
	resultproof.setName("result")

	basesProof := newBaseMerge(&g, &a1proof, &a2proof, &modproof, &resultproof)
	proofdata := newProofMerge(&a1proof, &a2proof, &modproof, &resultproof)

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

func TestAdditionProofVerifyStructure(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	var proof AdditionProof
	s := newAdditionProofStructure("a1", "a2", "mod", "result", 3)

	proof = s.fakeProof(g)
	proof.RangeProof.Results = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting missing rangeproof.\n")
	}

	proof = s.fakeProof(g)
	proof.ModAddProof.Result = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting missing modaddresult.\n")
	}

	proof = s.fakeProof(g)
	proof.HiderProof.Result = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting missing hiderresult.\n")
	}
}

func TestAdditionProofFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	s := newAdditionProofStructure("a1", "a2", "mod", "result", 3)

	proof := s.fakeProof(g)

	if !s.verifyProofStructure(proof) {
		t.Error("Rejecting fake proof structure.\n")
	}
}

func TestAdditionProofJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	s := newAdditionProofStructure("a1", "a2", "mod", "result", 3)

	proofBefore := s.fakeProof(g)

	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter AdditionProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}

	if !s.verifyProofStructure(proofAfter) {
		t.Error("json'ed proof structure invalid")
	}
}
