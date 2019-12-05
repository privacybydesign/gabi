package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
)

func TestExpProofFlow(t *testing.T) {
	const a = 2
	const b = 5
	const n = 11
	const r = -1

	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for exp proof testing")
		return
	}

	Follower.(*TestFollower).count = 0

	aPedersens := newPedersenStructure("a")
	bPedersens := newPedersenStructure("b")
	nPedersens := newPedersenStructure("n")
	rPedersens := newPedersenStructure("r")

	_, aPedersen := aPedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(a))
	_, bPedersen := bPedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(b))
	_, nPedersen := nPedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(n))
	_, rPedersen := rPedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(r))

	bases := newBaseMerge(&g, &aPedersen, &bPedersen, &nPedersen, &rPedersen)
	secrets := newSecretMerge(&aPedersen, &bPedersen, &nPedersen, &rPedersen)

	s := newExpProofStructure("a", "b", "n", "r", 4)

	if !s.isTrue(&secrets) {
		t.Error("proof premise deemed false")
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

	if !s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("proof structure rejected")
		return
	}

	aProof := aPedersens.buildProof(g, big.NewInt(12345), aPedersen)
	aProof.setName("a")
	bProof := bPedersens.buildProof(g, big.NewInt(12345), bPedersen)
	bProof.setName("b")
	nProof := nPedersens.buildProof(g, big.NewInt(12345), nPedersen)
	nProof.setName("n")
	rProof := rPedersens.buildProof(g, big.NewInt(12345), rPedersen)
	rProof.setName("r")

	proofBases := newBaseMerge(&g, &aProof, &bProof, &nProof, &rProof)
	proofs := newProofMerge(&aProof, &bProof, &nProof, &rProof)

	listProof := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &proofBases, &proofs, proof)

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}

	if !listCmp(listSecrets, listProof) {
		t.Errorf("Commitment lists differ\n%v\n%v", listSecrets, listProof)
	}
}

func TestExpProofFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for exp proof testing")
		return
	}

	s := newExpProofStructure("a", "b", "n", "r", 4)

	proof := s.fakeProof(g, big.NewInt(12345))
	if !s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("fake proof structure rejected")
	}
}

func TestExpProofJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for exp proof testing")
		return
	}

	s := newExpProofStructure("a", "b", "n", "r", 4)

	proofBefore := s.fakeProof(g, big.NewInt(12345))
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter ExpProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}

	if !s.verifyProofStructure(big.NewInt(12345), proofAfter) {
		t.Error("json'ed proof structure rejected")
	}
}

func TestExpProofVerifyStructure(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for exp proof testing")
		return
	}

	s := newExpProofStructure("a", "b", "n", "r", 4)

	proof := s.fakeProof(g, big.NewInt(12345))
	proof.ExpBitEqHider.Result = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("accepting missing expbiteqresult")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.ExpBitProofs = proof.ExpBitProofs[:len(proof.ExpBitProofs)-1]
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("accepting too short expbitproofs")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.ExpBitProofs[2].Commit = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("accepting corrupted expbitproof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.BasePowProofs = proof.BasePowProofs[:len(proof.BasePowProofs)-1]
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("accepting too short basepowproofs")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.BasePowProofs[1].Commit = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted basepowproofs")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.BasePowRangeProofs = proof.BasePowRangeProofs[:len(proof.BasePowRangeProofs)-1]
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting too short basepowrangeproofs")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.BasePowRangeProofs[1].Results = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted basepowrangeproofs")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.BasePowRelProofs = proof.BasePowRelProofs[:len(proof.BasePowRelProofs)-1]
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting too short basepowrelproofs")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.BasePowRelProofs[2].Hider.Result = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted basepowrelproof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.StartProof.Commit = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted startproof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.InterResProofs = proof.InterResProofs[:len(proof.InterResProofs)-1]
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting too short interresproofs")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.InterResProofs[1].Commit = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted interresproof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.InterResRangeProofs = proof.InterResRangeProofs[:len(proof.InterResRangeProofs)-1]
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting too short interresrangeproofs")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.InterResRangeProofs[2].Results = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted interresrangeproofs")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.InterStepsProofs = proof.InterStepsProofs[:len(proof.InterStepsProofs)-1]
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting too short interstepsproof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.InterStepsProofs[2].Achallenge = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted interstepsproof")
	}
}
