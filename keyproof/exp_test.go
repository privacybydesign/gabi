package keyproof

import "github.com/privacybydesign/gabi/big"
import "testing"
import "encoding/json"

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

	aPederson := newPedersonSecret(g, "a", big.NewInt(a))
	bPederson := newPedersonSecret(g, "b", big.NewInt(b))
	nPederson := newPedersonSecret(g, "n", big.NewInt(n))
	rPederson := newPedersonSecret(g, "r", big.NewInt(r))

	bases := NewBaseMerge(&g, &aPederson, &bPederson, &nPederson, &rPederson)
	secrets := NewSecretMerge(&aPederson, &bPederson, &nPederson, &rPederson)

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

	aProof := aPederson.buildProof(g, big.NewInt(12345))
	aProof.setName("a")
	bProof := bPederson.buildProof(g, big.NewInt(12345))
	bProof.setName("b")
	nProof := nPederson.buildProof(g, big.NewInt(12345))
	nProof.setName("n")
	rProof := rPederson.buildProof(g, big.NewInt(12345))
	rProof.setName("r")

	proofBases := NewBaseMerge(&g, &aProof, &bProof, &nProof, &rProof)
	proofs := NewProofMerge(&aProof, &bProof, &nProof, &rProof)

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
	proof.ExpBitEqResult = nil
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
	proof.BasePowRelProofs[2].HiderResult = nil
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
