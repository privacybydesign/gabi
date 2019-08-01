package keyproof

import "testing"
import "encoding/json"
import "github.com/privacybydesign/gabi/big"

func TestExpStepBFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepB proof testing")
		return
	}

	Follower.(*TestFollower).count = 0

	bitPederson := newPedersonSecret(g, "bit", big.NewInt(1))
	prePederson := newPedersonSecret(g, "pre", big.NewInt(2))
	postPederson := newPedersonSecret(g, "post", big.NewInt(6))
	mulPederson := newPedersonSecret(g, "mul", big.NewInt(3))
	modPederson := newPedersonSecret(g, "mod", big.NewInt(11))

	bases := NewBaseMerge(&g, &bitPederson, &prePederson, &postPederson, &mulPederson, &modPederson)
	secrets := NewSecretMerge(&bitPederson, &prePederson, &postPederson, &mulPederson, &modPederson)

	s := newExpStepBStructure("bit", "pre", "post", "mul", "mod", 4)

	if !s.isTrue(&secrets) {
		t.Error("Proof premis rejected")
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

	if !s.verifyProofStructure(proof) {
		t.Error("Proof structure rejected")
		return
	}

	bitProof := bitPederson.buildProof(g, big.NewInt(12345))
	bitProof.setName("bit")
	preProof := prePederson.buildProof(g, big.NewInt(12345))
	preProof.setName("pre")
	postProof := postPederson.buildProof(g, big.NewInt(12345))
	postProof.setName("post")
	mulProof := mulPederson.buildProof(g, big.NewInt(12345))
	mulProof.setName("mul")
	modProof := modPederson.buildProof(g, big.NewInt(12345))
	modProof.setName("mod")

	proofBases := NewBaseMerge(&g, &bitProof, &preProof, &postProof, &mulProof, &modProof)

	listProof := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &proofBases, proof)

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}

	if !listCmp(listSecrets, listProof) {
		t.Error("Commitment lists differ.")
	}
}

func TestExpStepBFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepB proof testing")
		return
	}

	s := newExpStepBStructure("bit", "pre", "post", "mul", "mod", 4)

	proof := s.fakeProof(g)
	if !s.verifyProofStructure(proof) {
		t.Error("Fake proof structure rejected")
	}
}

func TestExpStepBJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepB proof testing")
		return
	}

	s := newExpStepBStructure("bit", "pre", "post", "mul", "mod", 4)

	proofBefore := s.fakeProof(g)
	proofJSON, err := json.Marshal(proofBefore)

	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter ExpStepBProof
	err = json.Unmarshal(proofJSON, &proofAfter)

	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}
	if !s.verifyProofStructure(proofAfter) {
		t.Error("json'ed proof structure rejected")
	}
}

func TestExpStepBVerifyStructure(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepB proof testing")
		return
	}

	s := newExpStepBStructure("bit", "pre", "post", "mul", "mod", 4)

	proof := s.fakeProof(g)
	proof.MulResult = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting missing mulresult")
	}

	proof = s.fakeProof(g)
	proof.MulHiderResult = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting missing mulhiderresult")
	}

	proof = s.fakeProof(g)
	proof.BitHiderResult = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting missing bithiderresult")
	}

	proof = s.fakeProof(g)
	proof.MultiplicationProof.HiderResult = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting corrupted multiplicationproof")
	}
}
