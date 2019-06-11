package keyproof

import "testing"
import "encoding/json"
import "github.com/privacybydesign/gabi/big"

func TestExpStepFlowA(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStep proof testing")
		return
	}

	Follower.(*TestFollower).count = 0

	bitPederson := newPedersonSecret(g, "bit", big.NewInt(0))
	prePederson := newPedersonSecret(g, "pre", big.NewInt(2))
	postPederson := newPedersonSecret(g, "post", big.NewInt(2))
	mulPederson := newPedersonSecret(g, "mul", big.NewInt(3))
	modPederson := newPedersonSecret(g, "mod", big.NewInt(11))

	bases := newBaseMerge(&g, &bitPederson, &prePederson, &postPederson, &mulPederson, &modPederson)
	secrets := newSecretMerge(&bitPederson, &prePederson, &postPederson, &mulPederson, &modPederson)

	s := newExpStepStructure("bit", "pre", "post", "mul", "mod", 4)

	if !s.isTrue(&secrets) {
		t.Error("Proof premise rejected")
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

	proofBases := newBaseMerge(&g, &bitProof, &preProof, &postProof, &mulProof, &modProof)

	listProof := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &proofBases, proof)

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}

	if !listCmp(listSecrets, listProof) {
		t.Error("Commitment lists differ.")
	}
}

func TestExpStepFlowB(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStep proof testing")
	}

	bitPederson := newPedersonSecret(g, "bit", big.NewInt(1))
	prePederson := newPedersonSecret(g, "pre", big.NewInt(2))
	postPederson := newPedersonSecret(g, "post", big.NewInt(6))
	mulPederson := newPedersonSecret(g, "mul", big.NewInt(3))
	modPederson := newPedersonSecret(g, "mod", big.NewInt(11))

	bases := newBaseMerge(&g, &bitPederson, &prePederson, &postPederson, &mulPederson, &modPederson)
	secrets := newSecretMerge(&bitPederson, &prePederson, &postPederson, &mulPederson, &modPederson)

	s := newExpStepStructure("bit", "pre", "post", "mul", "mod", 4)

	if !s.isTrue(&secrets) {
		t.Error("Proof premise rejected")
	}

	listSecrets, commit := s.generateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secrets)
	proof := s.buildProof(g, big.NewInt(12345), commit, &secrets)

	if !s.verifyProofStructure(big.NewInt(12345), proof) {
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

	proofBases := newBaseMerge(&g, &bitProof, &preProof, &postProof, &mulProof, &modProof)

	listProof := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &proofBases, proof)

	if !listCmp(listSecrets, listProof) {
		t.Error("Commitment lists differ.")
	}
}

func TestExpStepFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStep proof testing")
		return
	}

	s := newExpStepStructure("bit", "pre", "post", "mul", "mod", 4)

	proof := s.fakeProof(g, big.NewInt(12345))

	if !s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Fake proof rejected")
	}
}

func TestExpStepJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStep proof testing")
		return
	}

	s := newExpStepStructure("bit", "pre", "post", "mul", "mod", 4)

	proofBefore := s.fakeProof(g, big.NewInt(12345))
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter ExpStepProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}

	if !s.verifyProofStructure(big.NewInt(12345), proofAfter) {
		t.Error("json'ed proof structure rejected")
	}
}

func TestExpStepVerifyProofStructure(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStep proof testing")
		return
	}

	s := newExpStepStructure("bit", "pre", "post", "mul", "mod", 4)

	proof := s.fakeProof(g, big.NewInt(12345))
	proof.Achallenge = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing achallenge.")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.Bchallenge = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing bchallenge.")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.Bchallenge.Add(proof.Bchallenge, big.NewInt(1))
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting incorrect challenges.")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.Aproof.BitHiderResult = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted aproof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.Bproof.BitHiderResult = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted bproof")
	}
}
