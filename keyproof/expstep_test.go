package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
)

func TestExpStepFlowA(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStep proof testing")
		return
	}

	Follower.(*TestFollower).count = 0

	bitPedersens := newPedersenStructure("bit")
	prePedersens := newPedersenStructure("pre")
	postPedersens := newPedersenStructure("post")
	mulPedersens := newPedersenStructure("mul")
	modPedersens := newPedersenStructure("mod")

	_, bitPedersen := bitPedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(0))
	_, prePedersen := prePedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(2))
	_, postPedersen := postPedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(2))
	_, mulPedersen := mulPedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(3))
	_, modPedersen := modPedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(11))

	bases := newBaseMerge(&g, &bitPedersen, &prePedersen, &postPedersen, &mulPedersen, &modPedersen)
	secrets := newSecretMerge(&bitPedersen, &prePedersen, &postPedersen, &mulPedersen, &modPedersen)

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

	bitProof := bitPedersens.buildProof(g, big.NewInt(12345), bitPedersen)
	bitProof.setName("bit")
	preProof := prePedersens.buildProof(g, big.NewInt(12345), prePedersen)
	preProof.setName("pre")
	postProof := postPedersens.buildProof(g, big.NewInt(12345), postPedersen)
	postProof.setName("post")
	mulProof := mulPedersens.buildProof(g, big.NewInt(12345), mulPedersen)
	mulProof.setName("mul")
	modProof := modPedersens.buildProof(g, big.NewInt(12345), modPedersen)
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

	bitPedersens := newPedersenStructure("bit")
	prePedersens := newPedersenStructure("pre")
	postPedersens := newPedersenStructure("post")
	mulPedersens := newPedersenStructure("mul")
	modPedersens := newPedersenStructure("mod")

	_, bitPedersen := bitPedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(1))
	_, prePedersen := prePedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(2))
	_, postPedersen := postPedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(6))
	_, mulPedersen := mulPedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(3))
	_, modPedersen := modPedersens.generateCommitmentsFromSecrets(g, nil, big.NewInt(11))

	bases := newBaseMerge(&g, &bitPedersen, &prePedersen, &postPedersen, &mulPedersen, &modPedersen)
	secrets := newSecretMerge(&bitPedersen, &prePedersen, &postPedersen, &mulPedersen, &modPedersen)

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

	bitProof := bitPedersens.buildProof(g, big.NewInt(12345), bitPedersen)
	bitProof.setName("bit")
	preProof := prePedersens.buildProof(g, big.NewInt(12345), prePedersen)
	preProof.setName("pre")
	postProof := postPedersens.buildProof(g, big.NewInt(12345), postPedersen)
	postProof.setName("post")
	mulProof := mulPedersens.buildProof(g, big.NewInt(12345), mulPedersen)
	mulProof.setName("mul")
	modProof := modPedersens.buildProof(g, big.NewInt(12345), modPedersen)
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
	proof.Aproof.Bit.Result = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted aproof")
	}

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.Bproof.Bit.Result = nil
	if s.verifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted bproof")
	}
}
