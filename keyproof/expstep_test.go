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

	bitPedersons := newPedersonStructure("bit")
	prePedersons := newPedersonStructure("pre")
	postPedersons := newPedersonStructure("post")
	mulPedersons := newPedersonStructure("mul")
	modPedersons := newPedersonStructure("mod")

	_, bitPederson := bitPedersons.generateCommitmentsFromSecrets(g, nil, big.NewInt(0))
	_, prePederson := prePedersons.generateCommitmentsFromSecrets(g, nil, big.NewInt(2))
	_, postPederson := postPedersons.generateCommitmentsFromSecrets(g, nil, big.NewInt(2))
	_, mulPederson := mulPedersons.generateCommitmentsFromSecrets(g, nil, big.NewInt(3))
	_, modPederson := modPedersons.generateCommitmentsFromSecrets(g, nil, big.NewInt(11))

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

	bitProof := bitPedersons.buildProof(g, big.NewInt(12345), bitPederson)
	bitProof.setName("bit")
	preProof := prePedersons.buildProof(g, big.NewInt(12345), prePederson)
	preProof.setName("pre")
	postProof := postPedersons.buildProof(g, big.NewInt(12345), postPederson)
	postProof.setName("post")
	mulProof := mulPedersons.buildProof(g, big.NewInt(12345), mulPederson)
	mulProof.setName("mul")
	modProof := modPedersons.buildProof(g, big.NewInt(12345), modPederson)
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

	bitPedersons := newPedersonStructure("bit")
	prePedersons := newPedersonStructure("pre")
	postPedersons := newPedersonStructure("post")
	mulPedersons := newPedersonStructure("mul")
	modPedersons := newPedersonStructure("mod")

	_, bitPederson := bitPedersons.generateCommitmentsFromSecrets(g, nil, big.NewInt(1))
	_, prePederson := prePedersons.generateCommitmentsFromSecrets(g, nil, big.NewInt(2))
	_, postPederson := postPedersons.generateCommitmentsFromSecrets(g, nil, big.NewInt(6))
	_, mulPederson := mulPedersons.generateCommitmentsFromSecrets(g, nil, big.NewInt(3))
	_, modPederson := modPedersons.generateCommitmentsFromSecrets(g, nil, big.NewInt(11))

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

	bitProof := bitPedersons.buildProof(g, big.NewInt(12345), bitPederson)
	bitProof.setName("bit")
	preProof := prePedersons.buildProof(g, big.NewInt(12345), prePederson)
	preProof.setName("pre")
	postProof := postPedersons.buildProof(g, big.NewInt(12345), postPederson)
	postProof.setName("post")
	mulProof := mulPedersons.buildProof(g, big.NewInt(12345), mulPederson)
	mulProof.setName("mul")
	modProof := modPedersons.buildProof(g, big.NewInt(12345), modPederson)
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
