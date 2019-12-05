package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
)

func TestExpStepAFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepA proof testing")
		return
	}

	Follower.(*TestFollower).count = 0

	bitPedersons := newPedersonStructure("bit")
	prePedersons := newPedersonStructure("pre")
	postPedersons := newPedersonStructure("post")

	_, bitPederson := bitPedersons.generateCommitmentsFromSecrets(g, nil, big.NewInt(0))
	_, prePederson := prePedersons.generateCommitmentsFromSecrets(g, nil, big.NewInt(5))
	_, postPederson := postPedersons.generateCommitmentsFromSecrets(g, nil, big.NewInt(5))

	bases := newBaseMerge(&g, &bitPederson, &prePederson, &postPederson)
	secrets := newSecretMerge(&bitPederson, &prePederson, &postPederson)

	s := newExpStepAStructure("bit", "pre", "post")

	if !s.isTrue(&secrets) {
		t.Error("Statement validity rejected")
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
		t.Error("Proof structure rejected.")
		return
	}

	bitProof := bitPedersons.buildProof(g, big.NewInt(12345), bitPederson)
	bitProof.setName("bit")
	preProof := prePedersons.buildProof(g, big.NewInt(12345), prePederson)
	preProof.setName("pre")
	postProof := postPedersons.buildProof(g, big.NewInt(12345), postPederson)
	postProof.setName("post")

	proofBases := newBaseMerge(&g, &bitProof, &preProof, &postProof)

	listProof := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &proofBases, proof)

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}

	if !listCmp(listSecrets, listProof) {
		t.Error("Commitment lists differ.")
	}
}

func TestExpStepAFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepA proof testing")
		return
	}

	s := newExpStepAStructure("bit", "pre", "post")

	proof := s.fakeProof(g)
	if !s.verifyProofStructure(proof) {
		t.Error("Fake proof structure rejected.")
	}
}

func TestExpStepAJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepA proof testing")
		return
	}

	s := newExpStepAStructure("bit", "pre", "post")

	proofBefore := s.fakeProof(g)
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter ExpStepAProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}

	if !s.verifyProofStructure(proofAfter) {
		t.Error("json'ed proof structure rejected.")
	}
}

func TestExpStepAVerifyStructure(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepA proof testing")
		return
	}

	s := newExpStepAStructure("bit", "pre", "post")

	proof := s.fakeProof(g)

	proof.Bit.Result = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting missing bithiderresult")
	}

	proof.Bit.Result = proof.EqualityHider.Result
	proof.EqualityHider.Result = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting missing equalityhiderresult")
	}
}
