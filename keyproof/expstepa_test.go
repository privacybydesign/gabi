package keyproof

import "testing"
import "encoding/json"
import "github.com/privacybydesign/gabi/big"

func TestExpStepAFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepA proof testing")
		return
	}

	Follower.(*TestFollower).count = 0

	bitPederson := newPedersonSecret(g, "bit", big.NewInt(0))
	prePederson := newPedersonSecret(g, "pre", big.NewInt(5))
	postPederson := newPedersonSecret(g, "post", big.NewInt(5))

	bases := NewBaseMerge(&g, &bitPederson, &prePederson, &postPederson)
	secrets := NewSecretMerge(&bitPederson, &prePederson, &postPederson)

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

	bitProof := bitPederson.buildProof(g, big.NewInt(12345))
	bitProof.setName("bit")
	preProof := prePederson.buildProof(g, big.NewInt(12345))
	preProof.setName("pre")
	postProof := postPederson.buildProof(g, big.NewInt(12345))
	postProof.setName("post")

	proofBases := NewBaseMerge(&g, &bitProof, &preProof, &postProof)

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

	proof.BitHiderResult = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting missing bithiderresult")
	}

	proof.BitHiderResult = proof.EqualityHiderResult
	proof.EqualityHiderResult = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting missing equalityhiderresult")
	}
}
