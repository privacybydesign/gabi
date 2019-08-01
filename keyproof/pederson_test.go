package keyproof

import "testing"
import "encoding/json"
import "github.com/privacybydesign/gabi/big"

func TestPedersonSecret(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Representation proof testing")
		return
	}

	testSecret := newPedersonSecret(g, "x", big.NewInt(15))

	x := testSecret.GetSecret("x")
	if x == nil || x.Cmp(big.NewInt(15)) != 0 {
		t.Error("Improper inclusion of secret.")
	}
	if testSecret.GetRandomizer("x") == nil {
		t.Error("Missing randomizer for secret")
	}
	if testSecret.GetSecret("x_hider") == nil {
		t.Error("Missing hider")
	}
	if testSecret.GetRandomizer("x") == nil {
		t.Error("Missing ramdomizer for hider")
	}
	if testSecret.GetBase("x") == nil {
		t.Error("Missing commitment")
	}
}

func TestPedersonProof(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Representation proof testing")
		return
	}

	testSecret := newPedersonSecret(g, "x", big.NewInt(15))
	listSecrets := testSecret.generateCommitments([]*big.Int{})
	testProof := testSecret.buildProof(g, big.NewInt(1))
	listProof := testProof.generateCommitments([]*big.Int{})

	testProof.setName("x")

	if testProof.GetBase("x") == nil {
		t.Error("Missing commitment")
	}
	if testProof.GetResult("x") == nil {
		t.Error("Missing result for secret")
	}
	if testProof.GetResult("x_hider") == nil {
		t.Error("Missing result for hider")
	}
	if !listCmp(listSecrets, listProof) {
		t.Error("Commitment lists differ")
	}
}

func TestPedersonRepresentationFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Representation proof testing")
		return
	}

	testSecret := newPedersonSecret(g, "x", big.NewInt(15))
	testProof := testSecret.buildProof(g, big.NewInt(2))
	testProof.setName("x")

	secretBases := NewBaseMerge(&g, &testSecret)
	proofBases := NewBaseMerge(&g, &testProof)

	s := newPedersonRepresentationProofStructure("x")

	if !s.isTrue(g, &secretBases, &testSecret) {
		t.Error("Attempted proof is false")
	}

	secretCommit := s.generateCommitmentsFromSecrets(g, []*big.Int{}, &secretBases, &testSecret)
	proofCommit := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(2), &proofBases, &testProof)

	if secretCommit[0].Cmp(proofCommit[0]) != 0 {
		t.Error("Commitments disagree")
	}
}

func TestPedersonRangeFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Representation proof testing")
		return
	}

	testSecret := newPedersonSecret(g, "x", big.NewInt(15))
	testProof := testSecret.buildProof(g, big.NewInt(2))
	testProof.setName("x")

	secretBases := NewBaseMerge(&g, &testSecret)
	proofBases := NewBaseMerge(&g, &testProof)

	s := newPedersonRangeProofStructure("x", 4, 2)

	if !s.isTrue(g, &secretBases, &testSecret) {
		t.Error("Attempted proof is false")
	}

	secretCommit, commit := s.generateCommitmentsFromSecrets(g, []*big.Int{}, &secretBases, &testSecret)
	proof := s.buildProof(g, big.NewInt(12345), commit, &testSecret)
	proofCommit := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &proofBases, proof)

	if !listCmp(secretCommit, proofCommit) {
		t.Error("Commitments disagree")
	}
}

func TestPedersonProofVerifyStructure(t *testing.T) {
	var proof PedersonProof
	testInt := big.NewInt(1)

	proof.Commit = testInt
	proof.Sresult = testInt
	proof.Hresult = testInt

	proof.Commit = nil
	if proof.verifyStructure() {
		t.Error("Accepted emtpy commit")
	}
	proof.Commit = testInt

	proof.Sresult = nil
	if proof.verifyStructure() {
		t.Error("Accepted empty Sresult")
	}
	proof.Sresult = testInt

	proof.Hresult = nil
	if proof.verifyStructure() {
		t.Error("Accepted empty Hresult")
	}
}

func TestPedersonProofFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Representation proof testing")
		return
	}

	proof := newPedersonFakeProof(g)
	ok := proof.verifyStructure()
	if !ok {
		t.Error("Fake proof structure rejected")
	}
}

func TestPedersonProofJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Representation proof testing")
		return
	}

	proofBefore := newPedersonFakeProof(g)
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", proofBefore)
		return
	}

	var proofAfter PedersonProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", proofAfter)
		return
	}

	if !proofAfter.verifyStructure() {
		t.Error("json'ed proof structure rejected")
	}
}
