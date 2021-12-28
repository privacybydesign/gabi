package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/zkproof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpStepBFlow(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for expStepB proof testing")

	Follower.(*TestFollower).count = 0

	bitPedersens := newPedersenStructure("bit")
	prePedersens := newPedersenStructure("pre")
	postPedersens := newPedersenStructure("post")
	mulPedersens := newPedersenStructure("mul")
	modPedersens := newPedersenStructure("mod")

	_, bitPedersen := bitPedersens.commitmentsFromSecrets(g, nil, big.NewInt(1))
	_, prePedersen := prePedersens.commitmentsFromSecrets(g, nil, big.NewInt(2))
	_, postPedersen := postPedersens.commitmentsFromSecrets(g, nil, big.NewInt(6))
	_, mulPedersen := mulPedersens.commitmentsFromSecrets(g, nil, big.NewInt(3))
	_, modPedersen := modPedersens.commitmentsFromSecrets(g, nil, big.NewInt(11))

	bases := zkproof.NewBaseMerge(&g, &bitPedersen, &prePedersen, &postPedersen, &mulPedersen, &modPedersen)
	secrets := zkproof.NewSecretMerge(&bitPedersen, &prePedersen, &postPedersen, &mulPedersen, &modPedersen)

	s := newExpStepBStructure("bit", "pre", "post", "mul", "mod", 4)

	assert.True(t, s.isTrue(&secrets), "Proof premis rejected")

	listSecrets, commit := s.commitmentsFromSecrets(g, []*big.Int{}, &bases, &secrets)

	assert.Equal(t, len(listSecrets), s.numCommitments(), "NumCommitments is off")
	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	Follower.(*TestFollower).count = 0

	proof := s.buildProof(g, big.NewInt(12345), commit, &secrets)

	require.True(t, s.verifyProofStructure(proof), "Proof structure rejected")

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

	proofBases := zkproof.NewBaseMerge(&g, &bitProof, &preProof, &postProof, &mulProof, &modProof)

	listProof := s.commitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &proofBases, proof)

	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	assert.Equal(t, listSecrets, listProof, "Commitment lists differ.")
}

func TestExpStepBFake(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for expStepB proof testing")

	s := newExpStepBStructure("bit", "pre", "post", "mul", "mod", 4)

	proof := s.fakeProof(g)
	assert.True(t, s.verifyProofStructure(proof), "Fake proof structure rejected")
}

func TestExpStepBJSON(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for expStepB proof testing")

	s := newExpStepBStructure("bit", "pre", "post", "mul", "mod", 4)

	proofBefore := s.fakeProof(g)
	proofJSON, err := json.Marshal(proofBefore)

	require.NoError(t, err, "error during json marshal")

	var proofAfter ExpStepBProof
	err = json.Unmarshal(proofJSON, &proofAfter)

	require.NoError(t, err, "error during json unmarshal")
	assert.True(t, s.verifyProofStructure(proofAfter), "json'ed proof structure rejected")
}

func TestExpStepBVerifyStructure(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for expStepB proof testing")

	s := newExpStepBStructure("bit", "pre", "post", "mul", "mod", 4)

	proof := s.fakeProof(g)
	proof.Mul.Hresult.Result = nil
	assert.False(t, s.verifyProofStructure(proof), "Accepting missing mulresult")

	proof = s.fakeProof(g)
	proof.Bit.Result = nil
	assert.False(t, s.verifyProofStructure(proof), "Accepting missing bithiderresult")

	proof = s.fakeProof(g)
	proof.MultiplicationProof.Hider.Result = nil
	assert.False(t, s.verifyProofStructure(proof), "Accepting corrupted multiplicationproof")
}
