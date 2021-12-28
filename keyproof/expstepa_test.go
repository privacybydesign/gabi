package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/zkproof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpStepAFlow(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for expStepA proof testing")

	Follower.(*TestFollower).count = 0

	bitPedersens := newPedersenStructure("bit")
	prePedersens := newPedersenStructure("pre")
	postPedersens := newPedersenStructure("post")

	_, bitPedersen := bitPedersens.commitmentsFromSecrets(g, nil, big.NewInt(0))
	_, prePedersen := prePedersens.commitmentsFromSecrets(g, nil, big.NewInt(5))
	_, postPedersen := postPedersens.commitmentsFromSecrets(g, nil, big.NewInt(5))

	bases := zkproof.NewBaseMerge(&g, &bitPedersen, &prePedersen, &postPedersen)
	secrets := zkproof.NewSecretMerge(&bitPedersen, &prePedersen, &postPedersen)

	s := newExpStepAStructure("bit", "pre", "post")

	assert.True(t, s.isTrue(&secrets), "Statement validity rejected")

	listSecrets, commit := s.commitmentsFromSecrets(g, []*big.Int{}, &bases, &secrets)

	assert.Equal(t, len(listSecrets), s.numCommitments(), "NumCommitments is off")
	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	Follower.(*TestFollower).count = 0

	proof := s.buildProof(g, big.NewInt(12345), commit, &secrets)

	require.True(t, s.verifyProofStructure(proof), "Proof structure rejected.")

	bitProof := bitPedersens.buildProof(g, big.NewInt(12345), bitPedersen)
	bitProof.setName("bit")
	preProof := prePedersens.buildProof(g, big.NewInt(12345), prePedersen)
	preProof.setName("pre")
	postProof := postPedersens.buildProof(g, big.NewInt(12345), postPedersen)
	postProof.setName("post")

	proofBases := zkproof.NewBaseMerge(&g, &bitProof, &preProof, &postProof)

	listProof := s.commitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &proofBases, proof)

	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	assert.Equal(t, listSecrets, listProof, "Commitment lists differ.")
}

func TestExpStepAFake(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for expStepA proof testing")

	s := newExpStepAStructure("bit", "pre", "post")

	proof := s.fakeProof(g)
	assert.True(t, s.verifyProofStructure(proof), "Fake proof structure rejected.")
}

func TestExpStepAJSON(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for expStepA proof testing")

	s := newExpStepAStructure("bit", "pre", "post")

	proofBefore := s.fakeProof(g)
	proofJSON, err := json.Marshal(proofBefore)
	require.NoError(t, err, "error during json marshal")

	var proofAfter ExpStepAProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	require.NoError(t, err, "error during json unmarshal")

	assert.True(t, s.verifyProofStructure(proofAfter), "json'ed proof structure rejected.")
}

func TestExpStepAVerifyStructure(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for expStepA proof testing")

	s := newExpStepAStructure("bit", "pre", "post")

	proof := s.fakeProof(g)

	proof.Bit.Result = nil
	assert.False(t, s.verifyProofStructure(proof), "Accepting missing bithiderresult")

	proof.Bit.Result = proof.EqualityHider.Result
	proof.EqualityHider.Result = nil
	assert.False(t, s.verifyProofStructure(proof), "Accepting missing equalityhiderresult")
}
