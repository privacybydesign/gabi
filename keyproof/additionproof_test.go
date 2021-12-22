package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/zkproof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdditionProofFlow(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Addition proof testing")

	Follower.(*TestFollower).count = 0

	const a = 4
	const b = 3
	const d = 2
	const n = 5

	a1s := newPedersenStructure("a1")
	a2s := newPedersenStructure("a2")
	mods := newPedersenStructure("mod")
	results := newPedersenStructure("result")

	_, a1 := a1s.commitmentsFromSecrets(g, []*big.Int{}, big.NewInt(a))
	_, a2 := a2s.commitmentsFromSecrets(g, []*big.Int{}, big.NewInt(b))
	_, mod := mods.commitmentsFromSecrets(g, []*big.Int{}, big.NewInt(n))
	_, result := results.commitmentsFromSecrets(g, []*big.Int{}, big.NewInt(d))

	bases := zkproof.NewBaseMerge(&g, &a1, &a2, &mod, &result)
	secrets := zkproof.NewSecretMerge(&a1, &a2, &mod, &result)

	s := newAdditionProofStructure("a1", "a2", "mod", "result", 3)
	assert.True(t, s.isTrue(&secrets), "Incorrectly assessed proof setup as incorrect.")

	listSecrets, commit := s.commitmentsFromSecrets(g, []*big.Int{}, &bases, &secrets)

	assert.Equal(t, len(listSecrets), s.numCommitments(), "NumCommitments is off")
	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")

	Follower.(*TestFollower).count = 0

	proof := s.buildProof(g, big.NewInt(12345), commit, &secrets)
	a1proof := a1s.buildProof(g, big.NewInt(12345), a1)
	a1proof.setName("a1")
	a2proof := a2s.buildProof(g, big.NewInt(12345), a2)
	a2proof.setName("a2")
	modproof := mods.buildProof(g, big.NewInt(12345), mod)
	modproof.setName("mod")
	resultproof := results.buildProof(g, big.NewInt(12345), result)
	resultproof.setName("result")

	basesProof := zkproof.NewBaseMerge(&g, &a1proof, &a2proof, &modproof, &resultproof)
	proofdata := zkproof.NewProofMerge(&a1proof, &a2proof, &modproof, &resultproof)

	assert.True(t, s.verifyProofStructure(proof), "Proof structure marked as invalid.")

	listProof := s.commitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &basesProof, &proofdata, proof)

	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	assert.Equal(t, listSecrets, listProof, "Commitment lists differ.")
}

func TestAdditionProofVerifyStructure(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Multiplication proof testing")

	var proof AdditionProof
	s := newAdditionProofStructure("a1", "a2", "mod", "result", 3)

	proof = s.fakeProof(g)
	proof.RangeProof.Results = nil
	require.False(t, s.verifyProofStructure(proof), "Accepting missing rangeproof.")

	proof = s.fakeProof(g)
	proof.ModAddProof.Result = nil
	require.False(t, s.verifyProofStructure(proof), "Accepting missing modaddresult.")

	proof = s.fakeProof(g)
	proof.HiderProof.Result = nil
	require.False(t, s.verifyProofStructure(proof), "Accepting missing hiderresult.")
}

func TestAdditionProofFake(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Multiplication proof testing")

	s := newAdditionProofStructure("a1", "a2", "mod", "result", 3)

	proof := s.fakeProof(g)
	require.True(t, s.verifyProofStructure(proof), "Rejecting fake proof structure.")
}

func TestAdditionProofJSON(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Multiplication proof testing")

	s := newAdditionProofStructure("a1", "a2", "mod", "result", 3)

	proofBefore := s.fakeProof(g)

	proofJSON, err := json.Marshal(proofBefore)
	require.NoError(t, err, "error during json marhsal")

	var proofAfter AdditionProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	require.NoError(t, err, "error during json unmarshal")

	assert.True(t, s.verifyProofStructure(proofAfter), "json'ed proof structure invalid")
}
