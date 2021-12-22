package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/zkproof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiplicationProofFlow(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Multiplication proof testing")

	Follower.(*TestFollower).count = 0

	const a = 2
	const b = 3
	const d = 1
	const n = 5

	m1s := newPedersenStructure("m1")
	m2s := newPedersenStructure("m2")
	mods := newPedersenStructure("mod")
	results := newPedersenStructure("result")

	_, m1 := m1s.commitmentsFromSecrets(g, nil, big.NewInt(a))
	_, m2 := m2s.commitmentsFromSecrets(g, nil, big.NewInt(b))
	_, mod := mods.commitmentsFromSecrets(g, nil, big.NewInt(n))
	_, result := results.commitmentsFromSecrets(g, nil, big.NewInt(d))

	bases := zkproof.NewBaseMerge(&g, &m1, &m2, &mod, &result)
	secrets := zkproof.NewSecretMerge(&m1, &m2, &mod, &result)

	s := newMultiplicationProofStructure("m1", "m2", "mod", "result", 3)
	assert.True(t, s.isTrue(&secrets), "Incorrectly assessed proof setup as incorrect.")

	listSecrets, commit := s.commitmentsFromSecrets(g, nil, &bases, &secrets)

	assert.Equal(t, len(listSecrets), s.numCommitments(), "NumCommitments is off")
	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	Follower.(*TestFollower).count = 0

	proof := s.buildProof(g, big.NewInt(12345), commit, &secrets)
	m1proof := m1s.buildProof(g, big.NewInt(12345), m1)
	m1proof.setName("m1")
	m2proof := m2s.buildProof(g, big.NewInt(12345), m2)
	m2proof.setName("m2")
	modproof := mods.buildProof(g, big.NewInt(12345), mod)
	modproof.setName("mod")
	resultproof := results.buildProof(g, big.NewInt(12345), result)
	resultproof.setName("result")

	basesProof := zkproof.NewBaseMerge(&g, &m1proof, &m2proof, &modproof, &resultproof)
	proofdata := zkproof.NewProofMerge(&m1proof, &m2proof, &modproof, &resultproof)

	require.True(t, s.verifyProofStructure(proof), "Proof structure marked as invalid.")

	listProof := s.commitmentsFromProof(g, nil, big.NewInt(12345), &basesProof, &proofdata, proof)

	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	Follower.(*TestFollower).count = 0

	assert.Equal(t, listSecrets, listProof, "Commitment lists differ.")
}

func TestMultiplicationProofFake(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Multiplication proof testing")

	s := newMultiplicationProofStructure("m1", "m2", "mod", "result", 3)

	proof := s.fakeProof(g)

	assert.True(t, s.verifyProofStructure(proof), "Fake proof structure rejected.")
}

func TestMultiplicationProofVerifyStructure(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Multiplication proof testing")

	var proof MultiplicationProof
	s := newMultiplicationProofStructure("m1", "m2", "mod", "result", 3)

	proof = s.fakeProof(g)
	proof.ModMultProof.Commit = nil
	assert.False(t, s.verifyProofStructure(proof), "Accepting malformed ModMultProof")

	proof = s.fakeProof(g)
	proof.Hider.Result = nil
	assert.False(t, s.verifyProofStructure(proof), "Accepting missing HiderResult")

	proof = s.fakeProof(g)
	proof.RangeProof.Results = nil
	assert.False(t, s.verifyProofStructure(proof), "Accepting malformed range proof")
}

func TestMultiplicationProofJSON(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Multiplication proof testing")

	s := newMultiplicationProofStructure("m1", "m2", "mod", "result", 3)

	proofBefore := s.fakeProof(g)
	proofJSON, err := json.Marshal(proofBefore)
	require.NoError(t, err, "error during json marshal")

	var proofAfter MultiplicationProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	require.NoError(t, err, "error during json unmarshal")

	assert.True(t, s.verifyProofStructure(proofAfter), "json'ed proof structure rejected")
}
