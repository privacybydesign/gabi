package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/zkproof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPedersenProofFlow(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group")

	s := newPedersenStructure("x")

	Follower.(*TestFollower).count = 0

	listSecrets, commit := s.commitmentsFromSecrets(g, []*big.Int{}, big.NewInt(15))
	proof := s.buildProof(g, big.NewInt(1), commit)

	assert.Equal(t, len(listSecrets), s.numCommitments(), "NumCommitments is off")
	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	Follower.(*TestFollower).count = 0

	proof.setName("x")

	assert.True(t, s.verifyProofStructure(proof), "Rejecting proof structure")

	listProof := s.commitmentsFromProof(g, []*big.Int{}, big.NewInt(1), proof)

	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	Follower.(*TestFollower).count = 0

	assert.Equal(t, listSecrets, listProof, "Commitment lists differ")
}

func TestPedersenProofVerifyStructure(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Representation proof testing")

	s := newPedersenStructure("x")

	proof := s.fakeProof(g)
	proof.Commit = nil
	require.False(t, s.verifyProofStructure(proof), "Accepting incorrectly structured proof")

	proof = s.fakeProof(g)
	proof.Sresult.Result = nil
	require.False(t, s.verifyProofStructure(proof), "Accepting incorrectly structured proof")

	proof = s.fakeProof(g)
	proof.Hresult.Result = nil
	require.False(t, s.verifyProofStructure(proof), "Accepting incorrectly structured proof")
}

func TestPedersenProofFake(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Representation proof testing")

	s := newPedersenStructure("x")
	proof := s.fakeProof(g)
	assert.True(t, s.verifyProofStructure(proof), "Fakeproof has incorrect structure")
}

func TestPedersenProofJSON(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Representation proof testing")

	s := newPedersenStructure("x")

	listSecrets, commit := s.commitmentsFromSecrets(g, []*big.Int{}, big.NewInt(15))

	proofBefore := s.buildProof(g, big.NewInt(12345), commit)
	proofJSON, err := json.Marshal(&proofBefore)
	assert.NoError(t, err, "Error converting to JSON")

	var proofAfter PedersenProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	assert.NoError(t, err, "Error parsing json")
	assert.True(t, s.verifyProofStructure(proofAfter), "Invalid proof structure after JSON")

	listProof := s.commitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), proofAfter)
	assert.Equal(t, listSecrets, listProof, "Commitment lists differ.")
}
