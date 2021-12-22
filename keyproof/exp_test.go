package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/zkproof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpProofFlow(t *testing.T) {
	const a = 2
	const b = 5
	const n = 11
	const r = -1

	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for exp proof testing")

	Follower.(*TestFollower).count = 0

	aPedersens := newPedersenStructure("a")
	bPedersens := newPedersenStructure("b")
	nPedersens := newPedersenStructure("n")
	rPedersens := newPedersenStructure("r")

	_, aPedersen := aPedersens.commitmentsFromSecrets(g, nil, big.NewInt(a))
	_, bPedersen := bPedersens.commitmentsFromSecrets(g, nil, big.NewInt(b))
	_, nPedersen := nPedersens.commitmentsFromSecrets(g, nil, big.NewInt(n))
	_, rPedersen := rPedersens.commitmentsFromSecrets(g, nil, big.NewInt(r))

	bases := zkproof.NewBaseMerge(&g, &aPedersen, &bPedersen, &nPedersen, &rPedersen)
	secrets := zkproof.NewSecretMerge(&aPedersen, &bPedersen, &nPedersen, &rPedersen)

	s := newExpProofStructure("a", "b", "n", "r", 4)

	assert.True(t, s.isTrue(&secrets), "proof premise deemed false")

	listSecrets, commit := s.commitmentsFromSecrets(g, []*big.Int{}, &bases, &secrets)

	assert.Equal(t, len(listSecrets), s.numCommitments(), "NumCommitments is off")
	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	Follower.(*TestFollower).count = 0

	proof := s.buildProof(g, big.NewInt(12345), commit, &secrets)

	require.True(t, s.verifyProofStructure(big.NewInt(12345), proof), "proof structure rejected")

	aProof := aPedersens.buildProof(g, big.NewInt(12345), aPedersen)
	aProof.setName("a")
	bProof := bPedersens.buildProof(g, big.NewInt(12345), bPedersen)
	bProof.setName("b")
	nProof := nPedersens.buildProof(g, big.NewInt(12345), nPedersen)
	nProof.setName("n")
	rProof := rPedersens.buildProof(g, big.NewInt(12345), rPedersen)
	rProof.setName("r")

	proofBases := zkproof.NewBaseMerge(&g, &aProof, &bProof, &nProof, &rProof)
	proofs := zkproof.NewProofMerge(&aProof, &bProof, &nProof, &rProof)

	listProof := s.commitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &proofBases, &proofs, proof)

	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	assert.Equal(t, listSecrets, listProof, "Commitment lists differ")
}

func TestExpProofFake(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for exp proof testing")

	s := newExpProofStructure("a", "b", "n", "r", 4)

	proof := s.fakeProof(g, big.NewInt(12345))
	assert.True(t, s.verifyProofStructure(big.NewInt(12345), proof), "fake proof structure rejected")
}

func TestExpProofJSON(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for exp proof testing")

	s := newExpProofStructure("a", "b", "n", "r", 4)

	proofBefore := s.fakeProof(g, big.NewInt(12345))
	proofJSON, err := json.Marshal(proofBefore)
	require.NoError(t, err, "error during json marshal")

	var proofAfter ExpProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	require.NoError(t, err, "error during json unmarshal")

	assert.True(t, s.verifyProofStructure(big.NewInt(12345), proofAfter), "json'ed proof structure rejected")
}

func TestExpProofVerifyStructure(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for exp proof testing")

	s := newExpProofStructure("a", "b", "n", "r", 4)

	proof := s.fakeProof(g, big.NewInt(12345))
	proof.ExpBitEqHider.Result = nil
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "accepting missing expbiteqresult")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.ExpBitProofs = proof.ExpBitProofs[:len(proof.ExpBitProofs)-1]
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "accepting too short expbitproofs")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.ExpBitProofs[2].Commit = nil
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "accepting corrupted expbitproof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.BasePowProofs = proof.BasePowProofs[:len(proof.BasePowProofs)-1]
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "accepting too short basepowproofs")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.BasePowProofs[1].Commit = nil
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting corrupted basepowproofs")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.BasePowRangeProofs = proof.BasePowRangeProofs[:len(proof.BasePowRangeProofs)-1]
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting too short basepowrangeproofs")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.BasePowRangeProofs[1].Results = nil
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting corrupted basepowrangeproofs")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.BasePowRelProofs = proof.BasePowRelProofs[:len(proof.BasePowRelProofs)-1]
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting too short basepowrelproofs")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.BasePowRelProofs[2].Hider.Result = nil
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting corrupted basepowrelproof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.StartProof.Commit = nil
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting corrupted startproof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.InterResProofs = proof.InterResProofs[:len(proof.InterResProofs)-1]
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting too short interresproofs")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.InterResProofs[1].Commit = nil
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting corrupted interresproof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.InterResRangeProofs = proof.InterResRangeProofs[:len(proof.InterResRangeProofs)-1]
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting too short interresrangeproofs")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.InterResRangeProofs[2].Results = nil
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting corrupted interresrangeproofs")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.InterStepsProofs = proof.InterStepsProofs[:len(proof.InterStepsProofs)-1]
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting too short interstepsproof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.InterStepsProofs[2].Achallenge = nil
	assert.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting corrupted interstepsproof")
}
