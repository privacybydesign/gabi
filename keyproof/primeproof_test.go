package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/safeprime"
	"github.com/privacybydesign/gabi/zkproof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrimeProofFlow(t *testing.T) {
	g, gok := zkproof.BuildGroup(testP)
	require.True(t, gok, "Failed to setup group for Prime proof testing")

	Follower.(*TestFollower).count = 0

	s := newPrimeProofStructure("p", uint(testP.BitLen())-2)

	p, err := safeprime.Generate(testP.BitLen()-2, nil)
	require.NoError(t, err)

	pCommits := newPedersenStructure("p")
	_, pCommit := pCommits.commitmentsFromSecrets(g, nil, p)
	bases := zkproof.NewBaseMerge(&g, &pCommit)

	listSecrets, commit := s.commitmentsFromSecrets(g, []*big.Int{}, &bases, &pCommit)

	require.Equal(t, len(listSecrets), s.numCommitments(), "NumCommitments is off")
	require.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	Follower.(*TestFollower).count = 0

	proof := s.buildProof(g, big.NewInt(12345), commit, &pCommit)
	pProof := pCommits.buildProof(g, big.NewInt(12345), pCommit)
	pProof.setName("p")

	basesProof := zkproof.NewBaseMerge(&g, &pProof)

	require.True(t, s.verifyProofStructure(big.NewInt(12345), proof), "Proof structure rejected.")

	listProof := s.commitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &basesProof, &pProof, proof)

	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	assert.Equal(t, listSecrets, listProof, "Commitment lists differ.")
}

func TestPrimeProofFake(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Prime proof testing")

	s := newPrimeProofStructure("p", 4)

	proof := s.fakeProof(g, big.NewInt(12345))

	assert.True(t, s.verifyProofStructure(big.NewInt(12345), proof), "Fake proof structure rejected.")
}

func TestPrimeProofJSON(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Prime proof testing")

	s := newPrimeProofStructure("p", 4)

	proofBefore := s.fakeProof(g, big.NewInt(12345))
	proofJSON, err := json.Marshal(proofBefore)
	require.NoError(t, err, "error during json marshal")

	var proofAfter PrimeProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	require.NoError(t, err, "error during json unmarshal")

	assert.True(t, s.verifyProofStructure(big.NewInt(12345), proofAfter), "json'ed proof structure rejected")
}

func TestPrimeProofVerify(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Prime proof testing")

	s := newPrimeProofStructure("p", 4)

	proof := s.fakeProof(g, big.NewInt(12345))
	proof.PreaCommit.Commit = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting wrong prea pedersen proof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.HalfPCommit.Commit = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting wrong halfp pedersen proof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.ACommit.Commit = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting wrong a pedersen proof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AnegCommit.Commit = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting wrong aneg pedersen proof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AResCommit.Commit = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting wrong aRes pedersen proof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AnegResCommit.Commit = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting wrong anegRes pedersen proof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.PreaMod.Result = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting missing preamodresult")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.PreaHider.Result = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting missing preahiderresult")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.APlus1.Result = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting missing aPlus1Result")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AMin1.Result = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting missing aMin1Result")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.APlus1Challenge = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting missing aPlus1Challenge")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AMin1Challenge = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting missing aMin1Challenge")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AMin1Challenge.Set(big.NewInt(1))
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting incorrect challenges")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.PreaRangeProof.Results = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting wrong prearangeproof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.ARangeProof.Results = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting wrong arangeproof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AnegRangeProof.Results = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting wrong anegrangeproof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.PreaModRangeProof.Results = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting wrong preamodrangeproof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AExpProof.ExpBitEqHider.Result = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting wrong aexpproof")

	proof = s.fakeProof(g, big.NewInt(12345))
	proof.AnegExpProof.ExpBitEqHider.Result = nil
	require.False(t, s.verifyProofStructure(big.NewInt(12345), proof), "Accepting wrong anegexpproof")
}
