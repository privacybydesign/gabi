package keyproof

import (
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/zkproof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsSquareProof(t *testing.T) {
	const p = 7
	const q = 11
	const a = 36
	const b = 49

	g, gok := zkproof.BuildGroup(big.NewInt(1439))
	require.True(t, gok, "Failed to setup group for Range proof testing")

	Follower.(*TestFollower).count = 0

	s := newIsSquareProofStructure(big.NewInt(p*q), []*big.Int{big.NewInt(a), big.NewInt(b)})

	listSecret, commit := s.commitmentsFromSecrets(g, []*big.Int{}, big.NewInt(p), big.NewInt(q))

	assert.Equal(t, len(listSecret), s.numCommitments(), "NumCommitments is off")
	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	Follower.(*TestFollower).count = 0

	proof := s.buildProof(g, big.NewInt(12345), commit)

	assert.True(t, s.verifyProofStructure(proof), "Proof structure rejected")

	listProof := s.commitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), proof)

	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	assert.Equal(t, listSecret, listProof, "Commitment lists disagree")
}

func TestIsSquareProofStructure(t *testing.T) {
	const p = 7
	const q = 11
	const a = 36
	const b = 49

	g, gok := zkproof.BuildGroup(big.NewInt(1439))
	require.True(t, gok, "Failed to setup group for Range proof testing")

	s := newIsSquareProofStructure(big.NewInt(p*q), []*big.Int{big.NewInt(a), big.NewInt(b)})
	_, commit := s.commitmentsFromSecrets(g, []*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := s.buildProof(g, big.NewInt(12345), commit)

	backup := proof.NProof.Commit
	proof.NProof.Commit = nil
	assert.False(t, s.verifyProofStructure(proof), "Accepting incorrect NProof commit")
	proof.NProof.Commit = backup

	backuplist := proof.SquaresProof
	proof.SquaresProof = proof.SquaresProof[:len(proof.SquaresProof)-1]
	assert.False(t, s.verifyProofStructure(proof), "Accepting too short SquaresProof")
	proof.SquaresProof = backuplist

	backup = proof.SquaresProof[0].Commit
	proof.SquaresProof[0].Commit = nil
	assert.False(t, s.verifyProofStructure(proof), "Accepting corrupted SquaresProof")
	proof.SquaresProof[0].Commit = backup

	backuplist = proof.RootsProof
	proof.RootsProof = proof.RootsProof[:len(proof.RootsProof)-1]
	assert.False(t, s.verifyProofStructure(proof), "Accepting too short RootsProof")
	proof.RootsProof = backuplist

	backup = proof.RootsProof[1].Commit
	proof.RootsProof[1].Commit = nil
	assert.False(t, s.verifyProofStructure(proof), "Accepting corrupted RootsProof")
	proof.RootsProof[1].Commit = backup

	backuplistB := proof.RootsRangeProof
	proof.RootsRangeProof = proof.RootsRangeProof[:len(proof.RootsRangeProof)-1]
	assert.False(t, s.verifyProofStructure(proof), "Accepting too short RootsRangeProof")
	proof.RootsRangeProof = backuplistB

	backupRP := proof.RootsRangeProof[0]
	proof.RootsRangeProof[0].Results = nil
	assert.False(t, s.verifyProofStructure(proof), "Accepting corrupter RootsRangeProof")
	proof.RootsRangeProof[0] = backupRP

	backuplistC := proof.RootsValidProof
	proof.RootsValidProof = proof.RootsValidProof[:len(proof.RootsValidProof)-1]
	assert.False(t, s.verifyProofStructure(proof), "Accepting too short RootsValidProof")
	proof.RootsValidProof = backuplistC

	backup = proof.RootsValidProof[1].ModMultProof.Commit
	proof.RootsValidProof[1].ModMultProof.Commit = nil
	assert.False(t, s.verifyProofStructure(proof), "Accepting corrupted RootsValidProof")
	proof.RootsValidProof[1].ModMultProof.Commit = backup

	assert.True(t, s.verifyProofStructure(proof), "Testing corrupted proof structure!")
}
