package keyproof

import "testing"
import "github.com/privacybydesign/gabi/big"

func TestIsSquareProof(t *testing.T) {
	const p = 7
	const q = 11
	const a = 36
	const b = 49

	g, gok := buildGroup(big.NewInt(1439))
	if !gok {
		t.Error("Failed to setup group for Range proof testing")
		return
	}

	Follower.(*TestFollower).count = 0

	s := newIsSquareProofStructure(big.NewInt(p*q), []*big.Int{big.NewInt(a), big.NewInt(b)})

	listSecret, commit := s.generateCommitmentsFromSecrets(g, []*big.Int{}, big.NewInt(p), big.NewInt(q))

	if len(listSecret) != s.numCommitments() {
		t.Errorf("NumCommitments is off %v %v", len(listSecret), s.numCommitments())
	}

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off GenerateCommitmentsFromSecrets")
	}
	Follower.(*TestFollower).count = 0

	proof := s.buildProof(g, big.NewInt(12345), commit)

	if !s.verifyProofStructure(proof) {
		t.Error("Proof structure rejected")
		return
	}

	listProof := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), proof)

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}

	if !listCmp(listSecret, listProof) {
		t.Error("Commitment lists disagree")
	}
}

func TestIsSquareProofStructure(t *testing.T) {
	const p = 7
	const q = 11
	const a = 36
	const b = 49

	g, gok := buildGroup(big.NewInt(1439))
	if !gok {
		t.Error("Failed to setup group for Range proof testing")
		return
	}

	s := newIsSquareProofStructure(big.NewInt(p*q), []*big.Int{big.NewInt(a), big.NewInt(b)})
	_, commit := s.generateCommitmentsFromSecrets(g, []*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := s.buildProof(g, big.NewInt(12345), commit)

	backup := proof.NProof.Commit
	proof.NProof.Commit = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting incorrect NProof commit")
	}
	proof.NProof.Commit = backup

	backuplist := proof.SquaresProof
	proof.SquaresProof = proof.SquaresProof[:len(proof.SquaresProof)-1]
	if s.verifyProofStructure(proof) {
		t.Error("Accepting too short SquaresProof")
	}
	proof.SquaresProof = backuplist

	backup = proof.SquaresProof[0].Commit
	proof.SquaresProof[0].Commit = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting corrupted SquaresProof")
	}
	proof.SquaresProof[0].Commit = backup

	backuplist = proof.RootsProof
	proof.RootsProof = proof.RootsProof[:len(proof.RootsProof)-1]
	if s.verifyProofStructure(proof) {
		t.Error("Accepting too short RootsProof")
	}
	proof.RootsProof = backuplist

	backup = proof.RootsProof[1].Commit
	proof.RootsProof[1].Commit = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting corrupted RootsProof")
	}
	proof.RootsProof[1].Commit = backup

	backuplistB := proof.RootsRangeProof
	proof.RootsRangeProof = proof.RootsRangeProof[:len(proof.RootsRangeProof)-1]
	if s.verifyProofStructure(proof) {
		t.Error("Accepting too short RootsRangeProof")
	}
	proof.RootsRangeProof = backuplistB

	backupRP := proof.RootsRangeProof[0]
	proof.RootsRangeProof[0].Results = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting corrupter RootsRangeProof")
	}
	proof.RootsRangeProof[0] = backupRP

	backuplistC := proof.RootsValidProof
	proof.RootsValidProof = proof.RootsValidProof[:len(proof.RootsValidProof)-1]
	if s.verifyProofStructure(proof) {
		t.Error("Accepting too short RootsValidProof")
	}
	proof.RootsValidProof = backuplistC

	backup = proof.RootsValidProof[1].ModMultProof.Commit
	proof.RootsValidProof[1].ModMultProof.Commit = nil
	if s.verifyProofStructure(proof) {
		t.Error("Accepting corrupted RootsValidProof")
	}
	proof.RootsValidProof[1].ModMultProof.Commit = backup

	if !s.verifyProofStructure(proof) {
		t.Error("Testing corrupted proof structure!")
	}
}
