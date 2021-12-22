package keyproof

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/zkproof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type RangeTestSecret struct {
	secrets     map[string]*big.Int
	randomizers map[string]*big.Int
}

func (rs *RangeTestSecret) Secret(name string) *big.Int {
	res, ok := rs.secrets[name]
	if ok {
		return res
	}
	return nil
}

func (rs *RangeTestSecret) Randomizer(name string) *big.Int {
	res, ok := rs.randomizers[name]
	if ok {
		return res
	}
	return nil
}

type RangeTestCommit struct {
	commits map[string]*big.Int
}

func (rc *RangeTestCommit) Names() (ret []string) {
	for name := range rc.commits {
		ret = append(ret, name)
	}
	return
}
func (rc *RangeTestCommit) Base(name string) *big.Int {
	res, ok := rc.commits[name]
	if ok {
		return res
	}
	return nil
}
func (rc *RangeTestCommit) Exp(ret *big.Int, name string, exp, P *big.Int) bool {
	base := rc.Base(name)
	ret.Exp(base, exp, P)
	return true
}

func listCmp(a []*big.Int, b []*big.Int) bool {
	if len(a) != len(b) {
		return false
	}
	for i, ai := range a {
		if ai == nil || b[i] == nil {
			return false
		}
		if ai.Cmp(b[i]) != 0 {
			return false
		}
	}
	return true
}

func TestRangeProofBasic(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Range proof testing")

	Follower.(*TestFollower).count = 0

	var s rangeProofStructure
	s.Lhs = []zkproof.LhsContribution{
		zkproof.LhsContribution{"x", big.NewInt(1)},
	}
	s.Rhs = []zkproof.RhsContribution{
		zkproof.RhsContribution{"g", "x", 1},
	}
	s.rangeSecret = "x"
	s.l1 = 3
	s.l2 = 2

	var secret RangeTestSecret
	secret.secrets = map[string]*big.Int{
		"x": big.NewInt(7),
	}
	secret.randomizers = map[string]*big.Int{} // These shouldn't be neccessary, so detect use with a panic

	var commit RangeTestCommit
	commit.commits = map[string]*big.Int{
		"x": new(big.Int).Exp(g.G, big.NewInt(7), g.P),
	}

	bases := zkproof.NewBaseMerge(&g, &commit)

	assert.True(t, s.IsTrue(g, &bases, &secret), "Statement incorrectly declared false")

	listSecret, rpcommit := s.commitmentsFromSecrets(g, []*big.Int{}, &bases, &secret)

	assert.Equal(t, len(listSecret), s.numCommitments(), "NumCommitments is off")
	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	Follower.(*TestFollower).count = 0

	proof := s.buildProof(g, big.NewInt(12345), rpcommit, &secret)

	assert.True(t, s.verifyProofStructure(proof), "Proof structure rejected")

	listProof := s.commitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &bases, proof)

	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	assert.Equal(t, listSecret, listProof, "Commitment lists disagree")
}

func TestRangeProofComplex(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Range proof testing")

	Follower.(*TestFollower).count = 0

	var s rangeProofStructure
	s.Lhs = []zkproof.LhsContribution{
		zkproof.LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []zkproof.RhsContribution{
		zkproof.RhsContribution{"g", "x", 1},
		zkproof.RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	var secret RangeTestSecret
	secret.secrets = map[string]*big.Int{
		"x":  big.NewInt(7),
		"xh": big.NewInt(21),
	}
	secret.randomizers = map[string]*big.Int{} // These shouldn't be neccessary, so detect use with a panic

	var commit RangeTestCommit
	commit.commits = map[string]*big.Int{
		"c": new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Exp(g.G, big.NewInt(7), g.P),
				new(big.Int).Exp(g.H, big.NewInt(21), g.P)),
			g.P),
	}

	bases := zkproof.NewBaseMerge(&g, &commit)

	assert.True(t, s.IsTrue(g, &bases, &secret), "Statement incorrectly declared false")

	listSecret, rpcommit := s.commitmentsFromSecrets(g, []*big.Int{}, &bases, &secret)

	assert.Equal(t, len(listSecret), s.numCommitments(), "NumCommitments is off")
	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	Follower.(*TestFollower).count = 0

	proof := s.buildProof(g, big.NewInt(12345), rpcommit, &secret)

	assert.True(t, s.verifyProofStructure(proof), "Proof structure rejected")

	listProof := s.commitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &bases, proof)

	assert.Equal(t, int(Follower.(*TestFollower).count), s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	assert.Equal(t, listSecret, listProof, "Commitment lists disagree")
}

func TestRangeProofVerifyStructureEmpty(t *testing.T) {
	var proof RangeProof
	var s rangeProofStructure
	s.Lhs = []zkproof.LhsContribution{
		zkproof.LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []zkproof.RhsContribution{
		zkproof.RhsContribution{"g", "x", 1},
		zkproof.RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	assert.False(t, s.verifyProofStructure(proof), "Accepting empty proof")
}

func TestRangeProofVerifyStructureMissingVar(t *testing.T) {
	var proof RangeProof
	var s rangeProofStructure
	s.Lhs = []zkproof.LhsContribution{
		zkproof.LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []zkproof.RhsContribution{
		zkproof.RhsContribution{"g", "x", 1},
		zkproof.RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	tlist := []*big.Int{}
	for i := 0; i < rangeProofIters; i++ {
		tlist = append(tlist, big.NewInt(1))
	}

	proof.Results = map[string][]*big.Int{
		"x": tlist,
	}

	assert.False(t, s.verifyProofStructure(proof), "Accepting missing variable in proof")
}

func TestRangeProofVerifyStructureTooShortVar(t *testing.T) {
	var proof RangeProof
	var s rangeProofStructure
	s.Lhs = []zkproof.LhsContribution{
		zkproof.LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []zkproof.RhsContribution{
		zkproof.RhsContribution{"g", "x", 1},
		zkproof.RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	tlist := []*big.Int{}
	for i := 0; i < rangeProofIters; i++ {
		tlist = append(tlist, big.NewInt(1))
	}

	proof.Results = map[string][]*big.Int{
		"x":  tlist,
		"xh": tlist[:len(tlist)-1],
	}

	assert.False(t, s.verifyProofStructure(proof), "Accepting variable with too few results in proof")

	proof.Results = map[string][]*big.Int{
		"x":  tlist[:len(tlist)-1],
		"xh": tlist,
	}
	assert.False(t, s.verifyProofStructure(proof), "Accepting variable with too few results in proof")
}

func TestRangeProofVerifyStructureMissingNo(t *testing.T) {
	var proof RangeProof
	var s rangeProofStructure
	s.Lhs = []zkproof.LhsContribution{
		zkproof.LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []zkproof.RhsContribution{
		zkproof.RhsContribution{"g", "x", 1},
		zkproof.RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	tlist := []*big.Int{}
	for i := 0; i < rangeProofIters; i++ {
		tlist = append(tlist, big.NewInt(1))
	}

	hlist := []*big.Int{}
	for i := 0; i < rangeProofIters; i++ {
		hlist = append(hlist, big.NewInt(2))
	}

	hlist[rangeProofIters/2] = nil

	proof.Results = map[string][]*big.Int{
		"x":  hlist,
		"xh": tlist,
	}

	assert.False(t, s.verifyProofStructure(proof), "Accepting variable with missing numbers in proof")
}

func TestRangeProofFake(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Range proof testing")

	var s rangeProofStructure
	s.Lhs = []zkproof.LhsContribution{
		zkproof.LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []zkproof.RhsContribution{
		zkproof.RhsContribution{"g", "x", 1},
		zkproof.RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	proof := s.fakeProof(g)
	assert.True(t, s.verifyProofStructure(proof), "Fake proof structure rejected.")
}

func TestRangeProofJSON(t *testing.T) {
	g, gok := zkproof.BuildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Range proof testing")

	var s rangeProofStructure
	s.Lhs = []zkproof.LhsContribution{
		zkproof.LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []zkproof.RhsContribution{
		zkproof.RhsContribution{"g", "x", 1},
		zkproof.RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	proofBefore := s.fakeProof(g)
	proofJSON, err := json.Marshal(proofBefore)
	require.NoError(t, err, "error during json marshal")

	var proofAfter RangeProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	require.NoError(t, err, "error during json unmarshal")

	assert.True(t, s.verifyProofStructure(proofAfter), "json'ed proof structure rejected")
}
