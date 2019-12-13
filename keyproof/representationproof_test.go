package keyproof

import (
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type RepTestSecret struct {
	secrets     map[string]*big.Int
	randomizers map[string]*big.Int
}

func (rs *RepTestSecret) secret(name string) *big.Int {
	res, ok := rs.secrets[name]
	if ok {
		return res
	}
	return nil
}

func (rs *RepTestSecret) randomizer(name string) *big.Int {
	res, ok := rs.randomizers[name]
	if ok {
		return res
	}
	return nil
}

type RepTestProof struct {
	results map[string]*big.Int
}

func (rp *RepTestProof) result(name string) *big.Int {
	res, ok := rp.results[name]
	if ok {
		return res
	}
	return nil
}

type RepTestCommit struct {
	commits map[string]*big.Int
}

func (rc *RepTestCommit) base(name string) *big.Int {
	res, ok := rc.commits[name]
	if ok {
		return res
	}
	return nil
}
func (rc *RepTestCommit) exp(ret *big.Int, name string, exp, P *big.Int) bool {
	base := rc.base(name)
	ret.Exp(base, exp, P)
	return true
}
func (rc *RepTestCommit) names() (ret []string) {
	for name := range rc.commits {
		ret = append(ret, name)
	}
	return
}

func TestRepresentationProofBasics(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Representation proof testing")

	Follower.(*TestFollower).count = 0

	var s representationProofStructure
	s.lhs = []lhsContribution{
		lhsContribution{"x", big.NewInt(1)},
	}
	s.rhs = []rhsContribution{
		rhsContribution{"g", "x", 1},
	}

	var secret RepTestSecret
	secret.secrets = map[string]*big.Int{"x": big.NewInt(10)}
	secret.randomizers = map[string]*big.Int{"x": big.NewInt(15)}

	var commit RepTestCommit
	commit.commits = map[string]*big.Int{"x": new(big.Int).Exp(g.g, secret.secrets["x"], g.p)}

	var proof RepTestProof
	proof.results = map[string]*big.Int{"x": big.NewInt(5)}

	bases := newBaseMerge(&g, &commit)

	listSecrets := s.generateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secret)

	assert.Equal(t, len(listSecrets), s.numCommitments(), "NumCommitments is off")
	assert.Equal(t, Follower.(*TestFollower).count, s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	Follower.(*TestFollower).count = 0

	listProofs := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(1), &bases, &proof)

	assert.Equal(t, Follower.(*TestFollower).count, s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	assert.True(t, s.isTrue(g, &bases, &secret), "Incorrect rejection of truth")
	assert.Equal(t, listSecrets, listProofs, "commitment lists different")
}

func TestRepresentationProofComplex(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	require.True(t, gok, "Failed to setup group for Representation proof testing")

	var s representationProofStructure
	s.lhs = []lhsContribution{
		lhsContribution{"c", big.NewInt(4)},
	}
	s.rhs = []rhsContribution{
		rhsContribution{"g", "x", 2},
		rhsContribution{"h", "y", 1},
	}

	Follower.(*TestFollower).count = 0

	var secret RepTestSecret
	secret.secrets = map[string]*big.Int{
		"x": big.NewInt(4),
		"y": big.NewInt(2),
	}
	secret.randomizers = map[string]*big.Int{
		"x": big.NewInt(12),
		"y": big.NewInt(21),
	}

	var commit RepTestCommit
	commit.commits = map[string]*big.Int{
		"c": new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Exp(g.g, big.NewInt(2), g.p),
				new(big.Int).Exp(g.h, big.NewInt(12), g.p)),
			g.p),
	}

	var proof RepTestProof
	proof.results = map[string]*big.Int{
		"x": big.NewInt(4),
		"y": big.NewInt(17),
	}

	bases := newBaseMerge(&g, &commit)

	listSecrets := s.generateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secret)

	assert.Equal(t, len(listSecrets), s.numCommitments(), "NumCommitments is off")
	assert.Equal(t, Follower.(*TestFollower).count, s.numRangeProofs(), "Logging is off GenerateCommitmentsFromSecrets")
	Follower.(*TestFollower).count = 0

	listProofs := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(2), &bases, &proof)

	assert.Equal(t, Follower.(*TestFollower).count, s.numRangeProofs(), "Logging is off on GenerateCommitmentsFromProof")
	assert.True(t, s.isTrue(g, &bases, &secret), "Incorrect rejection of truth")
	assert.Equal(t, listSecrets, listProofs, "Commitment lists different")
}
