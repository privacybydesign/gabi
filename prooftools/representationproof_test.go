package prooftools_test

import (
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/keyproof"
	"github.com/privacybydesign/gabi/prooftools"
	"github.com/stretchr/testify/assert"
)

type RepTestSecret struct {
	secrets     map[string]*big.Int
	randomizers map[string]*big.Int
}

func (rs *RepTestSecret) Secret(name string) *big.Int {
	return rs.secrets[name]
}

func (rs *RepTestSecret) Randomizer(name string) *big.Int {
	return rs.randomizers[name]
}

type RepTestProof struct {
	results map[string]*big.Int
}

func (rp *RepTestProof) ProofResult(name string) *big.Int {
	return rp.results[name]
}

type RepTestCommit struct {
	commits map[string]*big.Int
}

func (rc *RepTestCommit) Base(name string) *big.Int {
	return rc.commits[name]
}
func (rc *RepTestCommit) Exp(ret *big.Int, name string, exp, P *big.Int) bool {
	base := rc.Base(name)
	if base == nil {
		return false
	}
	ret.Exp(base, exp, P)
	return true
}
func (rc *RepTestCommit) Names() (ret []string) {
	for name := range rc.commits {
		ret = append(ret, name)
	}
	return
}

func TestRepresentationProofBasics(t *testing.T) {
	setupParameters(t)

	var s prooftools.QrRepresentationProofStructure
	s.Lhs = []keyproof.LhsContribution{
		{Base: "x", Power: big.NewInt(1)},
	}
	s.Rhs = []keyproof.RhsContribution{
		{Base: "S", Secret: "x", Power: 1},
	}

	var secret RepTestSecret
	secret.secrets = map[string]*big.Int{"x": big.NewInt(10)}
	secret.randomizers = map[string]*big.Int{"x": big.NewInt(15)}

	var commit RepTestCommit
	commit.commits = map[string]*big.Int{"x": new(big.Int).Exp(testPubK1.S, secret.secrets["x"], testPubK1.N)}

	var proof RepTestProof
	proof.results = map[string]*big.Int{"x": big.NewInt(25)}

	bases := keyproof.NewBaseMerge((*prooftools.PublicKeyGroup)(testPubK1), &commit)

	listSecrets := s.CommitmentsFromSecrets(testPubK1, []*big.Int{}, &bases, &secret)
	listProofs := s.CommitmentsFromProof(testPubK1, []*big.Int{}, big.NewInt(1), &bases, &proof)

	assert.Equal(t, listSecrets, listProofs, "commitment lists different")
}

func TestRepresentationProofComplex(t *testing.T) {
	setupParameters(t)

	var s prooftools.QrRepresentationProofStructure
	s.Lhs = []keyproof.LhsContribution{
		{Base: "c", Power: big.NewInt(4)},
	}
	s.Rhs = []keyproof.RhsContribution{
		{Base: "S", Secret: "x", Power: 2},
		{Base: "Z", Secret: "y", Power: 3},
	}

	var secret RepTestSecret
	secret.secrets = map[string]*big.Int{
		"x": big.NewInt(4),
		"y": big.NewInt(16),
	}
	secret.randomizers = map[string]*big.Int{
		"x": big.NewInt(12),
		"y": big.NewInt(21),
	}

	var commit RepTestCommit
	commit.commits = map[string]*big.Int{
		"c": new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Exp(testPubK1.S, big.NewInt(2), testPubK1.N),
				new(big.Int).Exp(testPubK1.Z, big.NewInt(12), testPubK1.N)),
			testPubK1.N),
	}

	var proof RepTestProof
	proof.results = map[string]*big.Int{
		"x": big.NewInt(20),
		"y": big.NewInt(53),
	}

	bases := keyproof.NewBaseMerge((*prooftools.PublicKeyGroup)(testPubK1), &commit)

	listSecrets := s.CommitmentsFromSecrets(testPubK1, []*big.Int{}, &bases, &secret)
	listProofs := s.CommitmentsFromProof(testPubK1, []*big.Int{}, big.NewInt(2), &bases, &proof)

	assert.Equal(t, listSecrets, listProofs, "Commitment lists different")
}
