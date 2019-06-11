package keyproof

import "testing"
import "github.com/privacybydesign/gabi/big"

type RepTestSecret struct {
	secrets     map[string]*big.Int
	randomizers map[string]*big.Int
}

func (rs *RepTestSecret) getSecret(name string) *big.Int {
	res, ok := rs.secrets[name]
	if ok {
		return res
	}
	return nil
}

func (rs *RepTestSecret) getRandomizer(name string) *big.Int {
	res, ok := rs.randomizers[name]
	if ok {
		return res
	}
	return nil
}

type RepTestProof struct {
	results map[string]*big.Int
}

func (rp *RepTestProof) getResult(name string) *big.Int {
	res, ok := rp.results[name]
	if ok {
		return res
	}
	return nil
}

type RepTestCommit struct {
	commits map[string]*big.Int
}

func (rc *RepTestCommit) getBase(name string) *big.Int {
	res, ok := rc.commits[name]
	if ok {
		return res
	}
	return nil
}
func (rc *RepTestCommit) exp(ret *big.Int, name string, exp, P *big.Int) bool {
	base := rc.getBase(name)
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
	if !gok {
		t.Error("Failed to setup group for Representation proof testing")
		return
	}

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

	if len(listSecrets) != s.numCommitments() {
		t.Error("NumCommitments is off")
	}

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off GenerateCommitmentsFromSecrets")
	}
	Follower.(*TestFollower).count = 0

	listProofs := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(1), &bases, &proof)

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}

	if !s.isTrue(g, &bases, &secret) {
		t.Error("Incorrect rejection of truth")
	}

	if len(listSecrets) != 1 {
		t.Error("listSecrets of wrong length")
	}
	if len(listProofs) != 1 {
		t.Error("listProofs of wrong length")
	}
	if listSecrets[0].Cmp(listProofs[0]) != 0 {
		t.Error("Commitment lists different")
	}
}

func TestRepresentationProofComplex(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Representation proof testing")
		return
	}

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

	if len(listSecrets) != s.numCommitments() {
		t.Error("NumCommitments is off")
	}

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off GenerateCommitmentsFromSecrets")
	}
	Follower.(*TestFollower).count = 0

	listProofs := s.generateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(2), &bases, &proof)

	if Follower.(*TestFollower).count != s.numRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}

	if !s.isTrue(g, &bases, &secret) {
		t.Error("Incorrect rejection of truth")
	}

	if len(listSecrets) != 1 {
		t.Error("listSecrets of wrong length")
	}
	if len(listProofs) != 1 {
		t.Error("listProofs of wrong length")
	}
	if listSecrets[0].Cmp(listProofs[0]) != 0 {
		t.Error("Commitment lists different")
	}
}
