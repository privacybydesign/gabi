package keyproof

import (
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroupAsLookupBase(t *testing.T) {
	const p = 26903
	g, ok := buildGroup(big.NewInt(p))
	require.True(t, ok, "Problem generating group")

	t1 := g.Base("g")
	t2 := g.Base("h")
	t3 := g.Base("x")

	assert.NotNil(t, t1, "Group base lookup g failed")
	assert.NotNil(t, t2, "Group base lookup h failed")
	assert.Nil(t, t3, "Group base lookup x incorrectly returned result")
}

type TestLookup struct {
	kvs map[string]*big.Int
}

func (m *TestLookup) getValue(name string) *big.Int {
	val, ok := m.kvs[name]
	if !ok {
		return nil
	}
	return val
}

func (m *TestLookup) Base(name string) *big.Int {
	return m.getValue(name)
}
func (m *TestLookup) Exp(ret *big.Int, name string, exp, P *big.Int) bool {
	base := m.Base(name)
	ret.Exp(base, exp, P)
	return true
}
func (m *TestLookup) Names() (ret []string) {
	for name := range m.kvs {
		ret = append(ret, name)
	}
	return
}
func (m *TestLookup) Secret(name string) *big.Int {
	return m.getValue(name)
}
func (m *TestLookup) Randomizer(name string) *big.Int {
	return m.getValue(name)
}
func (m *TestLookup) ProofResult(name string) *big.Int {
	return m.getValue(name)
}

func TestBaseMerge(t *testing.T) {
	var a, b TestLookup
	a.kvs = map[string]*big.Int{}
	b.kvs = map[string]*big.Int{}
	a.kvs["n1"] = big.NewInt(1)
	b.kvs["n1"] = big.NewInt(2)
	b.kvs["n2"] = big.NewInt(3)

	to := NewBaseMerge(&a, &b)
	t1 := to.Base("n1")
	assert.Equal(t, t1, big.NewInt(1), "Incorrect lookup of n1")
	t2 := to.Base("n2")
	assert.Equal(t, t2, big.NewInt(3), "Incorrect lookup of n2")
	t3 := to.Base("n3")
	assert.Nil(t, t3, "Incorrectly got result for lookup of n3")
}

func TestSecretMerge(t *testing.T) {
	var a, b TestLookup
	a.kvs = map[string]*big.Int{}
	b.kvs = map[string]*big.Int{}
	a.kvs["n1"] = big.NewInt(1)
	b.kvs["n1"] = big.NewInt(2)
	b.kvs["n2"] = big.NewInt(3)

	to := NewSecretMerge(&a, &b)
	t1 := to.Secret("n1")
	assert.Equal(t, t1, big.NewInt(1), "Incorrect secret lookup of n1")
	t2 := to.Secret("n2")
	assert.Equal(t, t2, big.NewInt(3), "Incorrect secret lookup of n2")
	t3 := to.Secret("n3")
	assert.Nil(t, t3, "Incorrectly got result for secret lookup of n3")

	t4 := to.Randomizer("n1")
	assert.Equal(t, t4, big.NewInt(1), "Incorrect randomizer lookup of n1")
	t5 := to.Randomizer("n2")
	assert.Equal(t, t5, big.NewInt(3), "Incorrect randomizer lookup of n2")
	t6 := to.Randomizer("n3")
	assert.Nil(t, t6, "Incorrectly got result for randomizer lookup of n3")
}

func TestProofMerge(t *testing.T) {
	var a, b TestLookup
	a.kvs = map[string]*big.Int{}
	b.kvs = map[string]*big.Int{}
	a.kvs["n1"] = big.NewInt(1)
	b.kvs["n1"] = big.NewInt(2)
	b.kvs["n2"] = big.NewInt(3)

	to := NewProofMerge(&a, &b)
	t1 := to.ProofResult("n1")
	assert.Equal(t, t1, big.NewInt(1), "Incorrect lookup of n1")
	t2 := to.ProofResult("n2")
	assert.Equal(t, t2, big.NewInt(3), "Incorrect lookup of n2")
	t3 := to.ProofResult("n3")
	assert.Nil(t, t3, "Incorrectly got result for lookup of n3")
}
