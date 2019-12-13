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

	t1 := g.base("g")
	t2 := g.base("h")
	t3 := g.base("x")

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

func (m *TestLookup) base(name string) *big.Int {
	return m.getValue(name)
}
func (m *TestLookup) exp(ret *big.Int, name string, exp, P *big.Int) bool {
	base := m.base(name)
	ret.Exp(base, exp, P)
	return true
}
func (m *TestLookup) names() (ret []string) {
	for name := range m.kvs {
		ret = append(ret, name)
	}
	return
}
func (m *TestLookup) secret(name string) *big.Int {
	return m.getValue(name)
}
func (m *TestLookup) randomizer(name string) *big.Int {
	return m.getValue(name)
}
func (m *TestLookup) result(name string) *big.Int {
	return m.getValue(name)
}

func TestBaseMerge(t *testing.T) {
	var a, b TestLookup
	a.kvs = map[string]*big.Int{}
	b.kvs = map[string]*big.Int{}
	a.kvs["n1"] = big.NewInt(1)
	b.kvs["n1"] = big.NewInt(2)
	b.kvs["n2"] = big.NewInt(3)

	to := newBaseMerge(&a, &b)
	t1 := to.base("n1")
	assert.Equal(t, t1, big.NewInt(1), "Incorrect lookup of n1")
	t2 := to.base("n2")
	assert.Equal(t, t2, big.NewInt(3), "Incorrect lookup of n2")
	t3 := to.base("n3")
	assert.Nil(t, t3, "Incorrectly got result for lookup of n3")
}

func TestSecretMerge(t *testing.T) {
	var a, b TestLookup
	a.kvs = map[string]*big.Int{}
	b.kvs = map[string]*big.Int{}
	a.kvs["n1"] = big.NewInt(1)
	b.kvs["n1"] = big.NewInt(2)
	b.kvs["n2"] = big.NewInt(3)

	to := newSecretMerge(&a, &b)
	t1 := to.secret("n1")
	assert.Equal(t, t1, big.NewInt(1), "Incorrect secret lookup of n1")
	t2 := to.secret("n2")
	assert.Equal(t, t2, big.NewInt(3), "Incorrect secret lookup of n2")
	t3 := to.secret("n3")
	assert.Nil(t, t3, "Incorrectly got result for secret lookup of n3")

	t4 := to.randomizer("n1")
	assert.Equal(t, t4, big.NewInt(1), "Incorrect randomizer lookup of n1")
	t5 := to.randomizer("n2")
	assert.Equal(t, t5, big.NewInt(3), "Incorrect randomizer lookup of n2")
	t6 := to.randomizer("n3")
	assert.Nil(t, t6, "Incorrectly got result for randomizer lookup of n3")
}

func TestProofMerge(t *testing.T) {
	var a, b TestLookup
	a.kvs = map[string]*big.Int{}
	b.kvs = map[string]*big.Int{}
	a.kvs["n1"] = big.NewInt(1)
	b.kvs["n1"] = big.NewInt(2)
	b.kvs["n2"] = big.NewInt(3)

	to := newProofMerge(&a, &b)
	t1 := to.result("n1")
	assert.Equal(t, t1, big.NewInt(1), "Incorrect lookup of n1")
	t2 := to.result("n2")
	assert.Equal(t, t2, big.NewInt(3), "Incorrect lookup of n2")
	t3 := to.result("n3")
	assert.Nil(t, t3, "Incorrectly got result for lookup of n3")
}
