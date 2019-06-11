package keyproof

import "testing"
import "github.com/privacybydesign/gabi/big"

func TestGroupAsLookupBase(t *testing.T) {
	const p = 26903
	g, ok := buildGroup(big.NewInt(p))

	if !ok {
		t.Error("Problem generating group")
		return
	}

	t1 := g.getBase("g")
	t2 := g.getBase("h")
	t3 := g.getBase("x")

	if t1 == nil {
		t.Error("Group base lookup g failed")
	}
	if t2 == nil {
		t.Error("Group base lookup h failed")
	}
	if t3 != nil {
		t.Error("Group base lookup x incorrectly returned result")
	}
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

func (m *TestLookup) getBase(name string) *big.Int {
	return m.getValue(name)
}
func (m *TestLookup) exp(ret *big.Int, name string, exp, P *big.Int) bool {
	base := m.getBase(name)
	ret.Exp(base, exp, P)
	return true
}
func (m *TestLookup) names() (ret []string) {
	for name := range m.kvs {
		ret = append(ret, name)
	}
	return
}
func (m *TestLookup) getSecret(name string) *big.Int {
	return m.getValue(name)
}
func (m *TestLookup) getRandomizer(name string) *big.Int {
	return m.getValue(name)
}
func (m *TestLookup) getResult(name string) *big.Int {
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
	t1 := to.getBase("n1")
	if t1 == nil || t1.Cmp(big.NewInt(1)) != 0 {
		t.Error("Incorrect lookup of n1")
	}
	t2 := to.getBase("n2")
	if t2 == nil || t2.Cmp(big.NewInt(3)) != 0 {
		t.Error("Incorrect lookup of n2")
	}
	t3 := to.getBase("n3")
	if t3 != nil {
		t.Error("Incorrectly got result for lookup of n3")
	}
}

func TestSecretMerge(t *testing.T) {
	var a, b TestLookup
	a.kvs = map[string]*big.Int{}
	b.kvs = map[string]*big.Int{}
	a.kvs["n1"] = big.NewInt(1)
	b.kvs["n1"] = big.NewInt(2)
	b.kvs["n2"] = big.NewInt(3)

	to := newSecretMerge(&a, &b)
	t1 := to.getSecret("n1")
	if t1 == nil || t1.Cmp(big.NewInt(1)) != 0 {
		t.Error("Incorrect secret lookup of n1")
	}
	t2 := to.getSecret("n2")
	if t2 == nil || t2.Cmp(big.NewInt(3)) != 0 {
		t.Error("Incorrect secret lookup of n2")
	}
	t3 := to.getSecret("n3")
	if t3 != nil {
		t.Error("Incorrectly got result for secret lookup of n3")
	}

	t4 := to.getRandomizer("n1")
	if t4 == nil || t4.Cmp(big.NewInt(1)) != 0 {
		t.Error("Incorrect randomizer lookup of n1")
	}
	t5 := to.getRandomizer("n2")
	if t5 == nil || t5.Cmp(big.NewInt(3)) != 0 {
		t.Error("Incorrect randomizer lookup of n2")
	}
	t6 := to.getRandomizer("n3")
	if t6 != nil {
		t.Error("Incorrectly got result for randomizer lookup of n3")
	}
}

func TestProofMerge(t *testing.T) {
	var a, b TestLookup
	a.kvs = map[string]*big.Int{}
	b.kvs = map[string]*big.Int{}
	a.kvs["n1"] = big.NewInt(1)
	b.kvs["n1"] = big.NewInt(2)
	b.kvs["n2"] = big.NewInt(3)

	to := newProofMerge(&a, &b)
	t1 := to.getResult("n1")
	if t1 == nil || t1.Cmp(big.NewInt(1)) != 0 {
		t.Error("Incorrect lookup of n1")
	}
	t2 := to.getResult("n2")
	if t2 == nil || t2.Cmp(big.NewInt(3)) != 0 {
		t.Error("Incorrect lookup of n2")
	}
	t3 := to.getResult("n3")
	if t3 != nil {
		t.Error("Incorrectly got result for lookup of n3")
	}
}
