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

	t1 := g.GetBase("g")
	t2 := g.GetBase("h")
	t3 := g.GetBase("x")

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

func (m *TestLookup) GetBase(name string) *big.Int {
	return m.getValue(name)
}
func (m *TestLookup) Exp(ret *big.Int, name string, exp, P *big.Int) bool {
	base := m.GetBase(name)
	ret.Exp(base, exp, P)
	return true
}
func (m *TestLookup) GetNames() (ret []string) {
	for name := range m.kvs {
		ret = append(ret, name)
	}
	return
}
func (m *TestLookup) GetSecret(name string) *big.Int {
	return m.getValue(name)
}
func (m *TestLookup) GetRandomizer(name string) *big.Int {
	return m.getValue(name)
}
func (m *TestLookup) GetResult(name string) *big.Int {
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
	t1 := to.GetBase("n1")
	if t1 == nil || t1.Cmp(big.NewInt(1)) != 0 {
		t.Error("Incorrect lookup of n1")
	}
	t2 := to.GetBase("n2")
	if t2 == nil || t2.Cmp(big.NewInt(3)) != 0 {
		t.Error("Incorrect lookup of n2")
	}
	t3 := to.GetBase("n3")
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

	to := NewSecretMerge(&a, &b)
	t1 := to.GetSecret("n1")
	if t1 == nil || t1.Cmp(big.NewInt(1)) != 0 {
		t.Error("Incorrect secret lookup of n1")
	}
	t2 := to.GetSecret("n2")
	if t2 == nil || t2.Cmp(big.NewInt(3)) != 0 {
		t.Error("Incorrect secret lookup of n2")
	}
	t3 := to.GetSecret("n3")
	if t3 != nil {
		t.Error("Incorrectly got result for secret lookup of n3")
	}

	t4 := to.GetRandomizer("n1")
	if t4 == nil || t4.Cmp(big.NewInt(1)) != 0 {
		t.Error("Incorrect randomizer lookup of n1")
	}
	t5 := to.GetRandomizer("n2")
	if t5 == nil || t5.Cmp(big.NewInt(3)) != 0 {
		t.Error("Incorrect randomizer lookup of n2")
	}
	t6 := to.GetRandomizer("n3")
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

	to := NewProofMerge(&a, &b)
	t1 := to.GetResult("n1")
	if t1 == nil || t1.Cmp(big.NewInt(1)) != 0 {
		t.Error("Incorrect lookup of n1")
	}
	t2 := to.GetResult("n2")
	if t2 == nil || t2.Cmp(big.NewInt(3)) != 0 {
		t.Error("Incorrect lookup of n2")
	}
	t3 := to.GetResult("n3")
	if t3 != nil {
		t.Error("Incorrectly got result for lookup of n3")
	}
}
