package common

import "testing"
import "github.com/privacybydesign/gabi/big"

func TestHashCommit(t *testing.T) {
	listA := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
	}
	hashA := HashCommit(listA, false)
	if hashA == nil {
		t.Error("Failed to generate hash for A")
		return
	}

	listB := []*big.Int{
		big.NewInt(1),
		nil,
		big.NewInt(3),
	}
	hashB := HashCommit(listB, false)
	if hashB == nil {
		t.Error("Failed to generate hash for B")
		return
	}

	listC := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
	}
	hashC := HashCommit(listC, false)
	if hashC == nil {
		t.Error("Failed to generate hash for C")
		return
	}

	if hashA.Cmp(hashB) == 0 {
		t.Error("Hashes for A and B coincide")
	}
	if hashA.Cmp(hashC) == 0 {
		t.Error("Hashes for A and C coincide")
	}
	if hashB.Cmp(hashC) == 0 {
		t.Error("Hashes for B and C coincide")
	}
}

func TestGetHashNumber(t *testing.T) {
	list := []*big.Int{
		GetHashNumber(nil, nil, 0, 10),
		GetHashNumber(big.NewInt(1), nil, 0, 10),
		GetHashNumber(big.NewInt(2), nil, 0, 10),
		GetHashNumber(big.NewInt(1), big.NewInt(2), 0, 10),
		GetHashNumber(big.NewInt(2), big.NewInt(2), 0, 10),
		GetHashNumber(big.NewInt(1), big.NewInt(3), 0, 10),
		GetHashNumber(big.NewInt(1), big.NewInt(2), 1, 10),
	}

	for i, vi := range list {
		for j, vj := range list {
			if i != j {
				if vi.Cmp(vj) == 0 {
					t.Errorf("%v and %v coincide", i, j)
				}
			}
		}
	}

	A := GetHashNumber(nil, nil, 0, 10)
	B := GetHashNumber(nil, nil, 0, 1000)
	C := GetHashNumber(nil, nil, 0, 10000)
	if A.BitLen() < 10 {
		t.Error("A too short")
	}
	if B.BitLen() < 1000 {
		t.Error("B too short")
	}
	if C.BitLen() < 10000 {
		t.Error("C too short")
	}
}
