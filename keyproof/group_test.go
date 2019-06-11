package keyproof

import "testing"
import "github.com/privacybydesign/gabi/big"

func TestGroupWithSafePrime(t *testing.T) {
	group, ok := buildGroup(big.NewInt(26903))
	if !ok {
		t.Error("Failed to recognize safeprime")
		return
	}
	if group.p == nil {
		t.Error("Missing group P")
	}
	if group.order == nil {
		t.Error("Missing group order")
	}
	if group.g == nil {
		t.Error("Missing group g")
	}
	if group.h == nil {
		t.Error("Missing group h")
	}
}

func TestNonSafePrime(t *testing.T) {
	_, ok := buildGroup(big.NewInt(10009))
	if ok {
		t.Error("Failed to recognize non-safe prime")
	}
}

func TestNonPrime(t *testing.T) {
	_, ok := buildGroup(big.NewInt(20015))
	if ok {
		t.Error("Failed to recognize non-prime")
	}
}
