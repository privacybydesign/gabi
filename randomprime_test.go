package credential

import (
	"crypto/rand"
	"testing"
)

func TestRandomPrimeInRange(t *testing.T) {
	p, err := randomPrimeInRange(rand.Reader, 597, 120)
	if err != nil {
		t.Error(err)
	}
	t.Log(p)
	if !p.ProbablyPrime(22) {
		t.Error("p not prime!")
	}
}
