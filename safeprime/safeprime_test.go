package safeprime

import (
	"math/big"
	"testing"
)

func TestGenerate(t *testing.T) {
	x, err := Generate(1024)

	if err != nil {
		t.Fatal(err)
	}

	t.Log(x.String())

	if !x.ProbablyPrime(100) {
		t.Fatal("Generated number was not prime")
	}

	y := new(big.Int).Sub(x, big.NewInt(1))
	y.Div(y, big.NewInt(2))
	if !y.ProbablyPrime(100) {
		t.Fatal("(prime-1)/2 was not prime")
	}
}
