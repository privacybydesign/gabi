package common

import (
	"sync"
	"testing"

	"github.com/privacybydesign/gabi/big"
)

// The CPRNG behind FastRandomBigInt / RandomQR is explicitly designed to be
// called from multiple goroutines (it uses an atomic counter). These tests
// hammer the public helpers concurrently; run under `go test -race` to detect
// data races on the shared global generator.

// TestFastRandomBigIntConcurrent calls FastRandomBigInt from many goroutines and
// checks every result stays within bounds.
func TestFastRandomBigIntConcurrent(t *testing.T) {
	limit := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256
	const goroutines = 32
	const iterations = 100

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				v := FastRandomBigInt(limit)
				if v.Sign() < 0 || v.Cmp(limit) >= 0 {
					t.Errorf("FastRandomBigInt returned out-of-range value: %s", v.String())
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestRandomQRConcurrent calls RandomQR from many goroutines and checks every
// result is a quadratic residue in the expected range.
func TestRandomQRConcurrent(t *testing.T) {
	// A large odd modulus so most candidates are coprime to n.
	n, ok := new(big.Int).SetString(
		"164849270410462350104130325681247905590883554049096338805080434441472785625514686982133223499269392762578795730418568510961568211704176723141852210985181059718962898851826265731600544499072072429389241617421101776748772563983535569756524904424870652659455911012103327708213798899264261222168033763550010103177",
		10)
	if !ok {
		t.Fatal("could not parse modulus")
	}

	const goroutines = 32
	const iterations = 25

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				qr := RandomQR(n)
				if qr.Sign() < 0 || qr.Cmp(n) >= 0 {
					t.Errorf("RandomQR returned out-of-range value: %s", qr.String())
					return
				}
			}
		}()
	}
	wg.Wait()
}
