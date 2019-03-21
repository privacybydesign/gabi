package safeprime

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	bitsize := 256
	x, err := Generate(bitsize, nil)

	require.NoError(t, err)
	require.NotNil(t, x)
	require.Equal(t, bitsize, x.BitLen(), "Generated number had wrong size: %d", x.BitLen())
	require.True(t, ProbablySafePrime(x, 40), "Generated number was not a safe prime")
}

func TestGenerateConcurrent(t *testing.T) {
	stop := make(chan struct{})
	stopped := false
	var count int

	// Stop after running for two seconds
	go func() {
		time.Sleep(2 * time.Second)
		close(stop)
	}()

	// Start generating safe primes
	ints, errs := GenerateConcurrent(64, stop)

	// Receive incoming safeprimes, or an error, until we stop
	for !stopped {
		select {
		case x := <-ints:
			count++
			require.True(t, ProbablySafePrime(x, 40))
		case err := <-errs:
			close(stop)
			require.NoError(t, err)
		case <-stop:
			stopped = true
		}
	}

	require.NotZero(t, count)
}
