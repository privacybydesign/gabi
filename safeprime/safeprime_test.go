package safeprime

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	bitsize := 256
	x, err := Generate(bitsize)

	require.NoError(t, err)
	require.NotNil(t, x)
	require.Equal(t, bitsize, x.BitLen(), "Generated number had wrong size: %d", x.BitLen())
	require.True(t, ProbablySafePrime(x, 40), "Generated number was not a safe prime")
}
