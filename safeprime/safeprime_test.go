package safeprime

import (
	"testing"

	"github.com/privacybydesign/gabi/big"

	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	bitsize := 256
	x, err := Generate(bitsize)
	require.NoError(t, err)
	require.NotNil(t, x)

	require.Equal(t, bitsize, x.BitLen(), "Generated number had wrong size: %d", x.BitLen())

	require.True(t, x.ProbablyPrime(40), "Generated number was not prime")

	y := new(big.Int).Sub(x, big.NewInt(1))
	y.Div(y, big.NewInt(2))
	require.True(t, y.ProbablyPrime(40), "Generated number was not a safe prime")
}
