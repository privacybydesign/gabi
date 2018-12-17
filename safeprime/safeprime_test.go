package safeprime

import (
	"testing"

	"github.com/privacybydesign/gabi/big"

	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	x, err := Generate(1024)

	require.NoError(t, err)
	require.NotNil(t, x)
	require.True(t, x.ProbablyPrime(100), "Generated number was not prime")

	y := new(big.Int).Sub(x, big.NewInt(1))
	y.Div(y, big.NewInt(2))

	require.True(t, y.ProbablyPrime(100), "Generated number was not a safe prime")
}
