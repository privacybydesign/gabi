package keyproof

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testcases = []int{
	250,
	256,
	512,
	600,
	1000,
	1024,
	1546,
	2570,
	4618,
}

func TestFindSafePrime(t *testing.T) {
	for _, tc := range testcases {
		result := findSafePrime(tc)
		require.NotNilf(t, result, "Missing result for %d", tc)
		assert.GreaterOrEqualf(t, result.BitLen(), tc, "Generated prime too short for %d", tc)
	}
}
