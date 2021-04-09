package zkproof

import (
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/assert"
)

func TestGroupWithSafePrime(t *testing.T) {
	group, ok := BuildGroup(big.NewInt(26903))
	assert.True(t, ok, "Failed to recognize safeprime")
	assert.NotNil(t, group.P, "Missing group P")
	assert.NotNil(t, group.Order, "Missing group order")
	assert.NotNil(t, group.G, "Missing group g")
	assert.NotNil(t, group.H, "Missing group h")
}

func TestNonSafePrime(t *testing.T) {
	_, ok := BuildGroup(big.NewInt(10009))
	assert.False(t, ok, "Failed to recognize non-safe prime")
}

func TestNonPrime(t *testing.T) {
	_, ok := BuildGroup(big.NewInt(20015))
	assert.False(t, ok, "Failed to recognize non-prime")
}
