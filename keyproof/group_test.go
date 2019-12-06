package keyproof

import (
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/assert"
)

func TestGroupWithSafePrime(t *testing.T) {
	group, ok := buildGroup(big.NewInt(26903))
	assert.True(t, ok, "Failed to recognize safeprime")
	assert.NotNil(t, group.p, "Missing group P")
	assert.NotNil(t, group.order, "Missing group order")
	assert.NotNil(t, group.g, "Missing group g")
	assert.NotNil(t, group.h, "Missing group h")
}

func TestNonSafePrime(t *testing.T) {
	_, ok := buildGroup(big.NewInt(10009))
	assert.False(t, ok, "Failed to recognize non-safe prime")
}

func TestNonPrime(t *testing.T) {
	_, ok := buildGroup(big.NewInt(20015))
	assert.False(t, ok, "Failed to recognize non-prime")
}
