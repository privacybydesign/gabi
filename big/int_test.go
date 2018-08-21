package big

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func testBase64(t *testing.T, bigint *Int) *Int {
	bts, err := json.Marshal(bigint)
	require.NoError(t, err)
	unmarshaled := new(Int)
	err = json.Unmarshal(bts, unmarshaled)
	require.NoError(t, err)
	require.Zero(t, bigint.Cmp(unmarshaled))
	return unmarshaled
}

func TestInt(t *testing.T) {
	var i int64 = 42
	bigint := NewInt(i)
	unmarshaled := testBase64(t, bigint)
	require.Equal(t, i, unmarshaled.Int64())
}

func TestZero(t *testing.T) {
	var i int64 = 0
	bigint := NewInt(i)
	unmarshaled := testBase64(t, bigint)
	require.Equal(t, i, unmarshaled.Int64())
}

func TestBigInt(t *testing.T) {
	s := "8931748931759284679376938475395713602744853768923750102"
	bigint, ok := new(Int).SetString(s, 10)
	require.True(t, ok)
	unmarshaled := testBase64(t, bigint)
	require.Equal(t, s, unmarshaled.String())
}

func TestRandom(t *testing.T) {
	max := new(Int).Lsh(NewInt(1), 100)
	bigint, err := RandInt(rand.Reader, max)
	require.NoError(t, err)
	testBase64(t, bigint)
}

func TestNegative(t *testing.T) {
	bigint := NewInt(-42)
	_, err := json.Marshal(bigint)
	require.Error(t, err)
}
