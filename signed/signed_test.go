package signed

import (
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/privacybydesign/gabi/big"
	"github.com/stretchr/testify/require"
)

// test struct for signing, verifying and (un)marshaling
type test struct {
	X string
	Y *big.Int
	Z int
	T *test // allow recursion
}

func TestSigned(t *testing.T) {
	sk, err := GenerateKey()
	require.NoError(t, err)

	// make random bigint for test struct below
	i, err := big.RandInt(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	var (
		before = test{X: "hello", Y: i, Z: 12, T: &test{X: "world"}}
		after  test
	)

	signedmsg, err := MarshalSign(sk, before)
	require.NoError(t, err)

	require.NoError(t, UnmarshalVerify(&sk.PublicKey, signedmsg, &after))
	require.True(t, reflect.DeepEqual(before, after))
}
