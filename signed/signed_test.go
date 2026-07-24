package signed

import (
	"crypto/rand"
	"encoding/asn1"
	stdbig "math/big"
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

func TestUnmarshalPemKey_Malformed(t *testing.T) {
	sk, err := GenerateKey()
	require.NoError(t, err)

	pubPem, err := MarshalPemPublicKey(&sk.PublicKey)
	require.NoError(t, err)
	privPem, err := MarshalPemPrivateKey(sk)
	require.NoError(t, err)

	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", []byte("")},
		{"not pem", []byte("not pem")},
		{"garbage", []byte("-----BEGIN BORK-----\nnope\n-----END BORK-----\n")},
	}
	for _, tc := range cases {
		t.Run("public/"+tc.name, func(t *testing.T) {
			_, err := UnmarshalPemPublicKey(tc.in)
			require.Error(t, err)
		})
		t.Run("private/"+tc.name, func(t *testing.T) {
			_, err := UnmarshalPemPrivateKey(tc.in)
			require.Error(t, err)
		})
	}

	t.Run("public-parsed-as-private", func(t *testing.T) {
		_, err := UnmarshalPemPrivateKey(pubPem)
		require.Error(t, err)
	})
	t.Run("private-parsed-as-public", func(t *testing.T) {
		_, err := UnmarshalPemPublicKey(privPem)
		require.Error(t, err)
	})
}

// Verify processes untrusted input, so every malformed signature encoding must
// be rejected with an error.
func TestVerify_MalformedSignature(t *testing.T) {
	sk, err := GenerateKey()
	require.NoError(t, err)

	valid, err := Sign(sk, []byte("hello"))
	require.NoError(t, err)

	empty, err := asn1.Marshal([]*stdbig.Int{})
	require.NoError(t, err)
	single, err := asn1.Marshal([]*stdbig.Int{stdbig.NewInt(1)})
	require.NoError(t, err)
	threeInts, err := asn1.Marshal([]*stdbig.Int{stdbig.NewInt(1), stdbig.NewInt(2), stdbig.NewInt(3)})
	require.NoError(t, err)

	cases := []struct {
		name string
		in   []byte
	}{
		{"empty bytes", []byte{}},
		{"garbage", []byte("not asn1")},
		{"empty sequence", empty},
		{"single integer", single},
		{"three integers", threeInts},
		{"trailing garbage", append(append([]byte{}, valid...), 0x00, 0x01)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				err := Verify(&sk.PublicKey, []byte("hello"), tc.in)
				require.Error(t, err)
			})
		})
	}

	// a genuine signature must still verify
	require.NoError(t, Verify(&sk.PublicKey, []byte("hello"), valid))
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
