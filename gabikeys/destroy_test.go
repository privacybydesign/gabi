package gabikeys

import (
	"bytes"
	mbig "math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/gabi/big"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// toyParameters returns small system parameters so that GenerateKeyPair runs
// fast enough for a unit test (real 2048-bit safe-prime generation is far too
// slow). These are for testing only and are not secure.
func toyParameters() *SystemParameters {
	base := BaseParameters{
		LePrime: 120,
		Lh:      256,
		Lm:      256,
		Ln:      256,
		Lstatzk: 80,
	}
	return &SystemParameters{
		BaseParameters:    base,
		DerivedParameters: MakeDerivedParameters(base),
	}
}

// allZero reports whether every word in the slice is zero.
func allZero(words []mbig.Word) bool {
	for _, w := range words {
		if w != 0 {
			return false
		}
	}
	return true
}

// TestPrivateKeyDestroy asserts that, after a key has been generated, Destroy
// removes and overwrites the secret prime factors P, Q, P' and Q' (and the
// derived group order), so they are not retained in memory. This is the storage
// mitigation for the timing side-channel concern in issue #8.
func TestPrivateKeyDestroy(t *testing.T) {
	privk, _, err := GenerateKeyPair(toyParameters(), 3, 0, time.Now().AddDate(1, 0, 0))
	require.NoError(t, err, "error generating key pair")

	// GenerateKeyPair also generates a revocation (ECDSA) keypair, so we can
	// verify Destroy wipes the revocation private key material too.
	require.True(t, privk.RevocationSupported(), "revocation should be supported before Destroy")
	require.NotNil(t, privk.ECDSA, "ECDSA key should be present before Destroy")

	// Sanity: freshly generated key holds all secret material and the derived
	// values are correct.
	require.NotNil(t, privk.P)
	require.NotNil(t, privk.Q)
	require.NotNil(t, privk.PPrime)
	require.NotNil(t, privk.QPrime)
	require.NotNil(t, privk.Order)
	require.NotNil(t, privk.N)
	assert.Equal(t, 0, new(big.Int).Mul(privk.P, privk.Q).Cmp(privk.N), "N should equal P*Q before Destroy")
	assert.Equal(t, 0, new(big.Int).Mul(privk.PPrime, privk.QPrime).Cmp(privk.Order), "Order should equal P'*Q' before Destroy")

	// Keep references to the underlying word backing arrays so we can verify the
	// memory itself is overwritten, not just the pointers cleared.
	pWords := privk.P.Bits()
	qWords := privk.Q.Bits()
	pPrimeWords := privk.PPrime.Bits()
	qPrimeWords := privk.QPrime.Bits()
	orderWords := privk.Order.Bits()
	require.False(t, allZero(pWords), "P should be non-zero before Destroy")

	privk.Destroy()

	// The secret fields are cleared.
	assert.Nil(t, privk.P, "P should be nil after Destroy")
	assert.Nil(t, privk.Q, "Q should be nil after Destroy")
	assert.Nil(t, privk.PPrime, "PPrime should be nil after Destroy")
	assert.Nil(t, privk.QPrime, "QPrime should be nil after Destroy")
	assert.Nil(t, privk.Order, "Order should be nil after Destroy")
	assert.Nil(t, privk.ECDSA, "ECDSA private key should be nil after Destroy")

	// The backing memory is overwritten with zeros.
	assert.True(t, allZero(pWords), "P memory should be wiped after Destroy")
	assert.True(t, allZero(qWords), "Q memory should be wiped after Destroy")
	assert.True(t, allZero(pPrimeWords), "PPrime memory should be wiped after Destroy")
	assert.True(t, allZero(qPrimeWords), "QPrime memory should be wiped after Destroy")
	assert.True(t, allZero(orderWords), "Order memory should be wiped after Destroy")

	// The revocation (ECDSA) private key is fully removed: both the parsed key
	// and the base64-encoded backing string, so it can no longer be
	// reconstructed and re-signed.
	assert.Empty(t, privk.ECDSAString, "ECDSAString should be cleared after Destroy")
	assert.False(t, privk.RevocationSupported(), "revocation should not be supported after Destroy")
	require.NoError(t, privk.parseRevocationKey(), "parseRevocationKey should not error after Destroy")
	assert.Nil(t, privk.ECDSA, "ECDSA key should not be reconstructable after Destroy")

	// The public modulus N is not secret and is retained.
	assert.NotNil(t, privk.N, "N should be retained after Destroy")
}

// TestPrivateKeyDestroyIdempotent asserts that Destroy is safe to call more than
// once and on a nil receiver.
func TestPrivateKeyDestroyIdempotent(t *testing.T) {
	privk, err := NewPrivateKey(testPrime1(), testPrime2(), "", 0, time.Now().AddDate(1, 0, 0))
	require.NoError(t, err)

	assert.NotPanics(t, func() { privk.Destroy() })
	assert.Nil(t, privk.P)
	// Second call must not panic on the already-nil fields.
	assert.NotPanics(t, func() { privk.Destroy() })

	// Nil receiver is safe.
	var nilKey *PrivateKey
	assert.NotPanics(t, func() { nilKey.Destroy() })
}

// TestPrivateKeyDestroyDoesNotWipeCallerPrimes asserts that Destroy only touches
// the key's own values. NewPrivateKey copies p and q, so a caller that keeps
// using its primes afterwards does not find them zeroed.
func TestPrivateKeyDestroyDoesNotWipeCallerPrimes(t *testing.T) {
	p, q := testPrime1(), testPrime2()
	pBefore, qBefore := p.String(), q.String()

	privk, err := NewPrivateKey(p, q, "", 0, time.Now().AddDate(1, 0, 0))
	require.NoError(t, err)

	privk.Destroy()

	assert.Equal(t, pBefore, p.String(), "Destroy should not zero the caller's p")
	assert.Equal(t, qBefore, q.String(), "Destroy should not zero the caller's q")
}

// TestPrivateKeyDestroyBlocksSerialization asserts that a destroyed key fails
// instead of serializing. encoding/xml omits nil pointer fields rather than
// erroring, so without the guard WriteTo would return a structurally valid XML
// document containing no key material and a nil error.
func TestPrivateKeyDestroyBlocksSerialization(t *testing.T) {
	privk, err := NewPrivateKey(testPrime1(), testPrime2(), "", 0, time.Now().AddDate(1, 0, 0))
	require.NoError(t, err)

	privk.Destroy()

	var buf bytes.Buffer
	n, err := privk.WriteTo(&buf)
	assert.Error(t, err, "WriteTo should error on a destroyed key")
	assert.Zero(t, n, "WriteTo should not write anything for a destroyed key")
	assert.Zero(t, buf.Len(), "WriteTo should not write anything for a destroyed key")

	assert.Error(t, privk.Print(), "Print should error on a destroyed key")
	assert.Error(t, privk.Validate(), "Validate should error on a destroyed key")
}

// TestPrivateKeyDestroyDoesNotTruncateExistingFile is the WriteToFile half of the
// above: the forceOverwrite branch truncates on open, so the check has to happen
// before the file is opened or a destroyed key would wipe a key file on disk.
func TestPrivateKeyDestroyDoesNotTruncateExistingFile(t *testing.T) {
	privk, err := NewPrivateKey(testPrime1(), testPrime2(), "", 0, time.Now().AddDate(1, 0, 0))
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "priv.xml")
	n, err := privk.WriteToFile(path, false)
	require.NoError(t, err)
	require.NotZero(t, n)
	existing, err := os.ReadFile(path)
	require.NoError(t, err)

	privk.Destroy()

	for _, forceOverwrite := range []bool{false, true} {
		n, err := privk.WriteToFile(path, forceOverwrite)
		assert.Error(t, err, "WriteToFile(forceOverwrite=%v) should error on a destroyed key", forceOverwrite)
		assert.Zero(t, n)
	}

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, existing, after, "the key file on disk should be untouched")
}

// testPrime1 and testPrime2 are the safe primes gabi's own test suite uses, so
// that these tests need no key generation.
func testPrime1() *big.Int {
	return s2big("10436034022637868273483137633548989700482895839559909621411910579140541345632481969613724849214412062500244238926015929148144084368427474551770487566048119")
}

func testPrime2() *big.Int {
	return s2big("9204968012315139729618449685392284928468933831570080795536662422367142181432679739143882888540883909887054345986640656981843559062844656131133512640733759")
}

func s2big(s string) *big.Int {
	x, _ := new(big.Int).SetString(s, 10)
	return x
}
