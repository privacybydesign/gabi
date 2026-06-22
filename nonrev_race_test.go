package gabi

import (
	"sync"
	"testing"

	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/stretchr/testify/require"
)

// TestSharedCredentialConcurrentNonrevDisclosure is a regression test for the data
// race reported in privacybydesign/gabi#63: two or more goroutines calling
// CreateDisclosureProof(..., nonrev=true, ...) on the *same* Credential raced on the
// shared NonRevocationWitness because revocation.NewProofCommit mutated witn.randomizer.
//
// The 1-buffered nonrevCache hands the cached builder to at most one goroutine; the
// rest fall back to NonrevBuildProofBuilder, which builds a NonRevocationProofBuilder
// pointing at the credential's shared witness. With the bug, those concurrent builds
// raced on witn.randomizer (write) and the downstream reads. Run under `go test -race`
// to detect a regression.
func TestSharedCredentialConcurrentNonrevDisclosure(t *testing.T) {
	witness, _, _ := setupRevocation(t, testPrivK, testPubK)

	attrs := revocationAttrs(witness)
	signature, err := SignMessageBlock(testPrivK, testPubK, attrs)
	require.NoError(t, err)
	require.True(t, signature.Verify(testPubK, attrs))

	cred := &Credential{
		Signature:            signature,
		Pk:                   testPubK,
		Attributes:           attrs,
		NonRevocationWitness: witness,
	}
	require.NoError(t, cred.NonrevPrepareCache())

	context, err := common.RandomBigInt(testPubK.Params.Lh)
	require.NoError(t, err)
	nonce, err := common.RandomBigInt(testPubK.Params.Lstatzk)
	require.NoError(t, err)

	const goroutines = 16
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	proofs := make([]*ProofD, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			proofs[i], errs[i] = cred.CreateDisclosureProof([]int{1, 2}, nil, true, context, nonce)
		}(i)
	}
	wg.Wait()

	// Every concurrently produced proof must be well-formed and verify. A racing
	// randomizer would otherwise corrupt the non-revocation proof for some goroutines.
	for i := 0; i < goroutines; i++ {
		require.NoErrorf(t, errs[i], "goroutine %d failed to create proof", i)
		require.NotNilf(t, proofs[i], "goroutine %d produced nil proof", i)
		require.NotNilf(t, proofs[i].NonRevocationProof, "goroutine %d produced no nonrevocation proof", i)
		require.Truef(t,
			ProofList{proofs[i]}.Verify([]*gabikeys.PublicKey{testPubK}, context, nonce, false, nil),
			"goroutine %d produced an invalid proof", i)
	}
}
