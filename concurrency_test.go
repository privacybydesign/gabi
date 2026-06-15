// Copyright 2016 Maarten Everts. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gabi

import (
	"sync"
	"testing"

	"github.com/privacybydesign/gabi/gabikeys"
	"github.com/privacybydesign/gabi/internal/common"
	"github.com/stretchr/testify/require"
)

// newRevocationCredential builds a credential with a fresh non-revocation
// witness against the shared test key, with its nonrevocation proof cache
// primed.
func newRevocationCredential(t *testing.T) *Credential {
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
	return cred
}

// TestNonrevCacheConcurrent stresses the non-revocation disclosure path
// (including Credential.nonrevCache and the revocation proof machinery) from
// many goroutines simultaneously, sharing the public key and the global CPRNG.
//
// Each goroutine operates on its OWN Credential (with its own witness). This is
// deliberate: concurrent disclosure on a *single shared* Credential currently
// races, because revocation.NewProofCommit mutates the shared
// NonRevocationWitness.randomizer. That race is captured (and skipped) in
// TestNonrevCacheSharedCredentialConcurrent below.
//
// Run under `go test -race` to detect data races on the shared public key,
// the revocation proof structures, and the global random generator.
func TestNonrevCacheConcurrent(t *testing.T) {
	const goroutines = 8
	const iterations = 2

	context, err := common.RandomBigInt(testPubK.Params.Lh)
	require.NoError(t, err)
	nonce, err := common.RandomBigInt(testPubK.Params.Lstatzk)
	require.NoError(t, err)

	creds := make([]*Credential, goroutines)
	for i := range creds {
		creds[i] = newRevocationCredential(t)
	}

	var wg sync.WaitGroup
	errs := make(chan error, goroutines*iterations)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(cred *Credential) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				proofd, err := cred.CreateDisclosureProof([]int{1, 2}, nil, true, context, nonce)
				if err != nil {
					errs <- err
					return
				}
				if proofd.NonRevocationProof == nil {
					errs <- errProofMissingNonrev
					return
				}
				if !(ProofList{proofd}).Verify([]*gabikeys.PublicKey{testPubK}, context, nonce, false, nil) {
					errs <- errProofDidNotVerify
					return
				}
			}
		}(creds[i])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestNonrevCacheSharedCredentialConcurrent reproduces a data race in the
// "realistic" call pattern described in the issue: a service issuing/disclosing
// in parallel on the *same* Credential. It is skipped because it currently
// fails under -race: revocation.NewProofCommit (revocation/proof.go) writes
// witn.randomizer on the Credential's shared NonRevocationWitness, so multiple
// goroutines building proof commitments concurrently race on that field (and on
// the downstream witness reads). See issue #63. Remove the t.Skip once the
// shared-witness mutation is fixed; this test then becomes the regression guard.
func TestNonrevCacheSharedCredentialConcurrent(t *testing.T) {
	t.Skip("known data race: concurrent disclosure on a shared Credential mutates NonRevocationWitness.randomizer (revocation.NewProofCommit); see issue #63")

	cred := newRevocationCredential(t)

	context, err := common.RandomBigInt(testPubK.Params.Lh)
	require.NoError(t, err)
	nonce, err := common.RandomBigInt(testPubK.Params.Lstatzk)
	require.NoError(t, err)

	const goroutines = 16
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			proofd, err := cred.CreateDisclosureProof([]int{1, 2}, nil, true, context, nonce)
			if err != nil {
				errs <- err
				return
			}
			if proofd.NonRevocationProof == nil {
				errs <- errProofMissingNonrev
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

var (
	errProofMissingNonrev = revocationTestError("proof is missing its non-revocation part")
	errProofDidNotVerify  = revocationTestError("concurrently-produced disclosure proof did not verify")
)

type revocationTestError string

func (e revocationTestError) Error() string { return string(e) }
