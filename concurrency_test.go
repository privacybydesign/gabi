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
	for i := range goroutines {
		wg.Add(1)
		go func(cred *Credential) {
			defer wg.Done()
			for range iterations {
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

// TestNonrevCacheSharedCredentialConcurrent is the regression guard for the
// data race from issue #63: a service disclosing in parallel on the *same*
// Credential. NewProofCommit used to write witn.randomizer onto the
// Credential's shared NonRevocationWitness, so concurrent proof-commitment
// builds raced on that field (and on the downstream witness reads). The fix
// (revocation/proof.go) makes NewProofCommit work on a shallow copy of the
// witness instead of mutating the shared one; issue #63 is closed. This test
// exercises the shared-Credential path and must stay green under -race.
func TestNonrevCacheSharedCredentialConcurrent(t *testing.T) {
	cred := newRevocationCredential(t)

	context, err := common.RandomBigInt(testPubK.Params.Lh)
	require.NoError(t, err)
	nonce, err := common.RandomBigInt(testPubK.Params.Lstatzk)
	require.NoError(t, err)

	const goroutines = 16
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for range goroutines {
		wg.Go(func() {
			proofd, err := cred.CreateDisclosureProof([]int{1, 2}, nil, true, context, nonce)
			if err != nil {
				errs <- err
				return
			}
			if proofd.NonRevocationProof == nil {
				errs <- errProofMissingNonrev
			}
		})
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
