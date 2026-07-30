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
// Each goroutine operates on its OWN Credential (with its own witness), so this
// covers the multi-credential fan-out a verifier-side service sees. The
// *single shared* Credential path — which used to race on
// NonRevocationWitness.randomizer, issue #63 — is guarded separately by
// TestSharedCredentialConcurrentNonrevDisclosure in nonrev_race_test.go.
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

var (
	errProofMissingNonrev = revocationTestError("proof is missing its non-revocation part")
	errProofDidNotVerify  = revocationTestError("concurrently-produced disclosure proof did not verify")
)

type revocationTestError string

func (e revocationTestError) Error() string { return string(e) }
